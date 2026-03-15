//! In-memory task store for A2A task lifecycle.

use super::types::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct TaskStore {
    tasks: Arc<Mutex<HashMap<String, Task>>>,
}

impl TaskStore {
    pub fn new() -> Self {
        Self {
            tasks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn insert(&self, task: Task) {
        if let Ok(mut tasks) = self.tasks.lock() {
            tasks.insert(task.id.clone(), task);
        }
    }

    pub fn get(&self, id: &str) -> Option<Task> {
        self.tasks.lock().ok()?.get(id).cloned()
    }

    pub fn update_state(&self, id: &str, new_state: TaskState) -> Option<Task> {
        let mut tasks = self.tasks.lock().ok()?;
        let task = tasks.get_mut(id)?;
        if !is_valid_transition(&task.status.state, &new_state) {
            return None;
        }
        task.status = TaskStatus {
            state: new_state,
            message: None,
            timestamp: Some(toq_core::now_utc()),
        };
        Some(task.clone())
    }

    pub fn complete_with_text(&self, id: &str, text: &str) -> Option<Task> {
        let mut tasks = self.tasks.lock().ok()?;
        let task = tasks.get_mut(id)?;
        if is_terminal(&task.status.state) {
            return None;
        }
        task.status = TaskStatus {
            state: TaskState::Completed,
            message: None,
            timestamp: Some(toq_core::now_utc()),
        };
        task.artifacts = Some(vec![Artifact {
            artifact_id: format!("{}-artifact", task.id),
            name: Some("response".into()),
            parts: vec![Part::text(text)],
        }]);
        Some(task.clone())
    }
}

/// Valid state transitions per A2A spec.
fn is_valid_transition(from: &TaskState, to: &TaskState) -> bool {
    match from {
        TaskState::Submitted => matches!(
            to,
            TaskState::Working | TaskState::Completed | TaskState::Failed | TaskState::Canceled
        ),
        TaskState::Working => matches!(
            to,
            TaskState::Completed | TaskState::Failed | TaskState::Canceled
        ),
        TaskState::Completed | TaskState::Failed | TaskState::Canceled => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_task(id: &str) -> Task {
        Task {
            id: id.into(),
            context_id: format!("ctx-{id}"),
            status: TaskStatus {
                state: TaskState::Submitted,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: None,
        }
    }

    #[test]
    fn insert_and_get() {
        let store = TaskStore::new();
        store.insert(test_task("t1"));
        let task = store.get("t1").unwrap();
        assert_eq!(task.id, "t1");
        assert_eq!(task.status.state, TaskState::Submitted);
    }

    #[test]
    fn get_missing_returns_none() {
        let store = TaskStore::new();
        assert!(store.get("nonexistent").is_none());
    }

    #[test]
    fn valid_state_transitions() {
        let store = TaskStore::new();
        store.insert(test_task("t1"));

        // Submitted -> Working
        let task = store.update_state("t1", TaskState::Working).unwrap();
        assert_eq!(task.status.state, TaskState::Working);
        assert!(task.status.timestamp.is_some());

        // Working -> Completed
        let task = store.update_state("t1", TaskState::Completed).unwrap();
        assert_eq!(task.status.state, TaskState::Completed);
    }

    #[test]
    fn invalid_state_transition_rejected() {
        let store = TaskStore::new();
        store.insert(test_task("t1"));
        store.update_state("t1", TaskState::Completed);

        // Completed -> Working is invalid
        assert!(store.update_state("t1", TaskState::Working).is_none());
    }

    #[test]
    fn terminal_states_block_transitions() {
        for terminal in [TaskState::Completed, TaskState::Failed, TaskState::Canceled] {
            let store = TaskStore::new();
            store.insert(test_task("t1"));
            store.update_state("t1", terminal);
            assert!(store.update_state("t1", TaskState::Working).is_none());
        }
    }

    #[test]
    fn complete_with_text_sets_artifact() {
        let store = TaskStore::new();
        store.insert(test_task("t1"));
        let task = store.complete_with_text("t1", "hello").unwrap();
        assert_eq!(task.status.state, TaskState::Completed);
        assert!(task.status.timestamp.is_some());
        let parts = &task.artifacts.unwrap()[0].parts;
        assert_eq!(parts[0].text.as_deref(), Some("hello"));
    }

    #[test]
    fn complete_with_text_rejects_terminal() {
        let store = TaskStore::new();
        store.insert(test_task("t1"));
        store.update_state("t1", TaskState::Failed);
        assert!(store.complete_with_text("t1", "hello").is_none());
    }

    #[test]
    fn complete_with_text_missing_task() {
        let store = TaskStore::new();
        assert!(store.complete_with_text("nonexistent", "hello").is_none());
    }
}
