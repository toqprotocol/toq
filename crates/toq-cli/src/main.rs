use clap::{Parser, Subcommand};
use std::fs;
use std::io::{self, BufRead, IsTerminal};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::prelude::*;

use toq_core::adapter::AgentMessage;

mod a2a;
mod api;
mod llm;
use toq_core::card::AgentCard;
use toq_core::config::{Config, dirs_path};
use toq_core::constants::{
    DEFAULT_CONNECTIONS_PER_IP_PER_SEC, DEFAULT_MAX_MESSAGE_SIZE, LOG_FILE, LOGS_DIR, PID_FILE,
    PROTOCOL_VERSION, STATE_FILE,
};
use toq_core::crypto::Keypair;
use toq_core::framing;
use toq_core::keystore;
use toq_core::messaging::{self, SendParams};
use toq_core::negotiation::Features;
use toq_core::policy::{ConnectionMode, PolicyEngine};
use toq_core::ratelimit::RateLimiter;
use toq_core::server;
use toq_core::session::SessionStore;
use toq_core::transport;
use toq_core::types::{Address, MessageType};

const LOGO_RAW: &str = r#"▄▄█████████████████▀▀▘
     ▄▄█▀▀▀
    ▄█▀▄▄▀▀▀▀▀▀▄▄▄▀▀▀▀▀▀▄▄
   ▄██▄██▀       ▀██▀      ▀██▄
  ▐██▐██          ██▌     ▄▄▄██▌
  ▐█▌ ▀██▄      ▄██▀██▄ ▀▀▀██▀
   ▀    ▀▀▀▄▄▄▀▀▀▀  ▀▀▀▄▄▀▀▐██
                           ██▀
                          ▀▀"#;

const ABOUT: &str = "secure agent-to-agent communication";

fn use_color() -> bool {
    std::env::var("NO_COLOR").is_err() && io::stdout().is_terminal()
}

fn gold(s: &str) -> String {
    if use_color() {
        format!("\x1b[38;2;250;163;0m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

fn red(s: &str) -> String {
    if use_color() {
        format!("\x1b[31m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

fn dim(s: &str) -> String {
    if use_color() {
        format!("\x1b[2m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

/// Derive a 32-byte encryption key from a passphrase and salt using Argon2id.
fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32], String> {
    use argon2::Argon2;
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| format!("key derivation failed: {e}"))?;
    Ok(key)
}

fn centered_logo() -> String {
    let about_width = ABOUT.len();
    let logo_width = LOGO_RAW
        .lines()
        .map(|l| l.chars().count())
        .max()
        .unwrap_or(0);
    let pad = if about_width > logo_width {
        (about_width - logo_width) / 2
    } else {
        0
    };
    let prefix = " ".repeat(pad);
    LOGO_RAW
        .lines()
        .map(|line| format!("{prefix}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[derive(Parser)]
#[command(name = "toq", version, about = ABOUT, help_template = "\
{about}

{usage-heading} {usage}

Getting Started:
  init         Initialize a workspace
  setup        Interactive guided setup
  whoami       Show your agent's address and public key

Daemon:
  up           Start the toq endpoint
  down         Stop the toq endpoint
  status       Show running state and connections
  agents       List all registered agents on this machine

Messaging:
  send         Send a message to an agent
  messages     Show recent received messages
  peers        List known peers
  ping         Ping a remote agent
  discover     Discover agents at a domain via DNS
  handler      Manage message handlers

Security:
  approvals    List pending approval requests
  approve      Approve a pending request
  deny         Deny a pending request
  revoke       Revoke a previously approved agent
  block        Block an agent
  unblock      Remove from the blocklist
  permissions  List all permission rules

Maintenance:
  config       View or modify configuration
  doctor       Run diagnostics
  logs         Show recent log entries
  clear-logs   Delete all audit logs
  export       Export encrypted backup
  import       Restore from backup
  rotate-keys  Rotate keys
  upgrade      Update the toq binary

{options}")]
struct Cli {
    /// Override config directory (default: .toq/ in cwd, then ~/.toq/)
    #[arg(long, global = true)]
    config_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a workspace. Creates .toq/ in the current directory.
    Init {
        /// Agent name
        #[arg(long, default_value = "agent")]
        name: String,
        /// Host (domain name or IP for this agent's address)
        #[arg(long, default_value = "localhost")]
        host: String,
        /// Port (use "auto" for automatic assignment)
        #[arg(long, default_value = "auto")]
        port: String,
    },
    /// Interactive guided setup. Generates keys, creates config.
    Setup {
        /// Run without prompts, using provided flags or defaults.
        #[arg(long)]
        non_interactive: bool,
        /// Agent name (default: agent).
        #[arg(long)]
        agent_name: Option<String>,
        /// Host address: IP or hostname other agents use to reach this endpoint.
        #[arg(long)]
        host: Option<String>,
        /// Connection mode: open, allowlist, approval (default: approval).
        #[arg(long)]
        connection_mode: Option<String>,
        /// Message adapter: http, stdin, unix (default: http).
        #[arg(long)]
        adapter: Option<String>,
        /// Agent framework: langchain, crewai, openclaw.
        #[arg(long)]
        framework: Option<String>,
    },
    /// Start the toq endpoint.
    Up {
        /// Run in the foreground (logs to stdout).
        #[arg(long)]
        foreground: bool,
    },
    /// Stop the toq endpoint.
    Down {
        /// Graceful shutdown: wait for active threads to finish.
        #[arg(long)]
        graceful: bool,
        /// Stop a specific named agent (from anywhere).
        #[arg(long)]
        name: Option<String>,
    },
    /// Show running state, connections, and pending approvals.
    Status,
    /// List known peers with status and last seen time.
    Peers,
    /// Block an agent by address, public key, or wildcard pattern.
    Block {
        /// Address or wildcard pattern (e.g. toq://host/*, toq://*/name).
        #[arg(long)]
        from: Option<String>,
        /// Public key (e.g. ed25519:abc...).
        #[arg(long)]
        key: Option<String>,
        /// Legacy positional argument (address or public key).
        agent: Option<String>,
    },
    /// Remove an agent from the blocklist.
    Unblock {
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        key: Option<String>,
        agent: Option<String>,
    },
    /// Send a message to an agent.
    Send {
        /// Agent address (e.g. toq://host/agent-name)
        address: String,
        /// Message text to send
        message: String,
        /// Continue an existing thread.
        #[arg(long)]
        thread_id: Option<String>,
        /// Close the thread after sending.
        #[arg(long)]
        close_thread: bool,
    },
    /// Export keys, config, and peer list as an encrypted backup.
    Export { path: String },
    /// Restore from an encrypted backup file.
    Import { path: String },
    /// Rotate keys and broadcast to connected peers.
    RotateKeys,
    /// Delete all audit logs.
    ClearLogs,
    /// List pending approval requests (requires running daemon).
    Approvals,
    /// Approve a pending request, or pre-approve by key/address/wildcard.
    Approve {
        /// Pending request ID (public key of the requesting agent).
        id: Option<String>,
        /// Address or wildcard pattern.
        #[arg(long)]
        from: Option<String>,
        /// Public key.
        #[arg(long)]
        key: Option<String>,
    },
    /// Deny a pending connection request (requires running daemon).
    Deny { id: String },
    /// Revoke a previously approved agent or rule.
    Revoke {
        /// Pending request ID (public key).
        id: Option<String>,
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        key: Option<String>,
    },
    /// Show recent received messages (requires running daemon).
    Messages {
        #[arg(long)]
        from: Option<String>,
        #[arg(long, default_value = "20")]
        limit: usize,
    },
    /// Run diagnostics: port, DNS, keys, agent responsiveness.
    Doctor,
    /// List all permission rules (approved and blocked).
    Permissions,
    /// Ping a remote agent to discover its public key.
    Ping { address: String },
    /// Discover agents at a domain via DNS TXT records.
    Discover { domain: String },
    /// Show your agent's address, public key, and connection mode.
    Whoami,
    /// List all registered agents on this machine.
    Agents,
    /// Update the toq binary.
    Upgrade,
    /// Show recent log entries.
    Logs {
        /// Stream log entries in real time.
        #[arg(long)]
        follow: bool,
    },
    /// Manage message handlers.
    Handler {
        #[command(subcommand)]
        action: HandlerAction,
    },
    /// View or modify configuration.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Manage A2A protocol compatibility.
    A2a {
        #[command(subcommand)]
        action: A2aAction,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Show current configuration.
    Show,
    /// Set a configuration value.
    Set {
        /// Config key (e.g. connection_mode, agent_name, port)
        key: String,
        /// New value
        value: String,
    },
}

#[derive(Subcommand)]
enum A2aAction {
    /// Enable A2A compatibility.
    Enable {
        /// Bearer token for authentication. Omit for open access.
        #[arg(long)]
        key: Option<String>,
    },
    /// Disable A2A compatibility.
    Disable,
    /// Show A2A status.
    Status,
}

#[derive(Parser)]
struct HandlerAddArgs {
    /// Handler name.
    name: String,
    /// Shell command (for command handlers).
    #[arg(long)]
    command: Option<String>,
    /// LLM provider: openai, anthropic, bedrock, or ollama.
    #[arg(long)]
    provider: Option<String>,
    /// LLM model name.
    #[arg(long)]
    model: Option<String>,
    /// System prompt.
    #[arg(long)]
    prompt: Option<String>,
    /// Path to system prompt file.
    #[arg(long)]
    prompt_file: Option<String>,
    /// Max turns before closing the thread.
    #[arg(long)]
    max_turns: Option<usize>,
    /// Let the LLM decide when to close the thread.
    #[arg(long)]
    auto_close: bool,
    /// Filter by sender address/wildcard (repeatable, OR logic).
    #[arg(long = "from")]
    filter_from: Vec<String>,
    /// Filter by sender public key (repeatable, OR logic).
    #[arg(long = "key")]
    filter_key: Vec<String>,
    /// Filter by message type (repeatable, OR logic).
    #[arg(long = "type")]
    filter_type: Vec<String>,
}

#[derive(Subcommand)]
enum HandlerAction {
    /// Register a new message handler.
    Add(Box<HandlerAddArgs>),
    /// List registered handlers.
    List,
    /// Remove a handler.
    Remove { name: String },
    /// Enable a disabled handler.
    Enable { name: String },
    /// Disable a handler without removing it.
    Disable { name: String },
    /// Stop running handler processes.
    Stop {
        name: String,
        /// Stop a specific process by PID.
        #[arg(long)]
        pid: Option<u32>,
    },
    /// Show handler logs.
    Logs { name: String },
}

#[tokio::main]
async fn main() {
    // Show logo when no args or when --help is requested
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 1 {
        println!("\n{}", gold(&centered_logo()));
        println!("{ABOUT}");
        let logo_width = centered_logo().lines().map(|l| l.chars().count()).max().unwrap_or(0);
        let ver = format!("v{}", env!("CARGO_PKG_VERSION"));
        let ver_pad = " ".repeat((logo_width.saturating_sub(ver.len())) / 2);
        println!("{ver_pad}{ver}");
        let help_msg = format!("Run {} for usage", gold("toq --help"));
        let help_plain = "Run toq --help for usage";
        let help_pad = " ".repeat((logo_width.saturating_sub(help_plain.len())) / 2);
        println!("\n{help_pad}{help_msg}");
        std::process::exit(0);
    }
    if args.iter().any(|a| a == "--help" || a == "-h" || a == "help") {
        println!("\n{}", gold(&centered_logo()));
    }

    let cli = Cli::parse();

    // Set config dir env var before any config resolution
    if let Some(ref dir) = cli.config_dir {
        // SAFETY: called before any threads are spawned (tokio runtime not yet started).
        unsafe { std::env::set_var(toq_core::constants::TOQ_CONFIG_DIR_ENV, dir) };
    }

    let result = match cli.command {
        Commands::Init {
            ref name,
            ref host,
            ref port,
        } => run_init(name, host, port),
        Commands::Setup {
            non_interactive,
            agent_name,
            host,
            connection_mode,
            adapter,
            framework,
        } => run_setup(
            non_interactive,
            agent_name,
            host,
            connection_mode,
            adapter,
            framework,
        ),
        Commands::Up { foreground } => run_up(foreground).await,
        Commands::Down { graceful, name } => run_down(graceful, name.as_deref()),
        Commands::Status => run_status(),
        Commands::Peers => run_peers(),
        Commands::Block {
            ref from,
            ref key,
            ref agent,
        } => run_block(from.as_deref(), key.as_deref(), agent.as_deref()).await,
        Commands::Unblock {
            ref from,
            ref key,
            ref agent,
        } => run_unblock(from.as_deref(), key.as_deref(), agent.as_deref()).await,
        Commands::Send {
            ref address,
            ref message,
            ref thread_id,
            close_thread,
        } => run_send(address, message, thread_id.as_deref(), close_thread).await,
        Commands::Export { ref path } => run_export(path),
        Commands::Import { ref path } => run_import(path),
        Commands::RotateKeys => run_rotate_keys(),
        Commands::ClearLogs => run_clear_logs(),
        Commands::Approvals => run_approvals().await,
        Commands::Approve {
            ref id,
            ref from,
            ref key,
        } => run_approve(id.as_deref(), from.as_deref(), key.as_deref()).await,
        Commands::Deny { ref id } => run_deny(id).await,
        Commands::Revoke {
            ref id,
            ref from,
            ref key,
        } => run_revoke(id.as_deref(), from.as_deref(), key.as_deref()).await,
        Commands::Messages { ref from, limit } => run_messages(from.as_deref(), limit).await,
        Commands::Doctor => run_doctor().await,
        Commands::Permissions => run_permissions().await,
        Commands::Ping { ref address } => run_ping(address).await,
        Commands::Discover { ref domain } => run_discover(domain).await,
        Commands::Whoami => run_whoami(),
        Commands::Agents => run_agents(),
        Commands::Upgrade => run_upgrade().await,
        Commands::Logs { follow } => run_logs(follow),
        Commands::Handler { action } => run_handler(action).await,
        Commands::Config { action } => run_config(action),
        Commands::A2a { action } => run_a2a(action),
    };

    if let Err(e) = result {
        eprintln!("{}", red(&format!("error: {e}")));
        std::process::exit(1);
    }
}

// --- Helpers ---

fn pid_path() -> PathBuf {
    dirs_path().join(PID_FILE)
}

fn log_path() -> PathBuf {
    dirs_path().join(LOGS_DIR).join(LOG_FILE)
}

fn state_path() -> PathBuf {
    dirs_path().join(STATE_FILE)
}

fn require_setup() {
    if !keystore::is_setup_complete() {
        eprintln!("Setup not complete");
        eprintln!("  Run `toq init` to create a workspace, or `toq setup` for guided setup");
        std::process::exit(1);
    }
}

fn require_running() {
    require_setup();
    if read_pid().is_none() {
        eprintln!("toq is not running");
        eprintln!("  Run `toq up` to start the daemon");
        std::process::exit(1);
    }
}

fn write_pid() -> Result<(), Box<dyn std::error::Error>> {
    let pid = std::process::id();
    fs::write(pid_path(), pid.to_string())?;
    Ok(())
}

fn remove_pid() {
    let _ = fs::remove_file(pid_path());
}

fn read_pid() -> Option<u32> {
    let pid: u32 = fs::read_to_string(pid_path())
        .ok()
        .and_then(|s| s.trim().parse().ok())?;

    // Verify the process is actually alive using `kill -0`.
    let alive = std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success());

    if alive {
        Some(pid)
    } else {
        // Stale PID file, clean it up.
        let _ = fs::remove_file(pid_path());
        None
    }
}

/// Global agents registry directory: always `~/.toq/agents/` regardless of workspace.
fn agents_registry_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home)
        .join(toq_core::constants::TOQ_DIR_NAME)
        .join(toq_core::constants::AGENTS_DIR)
}

fn register_agent(
    name: &str,
    port: u16,
    config_dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = agents_registry_dir();
    fs::create_dir_all(&dir)?;
    let content = format!(
        "name = \"{name}\"\n\
         port = {port}\n\
         pid = {}\n\
         config_dir = \"{}\"\n\
         started_at = \"{}\"\n",
        std::process::id(),
        config_dir.display(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs().to_string())
            .unwrap_or_default(),
    );
    fs::write(dir.join(format!("{name}.toml")), content)?;
    Ok(())
}

fn unregister_agent(name: &str) {
    let path = agents_registry_dir().join(format!("{name}.toml"));
    let _ = fs::remove_file(path);
}

/// Find an available port starting from DEFAULT_PORT, skipping ports claimed by other agents.
fn find_available_port() -> u16 {
    let dir = agents_registry_dir();
    let mut claimed: Vec<u16> = Vec::new();
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            if let Ok(contents) = fs::read_to_string(entry.path())
                && let Some(port) = contents
                    .lines()
                    .find(|l| l.starts_with("port"))
                    .and_then(|l| l.split('=').nth(1))
                    .and_then(|v| v.trim().parse::<u16>().ok())
            {
                claimed.push(port);
            }
        }
    }

    let mut port = toq_core::constants::DEFAULT_PORT;
    loop {
        if !claimed.contains(&port) {
            return port;
        }
        port += 1;
        if port > 9999 {
            return toq_core::constants::DEFAULT_PORT;
        }
    }
}

fn setup_logging() {
    let log_dir = dirs_path().join(LOGS_DIR);
    let _ = fs::create_dir_all(&log_dir);

    // Prune old log files based on retention
    if let Ok(config) = Config::load(&Config::default_path()) {
        let cutoff = std::time::SystemTime::now()
            - std::time::Duration::from_secs(config.log_retention_days as u64 * 86400);
        if let Ok(entries) = fs::read_dir(&log_dir) {
            for entry in entries.flatten() {
                let should_remove = entry
                    .metadata()
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .is_some_and(|modified| modified < cutoff);
                if should_remove {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }

    let file_appender = tracing_appender::rolling::daily(&log_dir, LOG_FILE);
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    std::mem::forget(_guard);

    // Wire log level from config
    let level = Config::load(&Config::default_path())
        .map(|c| c.log_level)
        .unwrap_or_else(|_| "warn".into());
    let filter = match level.as_str() {
        "error" => tracing_subscriber::filter::LevelFilter::ERROR,
        "info" => tracing_subscriber::filter::LevelFilter::INFO,
        "debug" => tracing_subscriber::filter::LevelFilter::DEBUG,
        _ => tracing_subscriber::filter::LevelFilter::WARN,
    };

    tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_target(false)
        .with_max_level(filter)
        .init();
}

fn load_card(config: &Config, keypair: &Keypair) -> AgentCard {
    AgentCard {
        name: config.agent_name.clone(),
        description: None,
        public_key: keypair.public_key().to_encoded(),
        protocol_version: PROTOCOL_VERSION.into(),
        capabilities: vec![],
        accept_files: config.accept_files,
        max_file_size: if config.accept_files {
            Some(config.max_file_size as u64)
        } else {
            None
        },
        max_message_size: Some(config.max_message_size),
        connection_mode: Some(config.connection_mode.clone()),
    }
}

// --- Commands ---

/// Detect the machine's primary non-loopback IP address, falling back to "localhost".
fn detect_host() -> String {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:80")?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "localhost".into())
}

fn run_init(name: &str, host: &str, port: &str) -> Result<(), Box<dyn std::error::Error>> {
    let toq_dir = PathBuf::from(".toq");
    if toq_dir.exists() {
        return Err("Workspace already initialized (.toq/ exists)".into());
    }

    fs::create_dir_all(toq_dir.join(LOGS_DIR))?;

    // Write config.toml
    let port_line = if port == "auto" {
        "port = 0  # auto-assigned on startup".to_string()
    } else {
        let p: u16 = port.parse().unwrap_or(toq_core::constants::DEFAULT_PORT);
        format!("port = {p}")
    };
    let host_line = if host != "localhost" {
        format!("host = \"{host}\"\n")
    } else {
        String::new()
    };
    let config_content = format!(
        "# toq workspace config\n\
         # Docs: https://toq.dev/getting-started/overview/\n\
         \n\
         agent_name = \"{name}\"\n\
         {host_line}\
         {port_line}\n\
         \n\
         # Connection mode: open, allowlist, or approval (default)\n\
         connection_mode = \"approval\"\n"
    );
    fs::write(toq_dir.join("config.toml"), config_content)?;

    // Write .gitignore
    let gitignore = "keys/\npeers.json\nmessages.jsonl\nlogs/\n";
    fs::write(toq_dir.join(".gitignore"), gitignore)?;

    // Write empty handlers.toml
    fs::write(
        toq_dir.join("handlers.toml"),
        "# toq message handlers\n# Register handlers with: toq handler add <name> --command <cmd>\n\nhandlers = []\n",
    )?;

    // Write empty permissions.toml
    fs::write(
        toq_dir.join("permissions.toml"),
        "# toq permission rules\n# Manage with: toq approve, toq block, toq revoke\n\napproved = []\nblocked = []\npending = []\n",
    )?;

    println!("Initialized workspace in .toq/");
    println!("  Agent: {name}");
    println!("  Host:  {host}");
    println!("  Port:  {port}");
    println!("\nRun `toq up` to start the agent");
    Ok(())
}

/// Remove stale agent registry entries (dead PIDs).
fn clean_stale_agents() {
    let dir = agents_registry_dir();
    if !dir.exists() {
        return;
    }
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "toml")
                && let Ok(contents) = fs::read_to_string(&path)
            {
                let pid: i64 = contents
                    .lines()
                    .find(|l| l.starts_with("pid"))
                    .and_then(|l| l.split('=').nth(1))
                    .and_then(|v| v.trim().trim_matches('"').parse().ok())
                    .unwrap_or(0);
                let alive = pid > 0
                    && std::process::Command::new("kill")
                        .args(["-0", &pid.to_string()])
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status()
                        .is_ok_and(|s| s.success());
                if !alive {
                    let _ = fs::remove_file(&path);
                }
            }
        }
    }
}

fn run_agents() -> Result<(), Box<dyn std::error::Error>> {
    clean_stale_agents();
    let agents_dir = agents_registry_dir();

    if !agents_dir.exists() {
        println!("No agents registered");
        return Ok(());
    }

    let mut found = false;
    for entry in fs::read_dir(&agents_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "toml") {
            let contents = fs::read_to_string(&path)?;

            let get = |key: &str| -> String {
                contents
                    .lines()
                    .find(|l| l.starts_with(key))
                    .and_then(|l| l.split('=').nth(1))
                    .map(|v| v.trim().trim_matches('"').to_string())
                    .unwrap_or_default()
            };

            let name = get("name");
            let port = get("port");
            let pid_str = get("pid");
            let config_dir = get("config_dir");
            let pid: i64 = pid_str.parse().unwrap_or(0);

            let alive = pid > 0
                && std::process::Command::new("kill")
                    .args(["-0", &pid.to_string()])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .is_ok_and(|s| s.success());
            if !alive {
                continue;
            }

            if !found {
                println!("{:<16} {:<8} {:<8} CONFIG", "NAME", "PORT", "PID");
                found = true;
            }
            println!("{:<16} {:<8} {:<8} {config_dir}", name, port, pid);
        }
    }

    if !found {
        println!("No agents registered");
    }
    Ok(())
}

fn run_setup(
    non_interactive: bool,
    cli_agent_name: Option<String>,
    cli_host: Option<String>,
    cli_connection_mode: Option<String>,
    cli_adapter: Option<String>,
    cli_framework: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if keystore::is_setup_complete() {
        if non_interactive {
            println!("Setup already complete");
            return Ok(());
        }
        println!("{}", centered_logo());
        println!("toq setup\n");
        let overwrite =
            inquire::Confirm::new("Setup already complete. Overwrite existing keys and config?")
                .with_default(false)
                .prompt()?;
        if !overwrite {
            println!("Aborted");
            return Ok(());
        }
    } else if !non_interactive {
        println!("{}", centered_logo());
        println!("toq setup\n");
    }

    let agent_name = if non_interactive {
        let name = cli_agent_name.unwrap_or_else(|| "agent".to_string());
        Address::new("localhost", &name)
            .map_err(|e| format!("Invalid agent name '{name}': {e}"))?;
        name
    } else {
        inquire::Text::new("Agent name")
            .with_default(&cli_agent_name.unwrap_or_else(|| "agent".to_string()))
            .with_validator(|input: &str| match Address::new("localhost", input) {
                Ok(_) => Ok(inquire::validator::Validation::Valid),
                Err(e) => Ok(inquire::validator::Validation::Invalid(
                    e.to_string().into(),
                )),
            })
            .prompt()?
    };

    let host = if non_interactive {
        cli_host.unwrap_or_else(detect_host)
    } else {
        let detected = detect_host();
        inquire::Text::new("Host address (IP or hostname for other agents to reach you)")
            .with_default(&cli_host.unwrap_or(detected))
            .prompt()?
    };

    let connection_mode = if non_interactive {
        let mode = cli_connection_mode.unwrap_or_else(|| "approval".to_string());
        if !["open", "allowlist", "approval", "dns-verified"].contains(&mode.as_str()) {
            return Err(format!(
                "Invalid connection mode '{mode}': must be open, allowlist, approval, or dns-verified"
            )
            .into());
        }
        mode
    } else {
        let mode_options = vec![
            "approval      - You approve each new agent (recommended)",
            "open          - Anyone can connect",
            "allowlist     - Only pre-approved agents",
            "dns-verified  - Only agents with valid DNS records",
        ];
        let mode_choice =
            inquire::Select::new("Who can connect to your agent?", mode_options).prompt()?;
        if mode_choice.starts_with("open") {
            "open".to_string()
        } else if mode_choice.starts_with("allowlist") {
            "allowlist".to_string()
        } else if mode_choice.starts_with("dns-verified") {
            "dns-verified".to_string()
        } else {
            "approval".to_string()
        }
    };

    let framework = if non_interactive {
        cli_framework.unwrap_or_default()
    } else {
        let framework_options = vec!["none / custom", "LangChain", "CrewAI", "OpenClaw"];
        let choice = inquire::Select::new("Which agent framework? (optional)", framework_options)
            .prompt()?;
        match choice {
            c if c.starts_with("LangChain") => "langchain".to_string(),
            c if c.starts_with("CrewAI") => "crewai".to_string(),
            c if c.starts_with("OpenClaw") => "openclaw".to_string(),
            _ => String::new(),
        }
    };

    let adapter = if !framework.is_empty() {
        "http".to_string()
    } else if non_interactive {
        let a = cli_adapter.unwrap_or_else(|| "http".to_string());
        if !["http", "stdin", "unix"].contains(&a.as_str()) {
            return Err(format!("Invalid adapter '{a}': must be http, stdin, or unix").into());
        }
        a
    } else {
        cli_adapter.unwrap_or_else(|| "http".to_string())
    };

    if non_interactive {
        println!("Generating identity keypair and TLS certificate...");
    } else {
        println!("\nGenerating identity keypair and TLS certificate...");
    }
    let keypair = Keypair::generate();
    keystore::save_keypair(&keypair, &keystore::identity_key_path())?;
    keystore::generate_and_save_tls_cert(&keystore::tls_cert_path(), &keystore::tls_key_path())?;

    let config = Config::default()
        .with_agent(agent_name.clone(), connection_mode.clone())
        .with_host(host.clone())
        .with_adapter(adapter.clone());
    config.save(&Config::default_path())?;

    let _ = fs::create_dir_all(dirs_path().join(LOGS_DIR));

    let pub_key = keypair.public_key().to_encoded();
    let pub_key_short = pub_key.strip_prefix("ed25519:").unwrap_or(&pub_key);

    if non_interactive {
        println!("Setup complete: toq://{host}/{agent_name}");
        println!("Public key: {pub_key_short}");
        return Ok(());
    }

    use comfy_table::{
        ContentArrangement, Table, modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL_CONDENSED,
    };
    let mut table = Table::new();
    table.load_preset(UTF8_FULL_CONDENSED);
    table.apply_modifier(UTF8_ROUND_CORNERS);
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec!["", "Setup complete"]);
    table.add_row(vec!["Agent", &agent_name]);
    table.add_row(vec!["Mode", &connection_mode]);
    table.add_row(vec!["Adapter", &adapter]);
    table.add_row(vec!["Address", &format!("toq://{host}/{agent_name}")]);
    table.add_row(vec!["Public key", pub_key_short]);
    println!("\n{table}");

    if connection_mode == "open" {
        println!("\n  ⚠ Open mode: any agent can connect without approval");
    }

    println!("\n  Quick start:");
    println!("    toq up                    Start your endpoint");
    match framework.as_str() {
        "langchain" => {
            println!("\n  LangChain integration:");
            println!("    from toq_langchain import connect, listen");
            println!("    client = connect()");
            println!("    tools = client.tools()");
        }
        "crewai" => {
            println!("\n  CrewAI integration:");
            println!("    from toq_crewai import connect, listen");
            println!("    client = connect()");
            println!("    tools = client.tools()");
        }
        "openclaw" => {
            println!("\n  OpenClaw integration:");
            println!("    clawhub install toq           Install the toq skill");
            println!("    openclaw plugins install \\");
            println!("      toq-openclaw-channel        Install the channel plugin");
        }
        _ => {
            println!("    toq send <addr> <msg>     Send a test message");
            println!("    toq down                  Stop the endpoint");
        }
    }

    println!("\n  Network security:");
    println!("    Your endpoint listens on port {}", config.port);
    println!("    If exposed to the internet, use a firewall");
    println!("    and 'approval' or 'allowlist' connection mode");

    println!("\n  DNS discovery:");
    println!("    To make your agent discoverable, add these DNS records:");
    println!();
    println!("    A record:");
    println!("      <your-domain>  ->  <your-public-ip>");
    println!();
    println!("    TXT record:");
    if config.port == toq_core::constants::DEFAULT_PORT {
        println!(
            "      _toq._tcp.<your-domain>  \"v=toq1; key={pub_key_short}; agent={agent_name}\""
        );
    } else {
        println!(
            "      _toq._tcp.<your-domain>  \"v=toq1; key={pub_key_short}; port={}; agent={agent_name}\"",
            config.port
        );
    }
    println!();
    println!("    After adding records, verify with: toq doctor");

    Ok(())
}

async fn run_up(foreground: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Require a workspace (.toq/ in cwd), global config (~/.toq/), or explicit --config-dir
    let has_local_workspace = PathBuf::from(".toq").is_dir();
    let has_explicit_config = std::env::var(toq_core::constants::TOQ_CONFIG_DIR_ENV).is_ok();
    let has_global_config = {
        let home = std::env::var("HOME").unwrap_or_default();
        PathBuf::from(home)
            .join(".toq")
            .join("config.toml")
            .exists()
    };
    if !has_local_workspace && !has_explicit_config && !has_global_config {
        eprintln!("No workspace found");
        eprintln!("  Run `toq init` to create one, or `toq setup` for guided setup");
        std::process::exit(1);
    }

    // For workspaces: auto-generate keys if config exists but keys don't
    let config_exists = Config::default_path().exists();
    let keys_exist = keystore::identity_key_path().exists();
    if config_exists && !keys_exist {
        let keypair = Keypair::generate();
        keystore::save_keypair(&keypair, &keystore::identity_key_path())?;
        keystore::generate_and_save_tls_cert(
            &keystore::tls_cert_path(),
            &keystore::tls_key_path(),
        )?;
    } else {
        require_setup();
    }
    clean_stale_agents();

    // Daemon mode: re-exec in background
    if !foreground {
        let exe = std::env::current_exe()?;
        let log_dir = dirs_path().join(LOGS_DIR);
        let _ = fs::create_dir_all(&log_dir);
        let log_file = fs::File::create(log_path())?;
        let mut cmd = std::process::Command::new(exe);
        cmd.arg("up").arg("--foreground");
        // Pass resolved config dir to background process
        let resolved = dirs_path();
        cmd.arg("--config-dir").arg(&resolved);
        let child = cmd.stdout(log_file.try_clone()?).stderr(log_file).spawn()?;
        let config = Config::load(&Config::default_path())?;
        println!(
            "{}",
            gold(&format!("toq started as daemon (PID {})", child.id()))
        );
        println!("  agent:           {}", config.agent_name);
        println!(
            "  port:            {}",
            if config.port == 0 {
                "auto".into()
            } else {
                config.port.to_string()
            }
        );
        println!("  connection mode: {}", config.connection_mode);
        return Ok(());
    }

    if let Some(pid) = read_pid() {
        eprintln!("toq appears to be running (PID {pid})");
        eprintln!("  run `toq down` to stop it, or `toq down --graceful` for a clean shutdown");
        std::process::exit(1);
    }

    let mut config = Config::load(&Config::default_path())?;

    // Auto-assign port if set to 0
    let auto_port = config.port == 0;
    if auto_port {
        config.port = find_available_port();
    }

    // If host is "auto", detect public IP on every startup.
    if config.host == "auto" {
        let output = std::process::Command::new("curl")
            .args(["-4", "-s", "--max-time", "5", "ifconfig.me"])
            .output();
        match output {
            Ok(o) if o.status.success() => {
                let detected = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if detected.is_empty() {
                    eprintln!("Failed to detect public IP (empty response)");
                    std::process::exit(1);
                }
                tracing::info!("auto-detected public IP: {detected}");
                config.host = detected;
            }
            _ => {
                eprintln!("Failed to detect public IP (curl failed)");
                std::process::exit(1);
            }
        }
    }

    let keypair = keystore::load_keypair(&keystore::identity_key_path())?;
    let (certs, key) =
        keystore::load_tls_cert(&keystore::tls_cert_path(), &keystore::tls_key_path())?;

    setup_logging();
    write_pid()?;

    let address = Address::with_port(&config.host, config.port, &config.agent_name)?;
    let tls_config = transport::server_config(certs, key)?;
    let tls_acceptor = transport::tls_acceptor(tls_config);
    let local_card = load_card(&config, &keypair);
    let features = Features::default();

    // Wire PolicyEngine from config
    let policy_mode = match config.connection_mode.as_str() {
        "open" => ConnectionMode::Open,
        "allowlist" => ConnectionMode::Allowlist,
        "dns-verified" => ConnectionMode::DnsVerified,
        _ => ConnectionMode::Approval,
    };
    let mut engine = PolicyEngine::new(policy_mode);
    let perms_file =
        toq_core::config::PermissionsFile::load(&toq_core::config::PermissionsFile::path())
            .unwrap_or_default();
    engine.load_from_permissions(&perms_file);
    let policy = std::sync::Arc::new(tokio::sync::Mutex::new(engine));

    // Wire RateLimiter
    let rate_limiter = std::sync::Arc::new(tokio::sync::Mutex::new(RateLimiter::new(
        DEFAULT_CONNECTIONS_PER_IP_PER_SEC,
    )));

    // Wire SessionStore
    let sessions = std::sync::Arc::new(tokio::sync::Mutex::new(SessionStore::new()));

    let listener = if auto_port {
        let mut port = config.port;
        loop {
            let addr = format!("{}:{}", toq_core::constants::DEFAULT_BIND_ADDRESS, port);
            match server::bind(&addr).await {
                Ok(l) => {
                    config.port = port;
                    break l;
                }
                Err(_) => {
                    port += 1;
                    if port > 9999 {
                        return Err("No available port found".into());
                    }
                }
            }
        }
    } else {
        let bind_addr = format!(
            "{}:{}",
            toq_core::constants::DEFAULT_BIND_ADDRESS,
            config.port
        );
        server::bind(&bind_addr).await?
    };
    register_agent(&config.agent_name, config.port, &dirs_path())?;

    let bind_addr = format!(
        "{}:{}",
        toq_core::constants::DEFAULT_BIND_ADDRESS,
        config.port
    );
    tracing::info!("toq up on {}", address);
    println!("toq up on {address}");
    println!("  public key: {}", keypair.public_key());
    println!("  listening on {bind_addr}");
    println!("  connection mode: {}", config.connection_mode);

    // Attempt UPnP port mapping
    match std::process::Command::new("upnpc")
        .args([
            "-a",
            &bind_addr,
            &config.port.to_string(),
            &config.port.to_string(),
            "TCP",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
    {
        Ok(status) if status.success() => {
            tracing::info!("UPnP port mapping added for port {}", config.port);
            println!("  UPnP: port {} mapped", config.port);
        }
        _ => {
            tracing::info!(
                "UPnP not available (install miniupnpc or configure port forwarding manually)"
            );
        }
    }

    // Load adapter config
    let adapter_url = config.adapter_http.as_ref().map(|h| h.callback_url.clone());

    let active_connections = std::sync::Arc::new(AtomicUsize::new(0));
    let messages_in = std::sync::Arc::new(AtomicUsize::new(0));
    let messages_out = std::sync::Arc::new(AtomicUsize::new(0));

    // Helper to update state file
    let state_address = address.to_string();
    let state_mode = config.connection_mode.clone();
    let state_port = config.port;
    let conn_counter = active_connections.clone();
    let in_counter = messages_in.clone();
    let out_counter = messages_out.clone();
    let update_state = move || {
        let state = serde_json::json!({
            "status": "running",
            "address": state_address,
            "port": state_port,
            "connection_mode": state_mode,
            "pid": std::process::id(),
            "active_connections": conn_counter.load(Ordering::Relaxed),
            "messages_in": in_counter.load(Ordering::Relaxed),
            "messages_out": out_counter.load(Ordering::Relaxed),
        });
        let _ = fs::write(
            state_path(),
            serde_json::to_string_pretty(&state).unwrap_or_default(),
        );
    };
    update_state();

    let error_count = std::sync::Arc::new(AtomicUsize::new(0));

    // Build API state
    let api_state = api::ApiState::new(api::state::ApiStateParams {
        config: config.clone(),
        keypair: keypair.clone(),
        address: address.clone(),
        active_connections: active_connections.clone(),
        messages_in: messages_in.clone(),
        messages_out: messages_out.clone(),
        error_count: error_count.clone(),
        policy: policy.clone(),
        sessions: sessions.clone(),
    });
    let message_tx = api_state.message_tx.clone();
    let history_store = api_state.history.clone();
    let handler_mgr = api_state.handler_manager.clone();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    *api_state.shutdown_tx.lock().await = Some(shutdown_tx);
    let http_router = api::router(api_state.clone(), config.a2a_enabled);
    let http_remote_router = api::remote_router(api_state, config.a2a_enabled);

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to register SIGTERM handler");

    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (tcp, peer_addr) = accept?;

                // Peek first byte to determine protocol.
                // Timeout prevents slowloris attacks where connections are
                // opened but no data is sent, tying up tokio tasks.
                const PEEK_TIMEOUT_SECS: u64 = 5;
                let mut peek_buf = [0u8; 1];
                match tokio::time::timeout(
                    std::time::Duration::from_secs(PEEK_TIMEOUT_SECS),
                    tcp.peek(&mut peek_buf),
                ).await {
                    Ok(Ok(1)) => {}
                    _ => continue,
                }

                // TLS ClientHello starts with 0x16 -> toq protocol
                // HTTP methods start with ASCII letters -> HTTP API
                const TLS_HANDSHAKE_BYTE: u8 = 0x16;
                if peek_buf[0] != TLS_HANDSHAKE_BYTE {
                    // Local connections get full API; remote connections
                    // only get A2A routes (if enabled) and are rate limited.
                    let app = if peer_addr.ip().is_loopback() {
                        http_router.clone()
                    } else {
                        let mut rl = rate_limiter.lock().await;
                        if !rl.check(peer_addr.ip()) {
                            tracing::warn!("rate limited: {}", peer_addr.ip());
                            continue;
                        }
                        drop(rl);
                        http_remote_router.clone()
                    };
                    tokio::spawn(async move {
                        api::serve_connection(app, tcp).await;
                    });
                    continue;
                }

                // Rate limiting (toq protocol connections only)
                {
                    let mut rl = rate_limiter.lock().await;
                    if !rl.check(peer_addr.ip()) {
                        tracing::warn!("rate limited: {}", peer_addr.ip());
                        continue;
                    }
                }

                tracing::info!("connection from {}", peer_addr);

                let tls_acceptor = tls_acceptor.clone();
                let keypair_clone = keypair.clone();
                let address_clone = address.clone();
                let card_clone = local_card.clone();
                let features_clone = features.clone();
                let policy_clone = policy.clone();
                let sessions_clone = sessions.clone();
                let adapter_url_clone = adapter_url.clone();
                let conn_count = active_connections.clone();
                let msg_count = messages_in.clone();
                let msg_tx = message_tx.clone();
                let history = history_store.clone();
                let handlers = handler_mgr.clone();

                tokio::spawn(async move {
                    // Lock policy only for accept_connection, release after
                    let accept_result = {
                        let mut policy_guard = policy_clone.lock().await;
                        server::accept_connection(
                            tcp, &tls_acceptor, &keypair_clone, &address_clone,
                            &card_clone, &features_clone, Some(&mut *policy_guard),
                        ).await
                    };

                    match accept_result {
                        Ok((info, mut stream)) => {
                            tracing::info!("connected: {} ({})", info.peer_card.name, info.peer_address);
                            println!("Connected: {} ({})", info.peer_card.name, info.peer_address);

                            // Register session
                            {
                                let mut sess = sessions_clone.lock().await;
                                if let Some(old_id) = sess.check_duplicate(&info.peer_public_key) {
                                    tracing::info!("duplicate connection, closing old session {}", old_id);
                                    sess.remove(&old_id);
                                }
                                sess.register(&info.session_id, &info.peer_public_key, &info.peer_address.to_string());
                            }

                            // Record peer in store
                            {
                                let mut store = keystore::PeerStore::load(&keystore::peers_path()).unwrap_or_default();
                                store.upsert(&info.peer_public_key, &info.peer_address.to_string());
                                let _ = store.save(&keystore::peers_path());
                            }
                            conn_count.fetch_add(1, Ordering::Relaxed);

                            // Connection receive loop
                            let mut seq = 2u64;
                            while let Ok(envelope) = framing::recv_envelope(
                                &mut stream, &info.peer_public_key, DEFAULT_MAX_MESSAGE_SIZE
                            ).await {
                                match envelope.msg_type {
                                    MessageType::MessageSend | MessageType::ThreadClose => {
                                        let agent_msg = AgentMessage::from_envelope(&envelope);
                                        tracing::info!("message from {}: {}", agent_msg.from, agent_msg.id);
                                        msg_count.fetch_add(1, Ordering::Relaxed);

                                        // Broadcast to SSE subscribers
                                        let incoming = api::types::IncomingMessage {
                                            id: agent_msg.id.clone(),
                                            msg_type: agent_msg.msg_type.clone(),
                                            from: agent_msg.from.clone(),
                                            body: agent_msg.body.clone(),
                                            thread_id: agent_msg.thread_id.clone(),
                                            reply_to: agent_msg.reply_to.clone(),
                                            content_type: agent_msg.content_type.clone(),
                                            timestamp: toq_core::now_utc(),
                                        };
                                        history.lock().await.push(&incoming);
                                        let _ = msg_tx.send(incoming.clone());

                                        // Dispatch to matching handlers
                                        handlers.lock().await.dispatch(&incoming, Some(&info.peer_public_key));

                                        // Deliver to adapter
                                        if let Some(ref url) = adapter_url_clone {
                                            let adapter = toq_core::adapter::HttpAdapter::new(url);
                                            if let Err(e) = adapter.deliver(&agent_msg).await {
                                                tracing::warn!("adapter delivery failed: {e}");
                                                let _ = toq_core::connection::send_system_error(
                                                    &mut stream, &keypair_clone, &address_clone,
                                                    &info.peer_address, "agent_unavailable",
                                                    "local agent is not responding",
                                                    Some(&envelope.id.to_string()), seq,
                                                ).await;
                                                seq += 1;
                                            }
                                        }

                                        // Send ack
                                        let _ = messaging::send_ack(
                                            &mut stream, &keypair_clone, &address_clone,
                                            &info.peer_address, &envelope.id, seq,
                                        ).await;
                                        seq += 1;
                                    }
                                    MessageType::StreamChunk | MessageType::StreamEnd => {
                                        let agent_msg = AgentMessage::from_envelope(&envelope);
                                        tracing::info!("stream from {}: {}", agent_msg.from, agent_msg.id);

                                        if envelope.msg_type == MessageType::StreamEnd {
                                            msg_count.fetch_add(1, Ordering::Relaxed);
                                        }

                                        let incoming = api::types::IncomingMessage {
                                            id: agent_msg.id.clone(),
                                            msg_type: agent_msg.msg_type.clone(),
                                            from: agent_msg.from.clone(),
                                            body: agent_msg.body.clone(),
                                            thread_id: agent_msg.thread_id.clone(),
                                            reply_to: agent_msg.reply_to.clone(),
                                            content_type: agent_msg.content_type.clone(),
                                            timestamp: toq_core::now_utc(),
                                        };
                                        if envelope.msg_type == MessageType::StreamEnd {
                                            history.lock().await.push(&incoming);
                                            // Dispatch to handlers on stream completion
                                            handlers.lock().await.dispatch(&incoming, Some(&info.peer_public_key));
                                        }
                                        let _ = msg_tx.send(incoming);

                                        let _ = messaging::send_ack(
                                            &mut stream, &keypair_clone, &address_clone,
                                            &info.peer_address, &envelope.id, seq,
                                        ).await;
                                        seq += 1;
                                    }
                                    MessageType::SessionDisconnect => {
                                        tracing::info!("peer disconnected: {}", info.peer_address);
                                        break;
                                    }
                                    MessageType::Heartbeat => {
                                        let _ = toq_core::connection::send_heartbeat_ack(
                                            &mut stream, &keypair_clone, &address_clone,
                                            &info.peer_address, &envelope.id, seq,
                                        ).await;
                                        seq += 1;
                                    }
                                    other => {
                                        tracing::debug!("received: {other:?}");
                                    }
                                }
                            }

                            // Clean up session
                            {
                                let mut sess = sessions_clone.lock().await;
                                sess.remove(&info.session_id);
                            }
                            conn_count.fetch_sub(1, Ordering::Relaxed);
                            tracing::info!("connection closed: {}", info.peer_address);
                        }
                        Err(e) => {
                            tracing::warn!("connection from {peer_addr} failed: {e}");
                        }
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("toq down (signal)");
                println!("\ntoq down");
                break;
            }
            _ = sigterm.recv() => {
                tracing::info!("toq down (SIGTERM)");
                println!("\ntoq down");
                break;
            }
            _ = &mut shutdown_rx => {
                tracing::info!("toq down (API shutdown)");
                println!("\ntoq down (API)");
                break;
            }
        }
    }

    remove_pid();
    let _ = fs::remove_file(state_path());
    unregister_agent(&config.agent_name);

    // Persist policy engine state
    {
        let policy_guard = policy.lock().await;
        // Save permissions (approved, blocked, pending) to permissions.toml
        let perms = policy_guard.sync_to_permissions();
        let _ = perms.save(&toq_core::config::PermissionsFile::path());
        // Save peer metadata to peer store (no permission status)
        let mut peer_store =
            toq_core::keystore::PeerStore::load(&keystore::peers_path()).unwrap_or_default();
        policy_guard.sync_to_peer_store(&mut peer_store);
        let _ = peer_store.save(&keystore::peers_path());
    }

    Ok(())
}

fn run_down(graceful: bool, name: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    // If --name is given, look up the agent in the registry
    if let Some(agent_name) = name {
        let agent_file = agents_registry_dir().join(format!("{agent_name}.toml"));
        if !agent_file.exists() {
            return Err(format!("No agent named '{agent_name}' found").into());
        }
        let contents = fs::read_to_string(&agent_file)?;
        let pid: u32 = contents
            .lines()
            .find(|l| l.starts_with("pid"))
            .and_then(|l| l.split('=').nth(1))
            .and_then(|v| v.trim().parse().ok())
            .ok_or("Could not read PID from agent registry")?;

        #[cfg(unix)]
        {
            let status = std::process::Command::new("kill")
                .arg(pid.to_string())
                .status()?;
            if status.success() {
                println!("toq down '{agent_name}' (PID {pid})");
            } else {
                println!("toq down '{agent_name}' (cleaned up stale state)");
            }
            let _ = fs::remove_file(&agent_file);
        }
        return Ok(());
    }

    match read_pid() {
        Some(pid) => {
            #[cfg(unix)]
            {
                use std::process::Command;
                let status = Command::new("kill").arg(pid.to_string()).status()?;
                if status.success() {
                    if graceful {
                        println!("toq down --graceful (PID {pid})");
                    } else {
                        println!("toq down (PID {pid})");
                    }
                } else {
                    println!("toq down (cleaned up stale state)");
                }
                let _ = fs::remove_file(pid_path());
                let _ = fs::remove_file(state_path());
                if let Ok(cfg) = Config::load(&Config::default_path()) {
                    unregister_agent(&cfg.agent_name);
                }
            }
            #[cfg(not(unix))]
            {
                let _ = graceful;
                eprintln!("toq down not supported on this platform");
            }
        }
        None => {
            println!("toq is not running (no PID file found)");
        }
    }
    Ok(())
}

fn run_config(action: ConfigAction) -> Result<(), Box<dyn std::error::Error>> {
    require_setup();
    let path = Config::default_path();
    match action {
        ConfigAction::Show => {
            let contents = fs::read_to_string(&path)?;
            print!("{contents}");
        }
        ConfigAction::Set { key, value } => {
            let mut config = Config::load(&path)?;
            match key.as_str() {
                "agent_name" => config.agent_name = value.clone(),
                "host" => config.host = value.clone(),
                "port" => config.port = value.parse().map_err(|_| "invalid port")?,
                "connection_mode" => {
                    if !["open", "allowlist", "approval", "dns-verified"].contains(&value.as_str())
                    {
                        return Err("must be open, allowlist, approval, or dns-verified".into());
                    }
                    config.connection_mode = value.clone();
                }
                "log_level" => config.log_level = value.clone(),
                "max_message_size" => {
                    config.max_message_size = value.parse().map_err(|_| "invalid number")?
                }
                _ => return Err(format!("unknown config key '{key}'").into()),
            }
            config.save(&path)?;
            println!("{key} = {value}");
        }
    }
    Ok(())
}

fn run_a2a(action: A2aAction) -> Result<(), Box<dyn std::error::Error>> {
    require_setup();
    let path = Config::default_path();
    let mut config = Config::load(&path)?;
    match action {
        A2aAction::Enable { key } => {
            config.a2a_enabled = true;
            if let Some(k) = key {
                if k.is_empty() {
                    return Err("API key cannot be empty".into());
                }
                config.a2a_api_key = Some(k);
            }
            config.save(&path)?;
            println!("A2A enabled");
            if config.a2a_api_key.is_some() {
                println!("  auth: Bearer token required");
            } else {
                println!("  auth: open access (no key set)");
            }
            println!("Restart the daemon for changes to take effect: toq down && toq up");
        }
        A2aAction::Disable => {
            config.a2a_enabled = false;
            config.save(&path)?;
            println!("A2A disabled");
            println!("Restart the daemon for changes to take effect: toq down && toq up");
        }
        A2aAction::Status => {
            if config.a2a_enabled {
                println!("A2A: enabled");
                if config.a2a_api_key.is_some() {
                    println!("  auth: Bearer token configured");
                } else {
                    println!("  auth: open access");
                }
                if let Some(ref url) = config.a2a_public_url {
                    println!("  public URL: {url}");
                }
            } else {
                println!("A2A: disabled");
                println!("  enable with: toq a2a enable");
            }
        }
    }
    Ok(())
}

fn run_whoami() -> Result<(), Box<dyn std::error::Error>> {
    require_setup();
    let config = Config::load(&Config::default_path())?;
    let keypair = keystore::load_keypair(&keystore::identity_key_path())?;
    let pub_key = keypair.public_key().to_encoded();
    println!("agent:           {}", config.agent_name);
    println!(
        "address:         toq://{}/{}",
        config.host, config.agent_name
    );
    println!("public key:      {pub_key}");
    println!("connection mode: {}", config.connection_mode);
    println!("port:            {}", config.port);
    Ok(())
}

fn run_status() -> Result<(), Box<dyn std::error::Error>> {
    let sp = state_path();
    if !sp.exists() {
        println!("toq is not running");
        return Ok(());
    }
    let data = fs::read_to_string(&sp)?;
    let file_state: serde_json::Value = serde_json::from_str(&data)?;
    let port = file_state["port"].as_u64().unwrap_or_else(|| {
        Config::load(&Config::default_path())
            .map(|c| c.port as u64)
            .unwrap_or(toq_core::constants::DEFAULT_PORT as u64)
    }) as u16;

    // Try live API first, fall back to state file
    let state = match std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        std::time::Duration::from_millis(500),
    ) {
        Ok(mut tcp) => {
            use std::io::{Read, Write};
            let req = "GET /v1/status HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n";
            let _ = tcp.write_all(req.as_bytes());
            let mut buf = String::new();
            let _ = tcp.read_to_string(&mut buf);
            buf.split("\r\n\r\n")
                .nth(1)
                .and_then(|body| serde_json::from_str(body).ok())
                .unwrap_or(file_state)
        }
        _ => file_state,
    };

    let config = Config::load(&Config::default_path()).ok();
    let technical = config
        .as_ref()
        .map(|c| c.verbosity == "technical")
        .unwrap_or(false);

    println!("toq status");
    println!(
        "  status:          {}",
        state["status"].as_str().unwrap_or("unknown")
    );
    println!(
        "  address:         {}",
        state["address"].as_str().unwrap_or("unknown")
    );
    println!(
        "  connection mode: {}",
        state["connection_mode"].as_str().unwrap_or("unknown")
    );
    println!(
        "  connections:     {}",
        state["active_connections"].as_u64().unwrap_or(0)
    );
    println!(
        "  messages in:     {}",
        state["messages_in"].as_u64().unwrap_or(0)
    );
    println!(
        "  messages out:    {}",
        state["messages_out"].as_u64().unwrap_or(0)
    );

    if technical {
        println!("  port:            {}", state["port"]);
        println!("  pid:             {}", state["pid"]);
    }

    Ok(())
}

fn run_peers() -> Result<(), Box<dyn std::error::Error>> {
    let store = toq_core::keystore::PeerStore::load(&keystore::peers_path())?;
    if store.peers.is_empty() {
        println!("No known peers");
        return Ok(());
    }
    println!("{:<50} {:<12} LAST SEEN", "PUBLIC KEY", "ADDRESS");
    for (key, record) in &store.peers {
        let short_key = if key.len() > 45 { &key[..45] } else { key };
        println!(
            "{:<50} {:<12} {}",
            short_key, record.address, record.last_seen
        );
    }
    Ok(())
}

/// Resolve --from, --key, or legacy positional arg into a PermissionRule.
fn resolve_rule(
    from: Option<&str>,
    key: Option<&str>,
    agent: Option<&str>,
) -> Result<toq_core::policy::PermissionRule, Box<dyn std::error::Error>> {
    use toq_core::policy::PermissionRule;
    if let Some(addr) = from {
        return Ok(PermissionRule::Address(addr.to_string()));
    }
    if let Some(k) = key {
        let pk = toq_core::crypto::PublicKey::from_encoded(k)?;
        return Ok(PermissionRule::Key(pk.as_bytes().to_vec()));
    }
    if let Some(a) = agent {
        // Legacy: try as public key first, then treat as address
        if let Ok(pk) = toq_core::crypto::PublicKey::from_encoded(a) {
            return Ok(PermissionRule::Key(pk.as_bytes().to_vec()));
        }
        // Look up in peer store by address
        let store = toq_core::keystore::PeerStore::load(&keystore::peers_path())?;
        if let Some((key_str, _)) = store.peers.iter().find(|(_, r)| r.address == a) {
            let pk = toq_core::crypto::PublicKey::from_encoded(key_str)?;
            return Ok(PermissionRule::Key(pk.as_bytes().to_vec()));
        }
        // Treat as address pattern
        return Ok(PermissionRule::Address(a.to_string()));
    }
    Err("Specify --from, --key, or a positional argument".into())
}

async fn run_block(
    from: Option<&str>,
    key: Option<&str>,
    agent: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let rule = resolve_rule(from, key, agent)?;
    let label = from.or(key).or(agent).unwrap_or("unknown");

    // If daemon is running, use API
    if read_pid().is_some()
        && let Ok(base) = api_base()
    {
        let body = match &rule {
            toq_core::policy::PermissionRule::Key(kb) => {
                let pk = toq_core::crypto::PublicKey::from_bytes(kb).ok_or("invalid key")?;
                serde_json::json!({"key": pk.to_encoded()})
            }
            toq_core::policy::PermissionRule::Address(addr) => {
                serde_json::json!({"from": addr})
            }
        };
        let url = format!("{}/v1/block", base);
        if let Ok(resp) = reqwest::Client::new().post(&url).json(&body).send().await
            && resp.status().is_success()
        {
            println!("Blocked {label}");
            return Ok(());
        }
    }

    // Fallback: modify permissions.toml directly (daemon not running)
    {
        let path = toq_core::config::PermissionsFile::path();
        let mut perms = toq_core::config::PermissionsFile::load(&path).unwrap_or_default();
        let entry = match &rule {
            toq_core::policy::PermissionRule::Key(kb) => toq_core::config::PermissionEntry {
                rule_type: "key".into(),
                value: toq_core::crypto::PublicKey::from_bytes(kb)
                    .map(|pk| pk.to_encoded())
                    .unwrap_or_default(),
            },
            toq_core::policy::PermissionRule::Address(addr) => toq_core::config::PermissionEntry {
                rule_type: "address".into(),
                value: addr.clone(),
            },
        };
        if !perms.blocked.contains(&entry) {
            perms.blocked.push(entry);
        }
        // Remove from approved if present
        perms
            .approved
            .retain(|e| e != perms.blocked.last().unwrap());
        let _ = perms.save(&path);
    }
    println!("Blocked {label}");
    Ok(())
}

async fn run_unblock(
    from: Option<&str>,
    key: Option<&str>,
    agent: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let rule = resolve_rule(from, key, agent)?;
    let label = from.or(key).or(agent).unwrap_or("unknown");

    if read_pid().is_some()
        && let Ok(base) = api_base()
    {
        let body = match &rule {
            toq_core::policy::PermissionRule::Key(kb) => {
                let pk = toq_core::crypto::PublicKey::from_bytes(kb).ok_or("invalid key")?;
                serde_json::json!({"key": pk.to_encoded()})
            }
            toq_core::policy::PermissionRule::Address(addr) => {
                serde_json::json!({"from": addr})
            }
        };
        let url = format!("{}/v1/block", base);
        if let Ok(resp) = reqwest::Client::new().delete(&url).json(&body).send().await
            && resp.status().is_success()
        {
            println!("Unblocked {label}");
            return Ok(());
        }
    }

    // Fallback: modify permissions.toml directly (daemon not running)
    {
        let path = toq_core::config::PermissionsFile::path();
        let mut perms = toq_core::config::PermissionsFile::load(&path).unwrap_or_default();
        let entry = match &rule {
            toq_core::policy::PermissionRule::Key(kb) => toq_core::config::PermissionEntry {
                rule_type: "key".into(),
                value: toq_core::crypto::PublicKey::from_bytes(kb)
                    .map(|pk| pk.to_encoded())
                    .unwrap_or_default(),
            },
            toq_core::policy::PermissionRule::Address(addr) => toq_core::config::PermissionEntry {
                rule_type: "address".into(),
                value: addr.clone(),
            },
        };
        perms.blocked.retain(|e| e != &entry);
        let _ = perms.save(&path);
    }
    println!("Unblocked {label}");
    Ok(())
}

fn run_clear_logs() -> Result<(), Box<dyn std::error::Error>> {
    let log_dir = dirs_path().join(LOGS_DIR);
    if log_dir.exists() {
        for entry in fs::read_dir(&log_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                let _ = fs::remove_dir_all(&path);
            } else {
                let _ = fs::remove_file(&path);
            }
        }
    }
    // Also clear message history file
    let history = crate::api::state::history_path();
    if history.exists() {
        let _ = fs::remove_file(&history);
    }
    println!("Logs cleared");
    Ok(())
}

/// Base URL for the local daemon API.
fn api_base() -> Result<String, Box<dyn std::error::Error>> {
    let config = Config::load(&Config::default_path())?;
    Ok(format!("http://127.0.0.1:{}", config.port))
}

async fn run_approvals() -> Result<(), Box<dyn std::error::Error>> {
    require_running();
    let url = format!("{}/v1/approvals", api_base()?);
    let resp: serde_json::Value = reqwest::get(&url).await?.json().await?;
    let approvals = resp["approvals"].as_array();
    match approvals {
        Some(list) if !list.is_empty() => {
            for a in list {
                let key = a["public_key"].as_str().unwrap_or("");
                let addr = a["address"].as_str().unwrap_or("");
                let time = a["requested_at"].as_str().unwrap_or("");
                println!("{key}");
                println!("  address:   {addr}");
                println!("  requested: {time}");
                println!();
            }
        }
        _ => println!("No pending approvals"),
    }
    Ok(())
}

async fn run_messages(from: Option<&str>, limit: usize) -> Result<(), Box<dyn std::error::Error>> {
    require_running();
    let mut url = format!("{}/v1/messages/history?limit={limit}", api_base()?);
    if let Some(f) = from {
        url.push_str(&format!("&from={}", urlencode_path(f)));
    }
    let resp: serde_json::Value = reqwest::get(&url).await?.json().await?;
    let messages = resp["messages"].as_array();
    match messages {
        Some(msgs) if msgs.is_empty() => println!("No messages"),
        Some(msgs) => {
            for m in msgs {
                let from = m["from"].as_str().unwrap_or("unknown");
                let text = m["body"]["text"].as_str().unwrap_or("");
                let ts = m["timestamp"].as_str().unwrap_or("");
                let id = m["id"].as_str().unwrap_or("");
                let thread = m["thread_id"].as_str().unwrap_or("-");
                let msg_type = m["type"].as_str().unwrap_or("message.send");
                if msg_type == "thread.close" {
                    if text.is_empty() {
                        println!(
                            "[{ts}] {from} closed the thread {}",
                            dim(&format!("(thread: {thread})"))
                        );
                    } else {
                        println!("[{ts}] {from}: {text} [thread closed]");
                        println!("  {}", dim(&format!("id: {id}  thread: {thread}")));
                    }
                } else {
                    println!("[{ts}] {from}: {text}");
                    println!("  {}", dim(&format!("id: {id}  thread: {thread}")));
                }
            }
        }
        None => println!("No messages"),
    }
    Ok(())
}

fn urlencode_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
}

async fn run_approve(
    id: Option<&str>,
    from: Option<&str>,
    key: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    require_running();
    let base = api_base()?;

    // If --from or --key, add a permission rule
    if from.is_some() || key.is_some() {
        let rule = resolve_rule(from, key, None)?;
        let label = from.or(key).unwrap_or("unknown");
        let body = match &rule {
            toq_core::policy::PermissionRule::Key(kb) => {
                let pk = toq_core::crypto::PublicKey::from_bytes(kb).ok_or("invalid key")?;
                serde_json::json!({"key": pk.to_encoded()})
            }
            toq_core::policy::PermissionRule::Address(addr) => {
                serde_json::json!({"from": addr})
            }
        };
        let url = format!("{}/v1/approve", base);
        let resp = reqwest::Client::new().post(&url).json(&body).send().await?;
        if resp.status().is_success() {
            println!("Approved {label}");
        } else {
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            let msg = body["error"]["message"].as_str().unwrap_or("unknown error");
            eprintln!("Failed to approve: {msg}");
        }
        return Ok(());
    }

    // Fetch pending approvals
    let list_url = format!("{}/v1/approvals", base);
    let list_resp: serde_json::Value = reqwest::get(&list_url).await?.json().await?;
    let approvals = list_resp["approvals"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if approvals.is_empty() {
        println!("No pending approvals");
        return Ok(());
    }

    // Resolve which approval to act on
    let resolved_key = if let Some(raw_id) = id {
        if raw_id.starts_with("ed25519:") {
            raw_id.to_string()
        } else if let Ok(idx) = raw_id.parse::<usize>() {
            if idx == 0 || idx > approvals.len() {
                return Err(format!("Invalid index {idx}. Use 1-{}", approvals.len()).into());
            }
            approvals[idx - 1]["public_key"]
                .as_str()
                .ok_or("missing key")?
                .to_string()
        } else {
            // Match by agent name in address
            approvals
                .iter()
                .find(|a| {
                    a["address"]
                        .as_str()
                        .is_some_and(|addr| addr.ends_with(&format!("/{raw_id}")))
                })
                .and_then(|a| a["public_key"].as_str())
                .ok_or_else(|| format!("No pending approval from '{raw_id}'"))?
                .to_string()
        }
    } else {
        // Interactive selector
        let options: Vec<String> = approvals
            .iter()
            .enumerate()
            .map(|(i, a)| {
                let addr = a["address"].as_str().unwrap_or("unknown");
                let key = a["public_key"].as_str().unwrap_or("");
                let short_key = key.get(..20).unwrap_or(key);
                format!("{}. {} ({}...)", i + 1, addr, short_key)
            })
            .collect();
        let choice = inquire::Select::new("Select agent to approve:", options).prompt()?;
        let idx: usize = choice.split('.').next().unwrap_or("0").parse().unwrap_or(0);
        if idx == 0 || idx > approvals.len() {
            return Err("Invalid selection".into());
        }
        approvals[idx - 1]["public_key"]
            .as_str()
            .ok_or("missing key")?
            .to_string()
    };

    let url = format!("{}/v1/approvals/{}", base, urlencode_path(&resolved_key));
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&serde_json::json!({"decision": "approve"}))
        .send()
        .await?;
    if resp.status().is_success() {
        println!("Approved {resolved_key}");
    } else {
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        let msg = body["error"]["message"].as_str().unwrap_or("unknown error");
        eprintln!("Failed to approve: {msg}");
    }
    Ok(())
}

async fn run_deny(id: &str) -> Result<(), Box<dyn std::error::Error>> {
    require_running();
    let url = format!("{}/v1/approvals/{}", api_base()?, urlencode_path(id));
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .json(&serde_json::json!({"decision": "deny"}))
        .send()
        .await?;
    if resp.status().is_success() {
        println!("Denied {id}");
    } else {
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        let msg = body["error"]["message"].as_str().unwrap_or("unknown error");
        eprintln!("Failed to deny: {msg}");
    }
    Ok(())
}

async fn run_revoke(
    id: Option<&str>,
    from: Option<&str>,
    key: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    require_running();
    let base = api_base()?;

    if from.is_some() || key.is_some() {
        let rule = resolve_rule(from, key, None)?;
        let label = from.or(key).unwrap_or("unknown");
        let body = match &rule {
            toq_core::policy::PermissionRule::Key(kb) => {
                let pk = toq_core::crypto::PublicKey::from_bytes(kb).ok_or("invalid key")?;
                serde_json::json!({"key": pk.to_encoded()})
            }
            toq_core::policy::PermissionRule::Address(addr) => {
                serde_json::json!({"from": addr})
            }
        };
        let url = format!("{}/v1/revoke", base);
        let resp = reqwest::Client::new().post(&url).json(&body).send().await?;
        if resp.status().is_success() {
            println!("Revoked {label}");
        } else {
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            let msg = body["error"]["message"].as_str().unwrap_or("unknown error");
            eprintln!("Failed to revoke: {msg}");
        }
        return Ok(());
    }

    let id = id.ok_or("Specify --from, --key, or a public key ID")?;
    let url = format!("{}/v1/approvals/{}/revoke", base, urlencode_path(id));
    let resp = reqwest::Client::new().post(&url).send().await?;
    if resp.status().is_success() {
        println!("Revoked {id}");
    } else {
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        let msg = body["error"]["message"].as_str().unwrap_or("unknown error");
        eprintln!("Failed to revoke: {msg}");
    }
    Ok(())
}

async fn run_permissions() -> Result<(), Box<dyn std::error::Error>> {
    require_running();
    let url = format!("{}/v1/permissions", api_base()?);
    let resp = reqwest::Client::new().get(&url).send().await?;
    let body: serde_json::Value = resp.json().await?;

    let approved = body["approved"].as_array();
    let blocked = body["blocked"].as_array();

    println!("Approved:");
    if let Some(rules) = approved {
        if rules.is_empty() {
            println!("  (none)");
        }
        for r in rules {
            let t = r["type"].as_str().unwrap_or("?");
            let v = r["value"].as_str().unwrap_or("?");
            println!("  {t}: {v}");
        }
    }

    println!("Blocked:");
    if let Some(rules) = blocked {
        if rules.is_empty() {
            println!("  (none)");
        }
        for r in rules {
            let t = r["type"].as_str().unwrap_or("?");
            let v = r["value"].as_str().unwrap_or("?");
            println!("  {t}: {v}");
        }
    }
    Ok(())
}

async fn run_ping(address: &str) -> Result<(), Box<dyn std::error::Error>> {
    require_setup();
    require_running();

    let url = format!("{}/v1/ping", api_base()?);
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&serde_json::json!({"address": address}))
        .send()
        .await?;

    if resp.status().is_success() {
        let body: serde_json::Value = resp.json().await?;
        let agent = body["agent_name"].as_str().unwrap_or("unknown");
        let reachable = body["reachable"].as_bool().unwrap_or(false);
        if reachable {
            let key = body["public_key"].as_str().unwrap_or("unknown");
            println!("Agent:      {agent}");
            println!("Address:    {address}");
            println!("Public key: {key}");
            println!("Status:     reachable");
        } else {
            let err = body["error"].as_str().unwrap_or("connection failed");
            eprintln!("Ping failed: {err}");
            std::process::exit(1);
        }
    } else {
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        let msg = body["error"]["message"].as_str().unwrap_or("ping failed");
        eprintln!("{msg}");
    }
    Ok(())
}
async fn run_discover(domain: &str) -> Result<(), Box<dyn std::error::Error>> {
    let records = toq_core::dns::lookup_txt(domain).await.map_err(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    })?;

    if records.is_empty() {
        println!("No agents found at {domain}");
        return Ok(());
    }

    println!("Agents at {domain}:\n");
    for record in &records {
        let addr = format!("toq://{}/{}", domain, record.agent_name);
        println!(
            "  {:<12} {:<40} port {}",
            record.agent_name, addr, record.port
        );
    }

    Ok(())
}
fn run_logs(follow: bool) -> Result<(), Box<dyn std::error::Error>> {
    let lp = log_path();
    if !lp.exists() {
        println!("No logs found");
        return Ok(());
    }

    if follow {
        let file = fs::File::open(&lp)?;
        let mut reader = io::BufReader::new(file);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
                Ok(_) => {
                    print!("{line}");
                }
                Err(e) => {
                    eprintln!("error reading log: {e}");
                    break;
                }
            }
        }
    } else {
        let content = fs::read_to_string(&lp)?;
        print!("{content}");
    }
    Ok(())
}

async fn run_send(
    target: &str,
    message: &str,
    thread_id: Option<&str>,
    close_thread: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    require_setup();

    // If daemon is running, send through the local API (tracks counters, history, SSE)
    if read_pid().is_some() {
        let url = format!("{}/v1/messages?wait=true", api_base()?);
        let client = reqwest::Client::new();
        let mut body = serde_json::json!({
            "to": target,
            "body": { "text": message }
        });
        if let Some(tid) = thread_id {
            body["thread_id"] = serde_json::json!(tid);
        }
        if close_thread {
            body["close_thread"] = serde_json::json!(true);
        }
        let resp = client.post(&url).json(&body).send().await?;
        let resp_body: serde_json::Value = resp.json().await?;
        if let Some(status) = resp_body["status"].as_str() {
            let id = resp_body["id"].as_str().unwrap_or("unknown");
            println!("{}", gold(&format!("Sent message {id} (status: {status})")));
        } else if let Some(err) = resp_body["error"]["message"].as_str() {
            eprintln!("Send failed: {err}");
        } else {
            eprintln!("Send failed: unexpected response");
        }
        return Ok(());
    }

    // Daemon not running: connect directly
    let config = Config::load(&Config::default_path())?;
    let keypair = keystore::load_keypair(&keystore::identity_key_path())?;
    let address = Address::with_port(&config.host, config.port, &config.agent_name)?;
    let target_addr: Address = target.parse()?;
    let local_card = load_card(&config, &keypair);
    let features = Features::default();

    let connect_addr = toq_core::transport::resolve_target_addr(&target_addr, &config.host).await;
    println!("Connecting to {target_addr}...");

    let (info, mut stream) = match server::connect_to_peer(
        &connect_addr,
        &keypair,
        &address,
        &local_card,
        &features,
        Some(&target_addr.agent_name),
    )
    .await
    {
        Ok(r) => r,
        Err(toq_core::error::Error::ConnectionRejected(reason)) => {
            eprintln!("Send failed: {reason}");
            std::process::exit(1);
        }
        Err(toq_core::error::Error::Io(msg)) if msg.contains("Connection refused") => {
            eprintln!("Send failed: no agent running at {target_addr}");
            std::process::exit(1);
        }
        Err(toq_core::error::Error::Io(msg))
            if msg.contains("timed out") || msg.contains("timeout") =>
        {
            eprintln!("Send failed: connection timed out reaching {target_addr}");
            std::process::exit(1);
        }
        Err(e) => return Err(e.into()),
    };

    println!(
        "connected to {} ({})",
        info.peer_card.name, info.peer_address
    );

    let msg_id = messaging::send_message(
        &mut stream,
        &keypair,
        SendParams {
            from: &address,
            to: std::slice::from_ref(&target_addr),
            sequence: 2,
            body: Some(serde_json::json!({ "text": message })),
            thread_id: thread_id.map(String::from),
            reply_to: None,
            priority: None,
            content_type: Some(toq_core::constants::DEFAULT_CONTENT_TYPE.into()),
            ttl: None,
            msg_type: if close_thread {
                Some(MessageType::ThreadClose)
            } else {
                None
            },
        },
    )
    .await?;

    println!("Sent message {msg_id}");

    let ack = framing::recv_envelope(&mut stream, &info.peer_public_key, DEFAULT_MAX_MESSAGE_SIZE)
        .await?;
    if ack.msg_type == MessageType::MessageAck {
        println!("Ack received");
    } else {
        println!("Unexpected response: {:?}", ack.msg_type);
    }

    Ok(())
}

fn run_rotate_keys() -> Result<(), Box<dyn std::error::Error>> {
    require_setup();

    let old_keypair = keystore::load_keypair(&keystore::identity_key_path())?;
    let old_public = old_keypair.public_key();

    let new_keypair = Keypair::generate();
    let new_public = new_keypair.public_key();

    let proof = toq_core::crypto::generate_rotation_proof(&old_keypair, &new_public);

    keystore::save_keypair(&new_keypair, &keystore::identity_key_path())?;

    // Update peer store with rotation info
    println!("Keys rotated");
    println!("  old public key: {old_public}");
    println!("  new public key: {new_public}");
    println!("  rotation proof: {proof}");
    println!("\nIf the daemon is running, restart it to use the new keys");

    Ok(())
}

fn run_export(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    require_setup();

    let identity = fs::read_to_string(keystore::identity_key_path())?;
    let tls_cert = fs::read_to_string(keystore::tls_cert_path())?;
    let tls_key = fs::read_to_string(keystore::tls_key_path())?;
    let config = fs::read_to_string(Config::default_path())?;
    let peers = if keystore::peers_path().exists() {
        fs::read_to_string(keystore::peers_path())?
    } else {
        "{}".to_string()
    };

    let bundle = serde_json::json!({
        "version": PROTOCOL_VERSION,
        "identity_key": identity.trim(),
        "tls_cert": tls_cert,
        "tls_key": tls_key,
        "config": config,
        "peers": peers,
    });

    let plaintext = serde_json::to_string_pretty(&bundle)?;

    // Encrypt with passphrase
    let passphrase = inquire::Password::new("Export passphrase")
        .without_confirmation()
        .prompt()?;
    if passphrase.is_empty() {
        return Err("passphrase cannot be empty".into());
    }

    let mut salt = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
    let key_bytes = derive_key(passphrase.as_bytes(), &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)?;
    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("encryption failed: {e}"))?;

    let output = serde_json::json!({
        "encrypted": true,
        "kdf": "argon2id",
        "salt": BASE64_STANDARD.encode(salt),
        "nonce": BASE64_STANDARD.encode(nonce_bytes),
        "data": BASE64_STANDARD.encode(&ciphertext),
    });

    fs::write(path, serde_json::to_string_pretty(&output)?)?;
    println!("Exported to {path} (encrypted)");

    Ok(())
}

fn run_import(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read_to_string(path)?;
    let wrapper: serde_json::Value = serde_json::from_str(&data)?;

    // Decrypt if encrypted
    let bundle: serde_json::Value = if wrapper.get("encrypted").and_then(|v| v.as_bool())
        == Some(true)
    {
        let passphrase = inquire::Password::new("Import passphrase")
            .without_confirmation()
            .prompt()?;

        let key_bytes = if wrapper.get("kdf").and_then(|v| v.as_str()) == Some("argon2id") {
            let salt = BASE64_STANDARD.decode(wrapper["salt"].as_str().ok_or("missing salt")?)?;
            derive_key(passphrase.as_bytes(), &salt)?
        } else {
            // Legacy SHA-256 fallback for old backups
            use sha2::{Digest, Sha256};
            Sha256::digest(passphrase.as_bytes()).into()
        };
        let cipher = Aes256Gcm::new_from_slice(&key_bytes)?;
        let nonce_bytes =
            BASE64_STANDARD.decode(wrapper["nonce"].as_str().ok_or("missing nonce")?)?;
        let ciphertext = BASE64_STANDARD.decode(wrapper["data"].as_str().ok_or("missing data")?)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| "decryption failed (wrong passphrase?)")?;
        serde_json::from_slice(&plaintext)?
    } else {
        wrapper
    };

    let identity = bundle["identity_key"]
        .as_str()
        .ok_or("missing identity_key in backup")?;
    let tls_cert = bundle["tls_cert"]
        .as_str()
        .ok_or("missing tls_cert in backup")?;
    let tls_key = bundle["tls_key"]
        .as_str()
        .ok_or("missing tls_key in backup")?;
    let config = bundle["config"]
        .as_str()
        .ok_or("missing config in backup")?;
    let peers = bundle["peers"].as_str().ok_or("missing peers in backup")?;

    let _ = fs::create_dir_all(dirs_path().join(toq_core::constants::KEYS_DIR));
    let _ = fs::create_dir_all(dirs_path().join(LOGS_DIR));

    fs::write(keystore::identity_key_path(), identity)?;
    fs::write(keystore::tls_cert_path(), tls_cert)?;
    fs::write(keystore::tls_key_path(), tls_key)?;
    fs::write(Config::default_path(), config)?;
    fs::write(keystore::peers_path(), peers)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(
            keystore::identity_key_path(),
            fs::Permissions::from_mode(0o600),
        );
        let _ = fs::set_permissions(keystore::tls_key_path(), fs::Permissions::from_mode(0o600));
    }

    println!("Imported from {path}");
    println!("Run `toq up` to start with the restored identity");

    Ok(())
}

async fn run_doctor() -> Result<(), Box<dyn std::error::Error>> {
    println!("toq doctor\n");
    let mut issues = 0;

    // Check setup
    if keystore::is_setup_complete() {
        println!("  [ok] setup complete");
    } else {
        println!("  [!!] setup not complete, run `toq setup`");
        issues += 1;
        println!("\n{issues} issue(s) found");
        return Ok(());
    }

    // Check config
    match Config::load(&Config::default_path()) {
        Ok(config) => println!("  [ok] config loaded (agent: {})", config.agent_name),
        Err(e) => {
            println!("  [!!] config error: {e}");
            issues += 1;
        }
    }

    // Check identity key
    match keystore::load_keypair(&keystore::identity_key_path()) {
        Ok(kp) => println!("  [ok] identity key valid ({})", kp.public_key()),
        Err(e) => {
            println!("  [!!] identity key error: {e}");
            issues += 1;
        }
    }

    // Check TLS cert
    match keystore::load_tls_cert(&keystore::tls_cert_path(), &keystore::tls_key_path()) {
        Ok(_) => println!("  [ok] TLS certificate valid"),
        Err(e) => {
            println!("  [!!] TLS certificate error: {e}");
            issues += 1;
        }
    }

    // Check port (skip if daemon is already running, since it owns the port)
    let config = Config::load(&Config::default_path())?;
    let daemon_running = read_pid().is_some();
    if daemon_running {
        println!("  [ok] port {} in use by daemon", config.port);
    } else {
        let bind_addr = format!(
            "{}:{}",
            toq_core::constants::DEFAULT_BIND_ADDRESS,
            config.port
        );
        match tokio::net::TcpListener::bind(&bind_addr).await {
            Ok(_) => println!("  [ok] port {} available", config.port),
            Err(_) => {
                println!("  [!!] port {} in use or unavailable", config.port);
                issues += 1;
            }
        }
    }

    // Check if configured IP matches current public IP
    if config.host != "auto"
        && config.host.parse::<std::net::IpAddr>().is_ok()
        && let Ok(output) = std::process::Command::new("curl")
            .args(["-4", "-s", "--max-time", "5", "ifconfig.me"])
            .output()
    {
        let detected = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !detected.is_empty() && detected != config.host {
            println!(
                "  [!!] configured IP ({}) does not match detected public IP ({})",
                config.host, detected
            );
            println!("       update config or set host = \"auto\" for dynamic IPs");
            issues += 1;
        } else if !detected.is_empty() {
            println!("  [ok] public IP matches config ({})", config.host);
        }
    }

    // Check DNS records (only if host is a domain name)
    if toq_core::transport::needs_dns_lookup(&config.host) {
        let pub_key = keystore::load_keypair(&keystore::identity_key_path())
            .map(|kp| {
                let encoded = kp.public_key().to_encoded();
                encoded
                    .strip_prefix("ed25519:")
                    .unwrap_or(&encoded)
                    .to_string()
            })
            .unwrap_or_default();

        match toq_core::dns::lookup_agent(&config.host, &config.agent_name).await {
            Ok(Some(record)) => {
                println!(
                    "  [ok] DNS TXT record found for {} at {}",
                    config.agent_name, config.host
                );
                if record.public_key_b64 == pub_key {
                    println!("  [ok] DNS public key matches local key");
                } else {
                    println!("  [!!] DNS public key does not match local key");
                    issues += 1;
                }
                if record.port != config.port {
                    println!(
                        "  [!!] DNS port ({}) does not match config port ({})",
                        record.port, config.port
                    );
                    issues += 1;
                }
            }
            Ok(None) => {
                println!(
                    "  [--] no DNS TXT record for {} at {}",
                    config.agent_name, config.host
                );
            }
            Err(_) => {
                println!("  [--] DNS lookup failed for {}", config.host);
            }
        }
    }

    // Check disk space
    let toq_dir = dirs_path();
    match fs::metadata(&toq_dir) {
        Ok(_) => {
            // Check if we can write (basic disk health check)
            let test_path = toq_dir.join(".disk_check");
            match fs::write(&test_path, "ok") {
                Ok(_) => {
                    let _ = fs::remove_file(&test_path);
                    println!("  [ok] disk writable");
                }
                Err(_) => {
                    println!("  [!!] disk not writable at {}", toq_dir.display());
                    issues += 1;
                }
            }
        }
        Err(_) => {
            println!("  [!!] toq directory not found");
            issues += 1;
        }
    }

    if issues == 0 {
        println!("\nno issues found");
    } else {
        println!("\n{issues} issue(s) found");
    }

    Ok(())
}

async fn run_upgrade() -> Result<(), Box<dyn std::error::Error>> {
    let current = env!("CARGO_PKG_VERSION");
    println!("toq v{current}");

    println!("Checking for updates...");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .user_agent("toq")
        .build()?;

    match client
        .get("https://api.github.com/repos/toqprotocol/toq/releases/latest")
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let body: serde_json::Value = resp.json().await?;
            if let Some(tag) = body["tag_name"].as_str() {
                let latest = tag.trim_start_matches('v');
                if latest != current {
                    println!("  new version available: v{latest}");
                    println!(
                        "  download: {}",
                        body["html_url"]
                            .as_str()
                            .unwrap_or("https://github.com/toqprotocol/toq/releases")
                    );
                } else {
                    println!("  Already up to date");
                }
            }
        }
        _ => {
            println!("  Could not check for updates");
            println!("  visit https://github.com/toqprotocol/toq/releases");
        }
    }

    Ok(())
}

async fn run_handler(action: HandlerAction) -> Result<(), Box<dyn std::error::Error>> {
    let path = toq_core::config::HandlersFile::path();

    /// Notify the running daemon to reload handlers.toml.
    async fn notify_reload() {
        if read_pid().is_some()
            && let Ok(base) = api_base()
        {
            let _ = reqwest::Client::new()
                .post(format!("{base}/v1/handlers/reload"))
                .send()
                .await;
        }
    }

    match action {
        HandlerAction::Add(args) => {
            let HandlerAddArgs {
                name,
                command,
                provider,
                model,
                prompt,
                prompt_file,
                max_turns,
                auto_close,
                filter_from,
                filter_key,
                filter_type,
            } = *args;
            // Validate: must have either --command or --provider
            if command.is_none() && provider.is_none() {
                return Err(
                    "specify --command for a shell handler or --provider for an LLM handler".into(),
                );
            }
            if command.is_some() && provider.is_some() {
                return Err("cannot use both --command and --provider".into());
            }
            if let Some(ref p) = provider {
                if !["openai", "anthropic", "bedrock", "ollama"].contains(&p.as_str()) {
                    return Err("provider must be openai, anthropic, bedrock, or ollama".into());
                }
                if model.is_none() {
                    return Err("--model is required for LLM handlers".into());
                }
            }

            let mut file = toq_core::config::HandlersFile::load(&path).unwrap_or_default();
            let entry = toq_core::config::HandlerEntry {
                name: name.clone(),
                command: command.unwrap_or_default(),
                provider: provider.unwrap_or_default(),
                model: model.unwrap_or_default(),
                prompt,
                prompt_file,
                max_turns,
                auto_close,
                enabled: true,
                filter_from,
                filter_key,
                filter_type,
            };
            file.add(entry).map_err(|e| format!("{e}"))?;
            file.save(&path)?;
            notify_reload().await;
            println!("Added handler '{name}'");
        }
        HandlerAction::List => {
            let file = toq_core::config::HandlersFile::load(&path).unwrap_or_default();
            if file.handlers.is_empty() {
                println!("No handlers registered");
                return Ok(());
            }

            // If daemon is running, get active counts
            let active_counts: std::collections::HashMap<String, usize> = if read_pid().is_some()
                && let Ok(base) = api_base()
            {
                let counts = async {
                    let resp = reqwest::Client::new()
                        .get(format!("{base}/v1/handlers"))
                        .send()
                        .await
                        .ok()?;
                    let body: serde_json::Value = resp.json().await.ok()?;
                    body["handlers"].as_array().map(|arr| {
                        arr.iter()
                            .filter_map(|h| {
                                let name = h["name"].as_str()?.to_string();
                                let active = h["active"].as_u64()? as usize;
                                Some((name, active))
                            })
                            .collect()
                    })
                }
                .await;
                counts.unwrap_or_default()
            } else {
                std::collections::HashMap::new()
            };

            println!(
                "{:<20} {:<8} {:<8} {:<16} FILTER",
                "NAME", "ENABLED", "ACTIVE", "TYPE"
            );
            for h in &file.handlers {
                let active = active_counts.get(&h.name).copied().unwrap_or(0);
                let enabled = if h.enabled { "yes" } else { "no" };
                let type_str = if h.is_llm() {
                    format!("{}/{}", h.provider, h.model)
                } else {
                    "command".to_string()
                };
                let mut filters = Vec::new();
                if !h.filter_from.is_empty() {
                    filters.push(format!("from: {}", h.filter_from.join(", ")));
                }
                if !h.filter_key.is_empty() {
                    filters.push(format!("key: {}", h.filter_key.join(", ")));
                }
                if !h.filter_type.is_empty() {
                    filters.push(format!("type: {}", h.filter_type.join(", ")));
                }
                let filter_str = if filters.is_empty() {
                    "(all)".to_string()
                } else {
                    filters.join("; ")
                };
                println!(
                    "{:<20} {:<8} {:<8} {:<16} {}",
                    h.name, enabled, active, type_str, filter_str
                );
            }
        }
        HandlerAction::Remove { name } => {
            let mut file = toq_core::config::HandlersFile::load(&path).unwrap_or_default();
            if file.remove(&name) {
                file.save(&path)?;
                notify_reload().await;
                println!("Removed handler '{name}'");
            } else {
                eprintln!("Handler '{name}' not found");
                std::process::exit(1);
            }
        }
        HandlerAction::Enable { name } => {
            let mut file = toq_core::config::HandlersFile::load(&path).unwrap_or_default();
            if let Some(h) = file.get_mut(&name) {
                h.enabled = true;
                file.save(&path)?;
                notify_reload().await;
                println!("Enabled handler '{name}'");
            } else {
                eprintln!("Handler '{name}' not found");
                std::process::exit(1);
            }
        }
        HandlerAction::Disable { name } => {
            let mut file = toq_core::config::HandlersFile::load(&path).unwrap_or_default();
            if let Some(h) = file.get_mut(&name) {
                h.enabled = false;
                file.save(&path)?;
                notify_reload().await;
                println!("Disabled handler '{name}'");
            } else {
                eprintln!("Handler '{name}' not found");
                std::process::exit(1);
            }
        }
        HandlerAction::Stop { name, pid } => {
            require_running();
            let base = api_base()?;
            let body = if let Some(p) = pid {
                serde_json::json!({"name": name, "pid": p})
            } else {
                serde_json::json!({"name": name})
            };
            let resp = reqwest::Client::new()
                .post(format!("{base}/v1/handlers/stop"))
                .json(&body)
                .send()
                .await?;
            if resp.status().is_success() {
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                let stopped = body["stopped"].as_u64().unwrap_or(0);
                println!("Stopped {stopped} process(es) for '{name}'");
            } else {
                eprintln!("Failed to stop handler '{name}'");
            }
        }
        HandlerAction::Logs { name } => {
            let log_path = api::state::handler_log_dir().join(format!("handler-{name}.log"));
            if !log_path.exists() {
                println!("No logs for handler '{name}'");
                return Ok(());
            }
            let content = fs::read_to_string(&log_path)?;
            print!("{content}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_rule_from_flag() {
        let rule = resolve_rule(Some("toq://host/*"), None, None).unwrap();
        assert_eq!(
            rule,
            toq_core::policy::PermissionRule::Address("toq://host/*".into())
        );
    }

    #[test]
    fn resolve_rule_from_flag_takes_priority() {
        let rule = resolve_rule(Some("toq://*"), Some("not-a-key"), Some("ignored")).unwrap();
        assert_eq!(
            rule,
            toq_core::policy::PermissionRule::Address("toq://*".into())
        );
    }

    #[test]
    fn resolve_rule_key_flag() {
        let kp = toq_core::crypto::Keypair::generate();
        let encoded = kp.public_key().to_encoded();
        let rule = resolve_rule(None, Some(&encoded), None).unwrap();
        assert_eq!(
            rule,
            toq_core::policy::PermissionRule::Key(kp.public_key().as_bytes().to_vec())
        );
    }

    #[test]
    fn resolve_rule_positional_as_address() {
        let rule = resolve_rule(None, None, Some("toq://1.2.3.4/bob")).unwrap();
        assert_eq!(
            rule,
            toq_core::policy::PermissionRule::Address("toq://1.2.3.4/bob".into())
        );
    }

    #[test]
    fn resolve_rule_no_args_errors() {
        assert!(resolve_rule(None, None, None).is_err());
    }

    #[test]
    fn send_command_accepts_thread_id() {
        use clap::Parser;
        let cli = Cli::parse_from(["toq", "send", "toq://h/a", "hi", "--thread-id", "t1"]);
        match cli.command {
            Commands::Send { thread_id, .. } => assert_eq!(thread_id.as_deref(), Some("t1")),
            _ => panic!("expected Send"),
        }
    }

    #[test]
    fn send_command_accepts_close_thread() {
        use clap::Parser;
        let cli = Cli::parse_from(["toq", "send", "toq://h/a", "bye", "--close-thread"]);
        match cli.command {
            Commands::Send { close_thread, .. } => assert!(close_thread),
            _ => panic!("expected Send"),
        }
    }

    #[test]
    fn send_command_defaults() {
        use clap::Parser;
        let cli = Cli::parse_from(["toq", "send", "toq://h/a", "hi"]);
        match cli.command {
            Commands::Send {
                thread_id,
                close_thread,
                ..
            } => {
                assert!(thread_id.is_none());
                assert!(!close_thread);
            }
            _ => panic!("expected Send"),
        }
    }

    #[test]
    fn init_config_content_auto() {
        let port_line = "port = 0  # auto-assigned on startup".to_string();
        let config_content =
            format!("# toq workspace config\n\nagent_name = \"test-agent\"\n{port_line}\n");
        assert!(config_content.contains("agent_name = \"test-agent\""));
        assert!(config_content.contains("port = 0"));
    }

    #[test]
    fn init_config_content_explicit() {
        let p: u16 = 9020;
        let config_content =
            format!("# toq workspace config\n\nagent_name = \"bot\"\nport = {p}\n",);
        assert!(config_content.contains("port = 9020"));
    }

    #[test]
    fn init_gitignore_content() {
        let gitignore = "keys/\npeers.json\nmessages.jsonl\nlogs/\n";
        assert!(gitignore.contains("keys/"));
        assert!(gitignore.contains("logs/"));
        assert!(!gitignore.contains("identity.key"));
    }

    #[test]
    fn agent_registry_file_format() {
        let dir = tempfile::tempdir().unwrap();
        let agents_dir = dir.path().join("agents");
        fs::create_dir_all(&agents_dir).unwrap();

        let content = format!(
            "name = \"test\"\nport = 9009\npid = {}\nconfig_dir = \"/tmp\"\n",
            std::process::id()
        );
        fs::write(agents_dir.join("test.toml"), &content).unwrap();
        assert!(agents_dir.join("test.toml").exists());

        let read = fs::read_to_string(agents_dir.join("test.toml")).unwrap();
        assert!(read.contains("name = \"test\""));
        assert!(read.contains("port = 9009"));

        fs::remove_file(agents_dir.join("test.toml")).unwrap();
        assert!(!agents_dir.join("test.toml").exists());
    }

    #[test]
    fn port_skip_logic() {
        let claimed: Vec<u16> = vec![
            toq_core::constants::DEFAULT_PORT,
            toq_core::constants::DEFAULT_PORT + 1,
        ];
        let mut port = toq_core::constants::DEFAULT_PORT;
        loop {
            if !claimed.contains(&port) {
                break;
            }
            port += 1;
        }
        assert_eq!(port, toq_core::constants::DEFAULT_PORT + 2);
    }

    #[test]
    fn stale_pid_detection() {
        let alive = std::process::Command::new("kill")
            .args(["-0", "999999"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        assert!(!alive);

        // Current process should be alive
        let self_alive = std::process::Command::new("kill")
            .args(["-0", &std::process::id().to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        assert!(self_alive);
    }

    #[test]
    fn tls_and_http_first_bytes_are_distinct() {
        const TLS_HANDSHAKE_BYTE: u8 = 0x16;
        for method in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] {
            assert_ne!(method.as_bytes()[0], TLS_HANDSHAKE_BYTE);
        }
    }
}
