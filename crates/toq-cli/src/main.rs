use clap::{Parser, Subcommand};
use std::fs;
use std::io::{self, BufRead};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::prelude::*;
use sha2::{Digest, Sha256};

use toq_core::adapter::AgentMessage;

mod api;
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
#[command(name = "toq", version, about = ABOUT)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
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
    },
    /// Show running state, connections, and pending approvals.
    Status,
    /// List known peers with status and last seen time.
    Peers,
    /// Block an agent by address or public key.
    Block { agent: String },
    /// Remove an agent from the blocklist.
    Unblock { agent: String },
    /// Send a test message to an agent.
    Send { address: String, message: String },
    /// Start a dummy agent that prints incoming messages.
    Listen,
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
    /// Approve a pending connection request (requires running daemon).
    Approve { id: String },
    /// Deny a pending connection request (requires running daemon).
    Deny { id: String },
    /// Run diagnostics: port, DNS, keys, agent responsiveness.
    Doctor,
    /// Update the toq binary.
    Upgrade,
    /// Show recent log entries.
    Logs {
        /// Stream log entries in real time.
        #[arg(long)]
        follow: bool,
    },
}

#[tokio::main]
async fn main() {
    // Show logo when no args or --help
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 1 || args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{}", centered_logo());
    }

    let cli = Cli::parse();

    let result = match cli.command {
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
        Commands::Down { graceful } => run_down(graceful),
        Commands::Status => run_status(),
        Commands::Peers => run_peers(),
        Commands::Block { ref agent } => run_block(agent).await,
        Commands::Unblock { ref agent } => run_unblock(agent).await,
        Commands::Send {
            ref address,
            ref message,
        } => run_send(address, message).await,
        Commands::Listen => run_listen().await,
        Commands::Export { ref path } => run_export(path),
        Commands::Import { ref path } => run_import(path),
        Commands::RotateKeys => run_rotate_keys(),
        Commands::ClearLogs => run_clear_logs(),
        Commands::Approvals => run_approvals().await,
        Commands::Approve { ref id } => run_approve(id).await,
        Commands::Deny { ref id } => run_deny(id).await,
        Commands::Doctor => run_doctor().await,
        Commands::Upgrade => run_upgrade(),
        Commands::Logs { follow } => run_logs(follow),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
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
        eprintln!("  Run `toq setup` to generate keys and create config");
        std::process::exit(1);
    }
}

fn require_running() {
    require_setup();
    if read_pid().is_none() {
        eprintln!("Toq is not running");
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
    fs::read_to_string(pid_path())
        .ok()
        .and_then(|s| s.trim().parse().ok())
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
        if !["open", "allowlist", "approval"].contains(&mode.as_str()) {
            return Err(format!(
                "Invalid connection mode '{mode}': must be open, allowlist, or approval"
            )
            .into());
        }
        mode
    } else {
        let mode_options = vec![
            "approval  - You approve each new agent (recommended)",
            "open      - Anyone can connect",
            "allowlist - Only pre-approved agents",
        ];
        let mode_choice =
            inquire::Select::new("Who can connect to your agent?", mode_options).prompt()?;
        if mode_choice.starts_with("open") {
            "open".to_string()
        } else if mode_choice.starts_with("allowlist") {
            "allowlist".to_string()
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
        let adapter_options = vec![
            "http   - HTTP POST to a localhost URL (recommended)",
            "stdin  - stdin/stdout JSON lines",
            "unix   - Unix domain socket",
        ];
        let adapter_choice =
            inquire::Select::new("How does your agent receive messages?", adapter_options)
                .prompt()?;
        if adapter_choice.starts_with("stdin") {
            "stdin".to_string()
        } else if adapter_choice.starts_with("unix") {
            "unix".to_string()
        } else {
            "http".to_string()
        }
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
            println!("    from toq_langchain import ToqToolkit, ToqListener");
            println!("    toolkit = ToqToolkit()");
            println!("    toolkit.connect()");
            println!("    tools = toolkit.get_tools()");
        }
        "crewai" => {
            println!("\n  CrewAI integration:");
            println!("    from toq_crewai import toq_tools, ToqListener");
            println!("    tools = toq_tools()");
        }
        "openclaw" => {
            println!("\n  OpenClaw integration:");
            println!("    clawhub install toq           Install the toq skill");
            println!("    openclaw plugins install \\");
            println!("      toq-openclaw-channel        Install the channel plugin");
        }
        _ => {
            println!("    toq send <addr> <msg>     Send a test message");
            println!("    toq listen                Print incoming messages");
            println!("    toq down                  Stop the endpoint");
        }
    }

    println!("\n  Network security:");
    println!("    Your endpoint listens on port {}", config.port);
    println!("    If exposed to the internet, use a firewall");
    println!("    and 'approval' or 'allowlist' connection mode");

    println!("\n  DNS discovery:");
    println!("    Add a TXT record to make your agent discoverable:");
    println!("    _toq._tcp.<domain>  \"v=toq1; key={pub_key_short}; agent={agent_name}\"");

    Ok(())
}

async fn run_up(foreground: bool) -> Result<(), Box<dyn std::error::Error>> {
    require_setup();

    // Daemon mode: re-exec in background
    if !foreground {
        let exe = std::env::current_exe()?;
        let log_dir = dirs_path().join(LOGS_DIR);
        let _ = fs::create_dir_all(&log_dir);
        let log_file = fs::File::create(log_path())?;
        let child = std::process::Command::new(exe)
            .arg("up")
            .arg("--foreground")
            .stdout(log_file.try_clone()?)
            .stderr(log_file)
            .spawn()?;
        println!("toq started as daemon (PID {})", child.id());
        return Ok(());
    }

    if let Some(pid) = read_pid() {
        eprintln!("toq appears to be running (PID {pid})");
        eprintln!("  run `toq down` to stop it, or `toq down --graceful` for a clean shutdown");
        std::process::exit(1);
    }

    let config = Config::load(&Config::default_path())?;
    let keypair = keystore::load_keypair(&keystore::identity_key_path())?;
    let (certs, key) =
        keystore::load_tls_cert(&keystore::tls_cert_path(), &keystore::tls_key_path())?;

    setup_logging();
    write_pid()?;

    let address = Address::new(&config.host, &config.agent_name)?;
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
    let peer_store =
        toq_core::keystore::PeerStore::load(&keystore::peers_path()).unwrap_or_default();
    engine.load_from_peer_store(&peer_store);
    let policy = std::sync::Arc::new(tokio::sync::Mutex::new(engine));

    // Wire RateLimiter
    let rate_limiter = std::sync::Arc::new(tokio::sync::Mutex::new(RateLimiter::new(
        DEFAULT_CONNECTIONS_PER_IP_PER_SEC,
    )));

    // Wire SessionStore
    let sessions = std::sync::Arc::new(tokio::sync::Mutex::new(SessionStore::new()));

    let bind_addr = format!(
        "{}:{}",
        toq_core::constants::DEFAULT_BIND_ADDRESS,
        config.port
    );
    let listener = server::bind(&bind_addr).await?;

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
    let state_api_port = config.api_port;
    let conn_counter = active_connections.clone();
    let in_counter = messages_in.clone();
    let out_counter = messages_out.clone();
    let update_state = move || {
        let state = serde_json::json!({
            "status": "running",
            "address": state_address,
            "port": state_port,
            "api_port": state_api_port,
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

    // Start local API server
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
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    *api_state.shutdown_tx.lock().await = Some(shutdown_tx);
    let api_address = format!("127.0.0.1:{}", config.api_port);
    tokio::spawn(async move {
        if let Err(e) = api::serve(api_state, &api_address).await {
            tracing::warn!("local API server error: {e}");
        }
    });

    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (tcp, peer_addr) = accept?;

                // Rate limiting
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
                                        let _ = msg_tx.send(api::types::IncomingMessage {
                                            id: agent_msg.id.clone(),
                                            msg_type: agent_msg.msg_type.clone(),
                                            from: agent_msg.from.clone(),
                                            body: agent_msg.body.clone(),
                                            thread_id: agent_msg.thread_id.clone(),
                                            reply_to: agent_msg.reply_to.clone(),
                                            content_type: agent_msg.content_type.clone(),
                                            timestamp: toq_core::now_utc(),
                                        });

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

                                        let _ = msg_tx.send(api::types::IncomingMessage {
                                            id: agent_msg.id.clone(),
                                            msg_type: agent_msg.msg_type.clone(),
                                            from: agent_msg.from.clone(),
                                            body: agent_msg.body.clone(),
                                            thread_id: agent_msg.thread_id.clone(),
                                            reply_to: agent_msg.reply_to.clone(),
                                            content_type: agent_msg.content_type.clone(),
                                            timestamp: toq_core::now_utc(),
                                        });

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
            _ = &mut shutdown_rx => {
                tracing::info!("toq down (API shutdown)");
                println!("\ntoq down (API)");
                break;
            }
        }
    }

    remove_pid();
    let _ = fs::remove_file(state_path());

    // Persist policy engine state to peer store
    {
        let policy_guard = policy.lock().await;
        let mut peer_store =
            toq_core::keystore::PeerStore::load(&keystore::peers_path()).unwrap_or_default();
        policy_guard.sync_to_peer_store(&mut peer_store);
        let _ = peer_store.save(&keystore::peers_path());
    }

    Ok(())
}

fn run_down(graceful: bool) -> Result<(), Box<dyn std::error::Error>> {
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
                    let _ = fs::remove_file(pid_path());
                    let _ = fs::remove_file(state_path());
                } else {
                    eprintln!("Failed to stop PID {pid}");
                }
            }
            #[cfg(not(unix))]
            {
                let _ = graceful;
                eprintln!("Toq down not supported on this platform");
            }
        }
        None => {
            println!("Toq is not running (no PID file found)");
        }
    }
    Ok(())
}

fn run_status() -> Result<(), Box<dyn std::error::Error>> {
    let sp = state_path();
    if !sp.exists() {
        println!("Toq is not running");
        return Ok(());
    }
    let data = fs::read_to_string(&sp)?;
    let file_state: serde_json::Value = serde_json::from_str(&data)?;
    let api_port = file_state["api_port"].as_u64().unwrap_or_else(|| {
        Config::load(&Config::default_path())
            .map(|c| c.api_port as u64)
            .unwrap_or(toq_core::constants::DEFAULT_API_PORT as u64)
    }) as u16;

    // Try live API first, fall back to state file
    let state = match std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], api_port)),
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
    println!("{:<50} {:<12} LAST SEEN", "PUBLIC KEY", "STATUS");
    for (key, record) in &store.peers {
        let short_key = if key.len() > 45 { &key[..45] } else { key };
        println!(
            "{:<50} {:<12} {}",
            short_key,
            format!("{:?}", record.status).to_lowercase(),
            record.last_seen
        );
    }
    Ok(())
}

async fn run_block(agent: &str) -> Result<(), Box<dyn std::error::Error>> {
    let store = toq_core::keystore::PeerStore::load(&keystore::peers_path())?;
    // Resolve to public key
    let public_key = match toq_core::crypto::PublicKey::from_encoded(agent) {
        Ok(key) => key,
        Err(_) => {
            let found = store.peers.iter().find(|(_, r)| r.address == agent);
            match found {
                Some((key_str, _)) => toq_core::crypto::PublicKey::from_encoded(key_str)?,
                None => return Err(format!("unknown agent: {agent}").into()),
            }
        }
    };
    let encoded = public_key.to_encoded();

    // If daemon is running, use API (updates both PolicyEngine and PeerStore)
    if read_pid().is_some()
        && let Ok(base) = api_base()
    {
        let url = format!("{}/v1/peers/{}/block", base, encoded);
        if let Ok(resp) = reqwest::Client::new().post(&url).send().await
            && resp.status().is_success()
        {
            println!("Blocked {agent}");
            return Ok(());
        }
    }

    // Fallback: modify PeerStore directly (daemon not running)
    let mut store = store;
    store.upsert(&public_key, "", toq_core::keystore::PeerStatus::Blocked);
    store.save(&keystore::peers_path())?;
    println!("Blocked {agent}");
    Ok(())
}

async fn run_unblock(agent: &str) -> Result<(), Box<dyn std::error::Error>> {
    let store = toq_core::keystore::PeerStore::load(&keystore::peers_path())?;
    let key = match toq_core::crypto::PublicKey::from_encoded(agent) {
        Ok(k) => k,
        Err(_) => {
            let found = store.peers.iter().find(|(_, r)| r.address == agent);
            match found {
                Some((key_str, _)) => toq_core::crypto::PublicKey::from_encoded(key_str)?,
                None => return Err(format!("unknown agent: {agent}").into()),
            }
        }
    };
    let encoded = key.to_encoded();

    // If daemon is running, use API (updates both PolicyEngine and PeerStore)
    if read_pid().is_some()
        && let Ok(base) = api_base()
    {
        let url = format!("{}/v1/peers/{}/block", base, encoded);
        if let Ok(resp) = reqwest::Client::new().delete(&url).send().await
            && resp.status().is_success()
        {
            println!("Unblocked {agent}");
            return Ok(());
        }
    }

    // Fallback: modify PeerStore directly (daemon not running)
    let mut store = store;
    store.peers.remove(&encoded);
    store.save(&keystore::peers_path())?;
    println!("Unblocked {agent}");
    Ok(())
}

fn run_clear_logs() -> Result<(), Box<dyn std::error::Error>> {
    let log_dir = dirs_path().join(LOGS_DIR);
    if log_dir.exists() {
        for entry in fs::read_dir(&log_dir)? {
            let entry = entry?;
            let _ = fs::remove_file(entry.path());
        }
    }
    println!("Logs cleared");
    Ok(())
}

/// Base URL for the local daemon API.
fn api_base() -> Result<String, Box<dyn std::error::Error>> {
    let config = Config::load(&Config::default_path())?;
    Ok(format!("http://127.0.0.1:{}", config.api_port))
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

async fn run_approve(id: &str) -> Result<(), Box<dyn std::error::Error>> {
    require_running();
    let url = format!("{}/v1/approvals/{}", api_base()?, id);
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .json(&serde_json::json!({"decision": "approve"}))
        .send()
        .await?;
    if resp.status().is_success() {
        println!("Approved {id}");
    } else {
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        let msg = body["error"]["message"].as_str().unwrap_or("unknown error");
        eprintln!("Failed to approve: {msg}");
    }
    Ok(())
}

async fn run_deny(id: &str) -> Result<(), Box<dyn std::error::Error>> {
    require_running();
    let url = format!("{}/v1/approvals/{}", api_base()?, id);
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

async fn run_send(target: &str, message: &str) -> Result<(), Box<dyn std::error::Error>> {
    require_setup();

    let config = Config::load(&Config::default_path())?;
    let keypair = keystore::load_keypair(&keystore::identity_key_path())?;
    let address = Address::new(&config.host, &config.agent_name)?;
    let target_addr: Address = target.parse()?;
    let local_card = load_card(&config, &keypair);
    let features = Features::default();

    let connect_addr = format!("{}:{}", target_addr.host, target_addr.port);
    println!("Connecting to {target_addr}...");

    let (info, mut stream) =
        server::connect_to_peer(&connect_addr, &keypair, &address, &local_card, &features).await?;

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
            thread_id: None,
            reply_to: None,
            priority: None,
            content_type: Some(toq_core::constants::DEFAULT_CONTENT_TYPE.into()),
            ttl: None,
            msg_type: None,
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

async fn run_listen() -> Result<(), Box<dyn std::error::Error>> {
    require_setup();

    let config = Config::load(&Config::default_path())?;
    let keypair = keystore::load_keypair(&keystore::identity_key_path())?;
    let (certs, key) =
        keystore::load_tls_cert(&keystore::tls_cert_path(), &keystore::tls_key_path())?;

    let address = Address::new(&config.host, &config.agent_name)?;
    let tls_config = transport::server_config(certs, key)?;
    let tls_acceptor = transport::tls_acceptor(tls_config);
    let local_card = load_card(&config, &keypair);
    let features = Features::default();

    let policy_mode = match config.connection_mode.as_str() {
        "open" => ConnectionMode::Open,
        "allowlist" => ConnectionMode::Allowlist,
        "dns-verified" => ConnectionMode::DnsVerified,
        _ => ConnectionMode::Approval,
    };
    let mut engine = PolicyEngine::new(policy_mode);
    let peer_store =
        toq_core::keystore::PeerStore::load(&keystore::peers_path()).unwrap_or_default();
    engine.load_from_peer_store(&peer_store);
    let policy = std::sync::Arc::new(tokio::sync::Mutex::new(engine));

    let bind_addr = format!(
        "{}:{}",
        toq_core::constants::DEFAULT_BIND_ADDRESS,
        config.port
    );
    let listener = server::bind(&bind_addr).await?;
    println!("toq listen on {address}");
    println!("  listening on {bind_addr}");
    println!("  Waiting for messages...\n");

    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (tcp, peer_addr) = accept?;
                let tls_acceptor = tls_acceptor.clone();
                let keypair_clone = keypair.clone();
                let address_clone = address.clone();
                let card_clone = local_card.clone();
                let features_clone = features.clone();
                let policy_clone = policy.clone();

                tokio::spawn(async move {
                    let accept_result = {
                        let mut policy_guard = policy_clone.lock().await;
                        server::accept_connection(
                            tcp, &tls_acceptor, &keypair_clone, &address_clone,
                            &card_clone, &features_clone, Some(&mut *policy_guard),
                        ).await
                    };

                    match accept_result {
                        Ok((info, mut stream)) => {
                            println!("Connected: {} ({}) from {peer_addr}", info.peer_card.name, info.peer_address);
                            let mut seq = 2u64;
                            while let Ok(envelope) = framing::recv_envelope(&mut stream, &info.peer_public_key, DEFAULT_MAX_MESSAGE_SIZE).await {
                                match envelope.msg_type {
                                    MessageType::MessageSend | MessageType::ThreadClose => {
                                        let agent_msg = AgentMessage::from_envelope(&envelope);
                                        println!("--- message from {} ---", agent_msg.from);
                                        if let Some(body) = &agent_msg.body {
                                            println!("{}", serde_json::to_string_pretty(body).unwrap_or_default());
                                        }
                                        if envelope.msg_type == MessageType::ThreadClose {
                                            println!("[thread closed]");
                                        }
                                        println!("---");
                                        let _ = messaging::send_ack(&mut stream, &keypair_clone, &address_clone, &info.peer_address, &envelope.id, seq).await;
                                        seq += 1;
                                    }
                                    MessageType::StreamChunk => {
                                        let agent_msg = AgentMessage::from_envelope(&envelope);
                                        if let Some(text) = agent_msg.body.as_ref()
                                            .and_then(|b| b.get("data"))
                                            .and_then(|d| d.get("text"))
                                            .and_then(|t| t.as_str())
                                        {
                                            print!("{text}");
                                        }
                                        let _ = messaging::send_ack(&mut stream, &keypair_clone, &address_clone, &info.peer_address, &envelope.id, seq).await;
                                        seq += 1;
                                    }
                                    MessageType::StreamEnd => {
                                        println!();
                                        println!("--- stream end ---");
                                        let _ = messaging::send_ack(&mut stream, &keypair_clone, &address_clone, &info.peer_address, &envelope.id, seq).await;
                                        seq += 1;
                                    }
                                    MessageType::SessionDisconnect => { println!("Peer disconnected"); break; }
                                    MessageType::Heartbeat => {
                                        let _ = toq_core::connection::send_heartbeat_ack(&mut stream, &keypair_clone, &address_clone, &info.peer_address, &envelope.id, seq).await;
                                        seq += 1;
                                    }
                                    other => { println!("received: {other:?}"); }
                                }
                            }
                        }
                        Err(e) => { eprintln!("connection from {peer_addr} failed: {e}"); }
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => {
                println!("\nStopped");
                break;
            }
        }
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

    let key_bytes = Sha256::digest(passphrase.as_bytes());
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)?;
    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("encryption failed: {e}"))?;

    let output = serde_json::json!({
        "encrypted": true,
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

        let key_bytes = Sha256::digest(passphrase.as_bytes());
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

    // Check port
    let config = Config::load(&Config::default_path())?;
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

fn run_upgrade() -> Result<(), Box<dyn std::error::Error>> {
    let current = env!("CARGO_PKG_VERSION");
    println!("toq v{current}");

    println!("Checking for updates...");
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .user_agent("toq")
        .build()?;

    match client
        .get("https://api.github.com/repos/toqprotocol/toq/releases/latest")
        .send()
    {
        Ok(resp) if resp.status().is_success() => {
            let body: serde_json::Value = resp.json()?;
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
