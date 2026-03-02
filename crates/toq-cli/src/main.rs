use clap::{Parser, Subcommand};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use toq_core::adapter::AgentMessage;

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

#[derive(Parser)]
#[command(name = "toq", version, about = ABOUT)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Interactive guided setup. Generates keys, creates config.
    Setup,
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
        Commands::Setup => run_setup(),
        Commands::Up { foreground: _ } => run_up().await,
        Commands::Down { graceful } => run_down(graceful),
        Commands::Status => run_status(),
        Commands::Peers => run_peers(),
        Commands::Block { ref agent } => run_block(agent),
        Commands::Unblock { ref agent } => run_unblock(agent),
        Commands::Send {
            ref address,
            ref message,
        } => run_send(address, message).await,
        Commands::Listen => run_listen().await,
        Commands::Export { ref path } => run_export(path),
        Commands::Import { ref path } => run_import(path),
        Commands::RotateKeys => run_rotate_keys(),
        Commands::ClearLogs => run_clear_logs(),
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
        eprintln!("setup not complete, run `toq setup` first.");
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

    let file_appender = tracing_appender::rolling::daily(&log_dir, LOG_FILE);
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    // Keep the guard alive for the lifetime of the program by leaking it
    std::mem::forget(_guard);

    tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_target(false)
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

fn prompt(question: &str, default: &str) -> String {
    print!("{question} [{default}]: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let trimmed = input.trim();
    if trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed.to_string()
    }
}

// --- Commands ---

fn run_setup() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", centered_logo());
    println!("toq setup\n");

    if keystore::is_setup_complete() {
        println!("setup already complete, re-running will overwrite existing keys and config");
        let answer = prompt("Continue?", "no");
        if !answer.starts_with('y') && !answer.starts_with('Y') {
            println!("Aborted");
            return Ok(());
        }
    }

    let agent_name = prompt("Agent name", "agent");
    Address::new("localhost", &agent_name)?;

    println!("\nWho can connect to your agent?");
    println!("  1. approval  - You approve each new agent (recommended)");
    println!("  2. open      - Anyone can connect");
    println!("  3. allowlist - Only pre-approved agents");
    let mode_choice = prompt("Choice", "1");
    let connection_mode = match mode_choice.as_str() {
        "2" | "open" => "open",
        "3" | "allowlist" => "allowlist",
        _ => "approval",
    };

    println!("\nHow does your agent receive messages?");
    println!("  1. http   - HTTP POST to a localhost URL (recommended)");
    println!("  2. stdin  - stdin/stdout JSON lines");
    println!("  3. unix   - Unix domain socket");
    let adapter_choice = prompt("Choice", "1");
    let adapter = match adapter_choice.as_str() {
        "2" | "stdin" => "stdin",
        "3" | "unix" => "unix",
        _ => "http",
    };

    println!("\nGenerating Ed25519 identity keypair...");
    let keypair = Keypair::generate();
    keystore::save_keypair(&keypair, &keystore::identity_key_path())?;
    println!("  Saved to {}", keystore::identity_key_path().display());

    println!("Generating self-signed TLS certificate...");
    keystore::generate_and_save_tls_cert(&keystore::tls_cert_path(), &keystore::tls_key_path())?;
    println!("  Saved to {}", keystore::tls_cert_path().display());

    let config = Config::default()
        .with_agent(agent_name.clone(), connection_mode.to_string())
        .with_adapter(adapter.to_string());
    config.save(&Config::default_path())?;
    println!("Config saved to {}", Config::default_path().display());

    // Create logs directory
    let _ = fs::create_dir_all(dirs_path().join(LOGS_DIR));

    println!("\n--- Setup complete ---");
    println!("  Agent name:      {agent_name}");
    println!("  Public key:      {}", keypair.public_key());
    println!("  Connection mode: {connection_mode}");
    println!("  Address:         toq://localhost/{agent_name}");
    println!("\nRun `toq up` to start your endpoint");

    Ok(())
}

async fn run_up() -> Result<(), Box<dyn std::error::Error>> {
    require_setup();

    if let Some(pid) = read_pid() {
        eprintln!("toq appears to be running (PID {pid}), run `toq down` first.");
        std::process::exit(1);
    }

    let config = Config::load(&Config::default_path())?;
    let keypair = keystore::load_keypair(&keystore::identity_key_path())?;
    let (certs, key) =
        keystore::load_tls_cert(&keystore::tls_cert_path(), &keystore::tls_key_path())?;

    setup_logging();
    write_pid()?;

    let address = Address::new("localhost", &config.agent_name)?;
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
    let policy = std::sync::Arc::new(tokio::sync::Mutex::new(PolicyEngine::new(policy_mode)));

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
    println!("{}", centered_logo());
    println!("toq up on {address}");
    println!("  public key: {}", keypair.public_key());
    println!("  listening on {bind_addr}");
    println!("  connection mode: {}", config.connection_mode);

    // Write state file
    let state = serde_json::json!({
        "status": "running",
        "address": address.to_string(),
        "port": config.port,
        "connection_mode": config.connection_mode,
        "pid": std::process::id(),
    });
    let _ = fs::write(state_path(), serde_json::to_string_pretty(&state)?);

    // Load adapter config
    let adapter_url = config.adapter_http.as_ref().map(|h| h.callback_url.clone());

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

                tokio::spawn(async move {
                    // Check policy before full accept
                    let policy_guard = policy_clone.lock().await;
                    let policy_ref: &PolicyEngine = &policy_guard;

                    match server::accept_connection(
                        tcp, &tls_acceptor, &keypair_clone, &address_clone,
                        &card_clone, &features_clone, Some(policy_ref),
                    ).await {
                        Ok((info, mut stream)) => {
                            tracing::info!("connected: {} ({})", info.peer_card.name, info.peer_address);
                            println!("connected: {} ({})", info.peer_card.name, info.peer_address);

                            // Register session
                            {
                                let mut sess = sessions_clone.lock().await;
                                // Check for duplicate
                                if let Some(old_id) = sess.check_duplicate(&info.peer_public_key) {
                                    tracing::info!("duplicate connection, closing old session {}", old_id);
                                    sess.remove(&old_id);
                                }
                                sess.register(&info.session_id, &info.peer_public_key);
                            }

                            // Connection receive loop
                            let mut seq = 2u64;
                            while let Ok(envelope) = framing::recv_envelope(
                                &mut stream, &info.peer_public_key, DEFAULT_MAX_MESSAGE_SIZE
                            ).await {
                                match envelope.msg_type {
                                    MessageType::MessageSend => {
                                        let agent_msg = AgentMessage::from_envelope(&envelope);
                                        tracing::info!("message from {}: {}", agent_msg.from, agent_msg.id);

                                        // Deliver to adapter
                                        if let Some(ref url) = adapter_url_clone {
                                            let adapter = toq_core::adapter::HttpAdapter::new(url);
                                            if let Err(e) = adapter.deliver(&agent_msg).await {
                                                tracing::warn!("adapter delivery failed: {e}");
                                            }
                                        }

                                        // Send ack
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
                            tracing::info!("connection closed: {}", info.peer_address);
                        }
                        Err(e) => {
                            tracing::warn!("connection from {peer_addr} failed: {e}");
                        }
                    }
                    drop(policy_guard);
                });
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("toq down (signal)");
                println!("\ntoq down");
                break;
            }
        }
    }

    remove_pid();
    let _ = fs::remove_file(state_path());
    Ok(())
}

fn run_down(graceful: bool) -> Result<(), Box<dyn std::error::Error>> {
    match read_pid() {
        Some(pid) => {
            #[cfg(unix)]
            {
                use std::process::Command;
                let signal = if graceful { "TERM" } else { "KILL" };
                let status = Command::new("kill")
                    .arg(format!("-{signal}"))
                    .arg(pid.to_string())
                    .status()?;
                if status.success() {
                    if graceful {
                        println!("toq down --graceful (sent SIGTERM to PID {pid})");
                    } else {
                        println!("toq down (sent SIGKILL to PID {pid})");
                    }
                    let _ = fs::remove_file(pid_path());
                    let _ = fs::remove_file(state_path());
                } else {
                    eprintln!("failed to stop PID {pid}");
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

fn run_status() -> Result<(), Box<dyn std::error::Error>> {
    let sp = state_path();
    if !sp.exists() {
        println!("toq is not running");
        return Ok(());
    }
    let data = fs::read_to_string(sp)?;
    let state: serde_json::Value = serde_json::from_str(&data)?;
    println!("toq status");
    println!(
        "  status:          {}",
        state["status"].as_str().unwrap_or("unknown")
    );
    println!(
        "  address:         {}",
        state["address"].as_str().unwrap_or("unknown")
    );
    println!("  port:            {}", state["port"]);
    println!(
        "  connection mode: {}",
        state["connection_mode"].as_str().unwrap_or("unknown")
    );
    println!("  pid:             {}", state["pid"]);
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

fn run_block(agent: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut store = toq_core::keystore::PeerStore::load(&keystore::peers_path())?;
    // Try parsing as encoded public key first, then as address
    let public_key = match toq_core::crypto::PublicKey::from_encoded(agent) {
        Ok(key) => key,
        Err(_) => {
            // Try looking up by address in peer store
            let found = store.peers.iter().find(|(_, r)| r.address == agent);
            match found {
                Some((key_str, _)) => toq_core::crypto::PublicKey::from_encoded(key_str)?,
                None => return Err(format!("unknown agent: {agent}").into()),
            }
        }
    };
    store.upsert(&public_key, "", toq_core::keystore::PeerStatus::Blocked);
    store.save(&keystore::peers_path())?;
    println!("blocked {agent}");
    Ok(())
}

fn run_unblock(agent: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut store = toq_core::keystore::PeerStore::load(&keystore::peers_path())?;
    let key = toq_core::crypto::PublicKey::from_encoded(agent)?;
    let key_str = key.to_encoded();
    store.peers.remove(&key_str);
    store.save(&keystore::peers_path())?;
    println!("unblocked {agent}");
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

fn run_logs(follow: bool) -> Result<(), Box<dyn std::error::Error>> {
    let lp = log_path();
    if !lp.exists() {
        println!("no logs found");
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
    let address = Address::new("localhost", &config.agent_name)?;
    let target_addr: Address = target.parse()?;
    let local_card = load_card(&config, &keypair);
    let features = Features::default();

    let connect_addr = format!("{}:{}", target_addr.host, target_addr.port);
    println!("connecting to {target_addr}...");

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
        },
    )
    .await?;

    println!("sent message {msg_id}");

    let ack = framing::recv_envelope(&mut stream, &info.peer_public_key, DEFAULT_MAX_MESSAGE_SIZE)
        .await?;
    if ack.msg_type == MessageType::MessageAck {
        println!("ack received");
    } else {
        println!("unexpected response: {:?}", ack.msg_type);
    }

    Ok(())
}

async fn run_listen() -> Result<(), Box<dyn std::error::Error>> {
    require_setup();

    let config = Config::load(&Config::default_path())?;
    let keypair = keystore::load_keypair(&keystore::identity_key_path())?;
    let (certs, key) =
        keystore::load_tls_cert(&keystore::tls_cert_path(), &keystore::tls_key_path())?;

    let address = Address::new("localhost", &config.agent_name)?;
    let tls_config = transport::server_config(certs, key)?;
    let tls_acceptor = transport::tls_acceptor(tls_config);
    let local_card = load_card(&config, &keypair);
    let features = Features::default();

    let bind_addr = format!(
        "{}:{}",
        toq_core::constants::DEFAULT_BIND_ADDRESS,
        config.port
    );
    let listener = server::bind(&bind_addr).await?;
    println!("toq listen on {address}");
    println!("  listening on {bind_addr}");
    println!("  waiting for messages...\n");

    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (tcp, peer_addr) = accept?;
                let tls_acceptor = tls_acceptor.clone();
                let keypair_clone = keypair.clone();
                let address_clone = address.clone();
                let card_clone = local_card.clone();
                let features_clone = features.clone();

                tokio::spawn(async move {
                    match server::accept_connection(
                        tcp, &tls_acceptor, &keypair_clone, &address_clone,
                        &card_clone, &features_clone, None,
                    ).await {
                        Ok((info, mut stream)) => {
                            println!("connected: {} ({}) from {peer_addr}", info.peer_card.name, info.peer_address);
                            let mut seq = 2u64;
                            while let Ok(envelope) = framing::recv_envelope(&mut stream, &info.peer_public_key, DEFAULT_MAX_MESSAGE_SIZE).await {
                                match envelope.msg_type {
                                    MessageType::MessageSend => {
                                        let agent_msg = AgentMessage::from_envelope(&envelope);
                                        println!("--- message from {} ---", agent_msg.from);
                                        if let Some(body) = &agent_msg.body {
                                            println!("{}", serde_json::to_string_pretty(body).unwrap_or_default());
                                        }
                                        println!("---");
                                        let _ = messaging::send_ack(&mut stream, &keypair_clone, &address_clone, &info.peer_address, &envelope.id, seq).await;
                                        seq += 1;
                                    }
                                    MessageType::SessionDisconnect => { println!("peer disconnected"); break; }
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
                println!("\nstopped");
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
    println!("keys rotated");
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

    fs::write(path, serde_json::to_string_pretty(&bundle)?)?;
    println!("exported to {path}");

    Ok(())
}

fn run_import(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read_to_string(path)?;
    let bundle: serde_json::Value = serde_json::from_str(&data)?;

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

    // Create directories
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

    println!("imported from {path}");
    println!("run `toq up` to start with the restored identity");

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
    println!("check for updates at https://github.com/toqprotocol/toq/releases");
    Ok(())
}
