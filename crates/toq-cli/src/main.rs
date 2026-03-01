use clap::{Parser, Subcommand};
use std::io::{self, Write};
use toq_core::card::AgentCard;
use toq_core::config::Config;
use toq_core::constants::PROTOCOL_VERSION;
use toq_core::crypto::Keypair;
use toq_core::keystore;
use toq_core::negotiation::Features;
use toq_core::server;
use toq_core::transport;
use toq_core::types::Address;

#[derive(Parser)]
#[command(name = "toq", version, about = "toq protocol CLI")]
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
    Block {
        /// Agent address or public key to block.
        agent: String,
    },
    /// Remove an agent from the blocklist.
    Unblock {
        /// Agent address or public key to unblock.
        agent: String,
    },
    /// Send a test message to an agent.
    Send {
        /// Target agent address.
        address: String,
        /// Message content.
        message: String,
    },
    /// Start a dummy agent that prints incoming messages.
    Listen,
    /// Export keys, config, and peer list as an encrypted backup.
    Export {
        /// Output file path.
        path: String,
    },
    /// Restore from an encrypted backup file.
    Import {
        /// Backup file path.
        path: String,
    },
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
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Setup => run_setup(),
        Commands::Up { foreground: _ } => run_up().await,
        Commands::Down { graceful } => {
            if graceful {
                stub("down --graceful")
            } else {
                stub("down")
            }
        }
        Commands::Status => stub("status"),
        Commands::Peers => stub("peers"),
        Commands::Block { ref agent } => stub(&format!("block {agent}")),
        Commands::Unblock { ref agent } => stub(&format!("unblock {agent}")),
        Commands::Send {
            ref address,
            ref message,
        } => stub(&format!("send {address} {message}")),
        Commands::Listen => stub("listen"),
        Commands::Export { ref path } => stub(&format!("export {path}")),
        Commands::Import { ref path } => stub(&format!("import {path}")),
        Commands::RotateKeys => stub("rotate-keys"),
        Commands::ClearLogs => stub("clear-logs"),
        Commands::Doctor => stub("doctor"),
        Commands::Upgrade => stub("upgrade"),
        Commands::Logs { follow } => {
            if follow {
                stub("logs --follow")
            } else {
                stub("logs")
            }
        }
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn stub(cmd: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("toq {cmd}: not yet implemented");
    Ok(())
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

fn run_setup() -> Result<(), Box<dyn std::error::Error>> {
    println!("toq setup\n");

    if keystore::is_setup_complete() {
        println!("Setup already complete. Re-running will overwrite existing keys and config.");
        let answer = prompt("Continue?", "no");
        if !answer.starts_with('y') && !answer.starts_with('Y') {
            println!("Aborted.");
            return Ok(());
        }
    }

    // Agent name
    let agent_name = prompt("Agent name", "agent");
    Address::new("localhost", &agent_name)?;

    // Connection mode
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

    // Generate identity keypair
    println!("\nGenerating Ed25519 identity keypair...");
    let keypair = Keypair::generate();
    keystore::save_keypair(&keypair, &keystore::identity_key_path())?;
    println!("  Saved to {}", keystore::identity_key_path().display());

    // Generate TLS certificate
    println!("Generating self-signed TLS certificate...");
    keystore::generate_and_save_tls_cert(&keystore::tls_cert_path(), &keystore::tls_key_path())?;
    println!("  Saved to {}", keystore::tls_cert_path().display());

    // Create config
    let config = Config::default().with_agent(agent_name.clone(), connection_mode.to_string());
    config.save(&Config::default_path())?;
    println!("Config saved to {}", Config::default_path().display());

    // Summary
    println!("\n--- Setup complete ---");
    println!("  Agent name:      {agent_name}");
    println!("  Public key:      {}", keypair.public_key());
    println!("  Connection mode: {connection_mode}");
    println!("  Address:         toq://localhost/{agent_name}");
    println!("\nRun `toq up` to start your endpoint.");

    Ok(())
}

async fn run_up() -> Result<(), Box<dyn std::error::Error>> {
    if !keystore::is_setup_complete() {
        eprintln!("Setup not complete. Run `toq setup` first.");
        std::process::exit(1);
    }

    let config = Config::load(&Config::default_path())?;
    let keypair = keystore::load_keypair(&keystore::identity_key_path())?;
    let (certs, key) =
        keystore::load_tls_cert(&keystore::tls_cert_path(), &keystore::tls_key_path())?;

    let address = Address::new("localhost", &config.agent_name)?;
    let tls_config = transport::server_config(certs, key)?;
    let tls_acceptor = transport::tls_acceptor(tls_config);

    let local_card = AgentCard {
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
    };
    let features = Features::default();

    let bind_addr = format!("0.0.0.0:{}", config.port);
    let listener = server::bind(&bind_addr).await?;
    println!("toq up on {address}");
    println!("  public key: {}", keypair.public_key());
    println!("  listening on {bind_addr}");
    println!("  connection mode: {}", config.connection_mode);

    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (tcp, peer_addr) = accept?;
                println!("connection from {peer_addr}");

                let tls_acceptor = tls_acceptor.clone();
                let keypair_clone = keypair.clone();
                let address_clone = address.clone();
                let card_clone = local_card.clone();
                let features_clone = features.clone();

                tokio::spawn(async move {
                    match server::accept_connection(
                        tcp,
                        &tls_acceptor,
                        &keypair_clone,
                        &address_clone,
                        &card_clone,
                        &features_clone,
                        None,
                    ).await {
                        Ok(conn) => {
                            println!(
                                "connected: {} ({})",
                                conn.peer_card.name, conn.peer_address
                            );
                        }
                        Err(e) => {
                            eprintln!("connection failed: {e}");
                        }
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => {
                println!("\ntoq down");
                break;
            }
        }
    }

    Ok(())
}
