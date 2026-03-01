use clap::{Parser, Subcommand};
use toq_core::card::AgentCard;
use toq_core::constants::{DEFAULT_PORT, PROTOCOL_VERSION};
use toq_core::crypto::Keypair;
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
    /// Start the toq endpoint
    Up,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Up => {
            if let Err(e) = run_up().await {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    }
}

async fn run_up() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = Keypair::generate();
    let address = Address::new("localhost", "agent")?;

    let (certs, key) = transport::generate_self_signed_cert()?;
    let tls_config = transport::server_config(certs, key)?;
    let tls_acceptor = transport::tls_acceptor(tls_config);

    let local_card = AgentCard {
        name: "toq agent".into(),
        description: None,
        public_key: keypair.public_key().to_encoded(),
        protocol_version: PROTOCOL_VERSION.into(),
        capabilities: vec![],
        accept_files: false,
        max_file_size: None,
        max_message_size: None,
        connection_mode: Some("approval".into()),
    };
    let features = Features::default();

    let bind_addr = format!("0.0.0.0:{DEFAULT_PORT}");
    let listener = server::bind(&bind_addr).await?;
    println!("toq up on {}", address);
    println!("listening on {bind_addr}");

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
