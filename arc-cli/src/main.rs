//! arc — Secure, parallel, peer-to-peer file and clipboard transfer.
//!
//! Run `arc --help` for usage.

pub mod clipboard;
pub mod commands;
mod ui;

pub use ui::{generate_phrase, setup_progress_bar, validate_passphrase};

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use arc_core::storage::wipe_config;

#[derive(Parser)]
#[command(
    name = "arc",
    version = env!("CARGO_PKG_VERSION"),
    author,
    about = "Secure, parallel P2P file and clipboard transfer",
    long_about = None
)]
struct Cli {
    /// Enable verbose logging (set RUST_LOG=arc=debug for full debug output).
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Emit structured JSON logs (tracing output only).
    #[arg(long, global = true)]
    json: bool,

    /// Override the default relay URL.
    #[arg(long, global = true, env = "ARC_RELAY_URL")]
    relay: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Send a file or directory to a paired device.
    Send {
        /// Path to the file or directory to send.
        path: Option<String>,
        /// Target device name (from `arc peers list`).
        #[arg(long)]
        to: Option<String>,
        /// Enable multi-user sharing mode.
        #[arg(long)]
        share: bool,
        /// Send from standard input.
        #[arg(long)]
        stdin: bool,
        /// File name to use when sending from stdin.
        #[arg(long)]
        name: Option<String>,
        /// Send from the system clipboard.
        #[arg(long)]
        clipboard: bool,
        /// Use a specific transfer code (for scripting and tests).
        #[arg(long)]
        code: Option<String>,
    },

    /// Receive files from a paired device.
    Receive {
        /// Pairing or transfer 6-word phrase/code.
        phrase: String,
        /// Save received files to this directory.
        #[arg(long, default_value = ".")]
        dir: String,
        /// Write received file to standard output.
        #[arg(long)]
        stdout: bool,
    },

    /// Pair with a new device (generates QR code and pairing code).
    Pair {
        /// Device name to display during pairing.
        #[arg(long)]
        name: Option<String>,
        /// Initiate pairing non-interactively.
        #[arg(long)]
        initiator: bool,
        /// Use a specific pairing code (initiator only; for scripting and tests).
        #[arg(long)]
        code: Option<String>,
        /// Join pairing non-interactively with the given codephrase.
        #[arg(long)]
        joiner: Option<String>,
    },

    /// Manage paired devices.
    #[command(subcommand)]
    Peers(PeersCommands),

    /// Configure arc settings.
    #[command(subcommand)]
    Config(ConfigCommands),

    /// Discover active arc devices on the local network.
    Discover,

    /// Sync clipboard in real-time (daemon mode).
    Clipboard {
        /// Codephrase room to sync over.
        phrase: String,
    },

    /// Relay server diagnostics.
    Relay {
        #[command(subcommand)]
        action: RelayAction,
    },

    /// Ping a paired device to check reachability.
    Ping {
        /// Device name.
        device: String,
    },

    /// Verify a file's BLAKE3 hash.
    Verify {
        /// Path to the file.
        path: String,
        /// Expected BLAKE3 hash (hex).
        #[arg(long)]
        hash: String,
    },

    /// Generate shell completions.
    Completions {
        /// Shell type.
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },

    /// EMERGENCY: Wipe all pairing keys and generate a new device identity.
    Panic,

    /// Completely uninstall arc, removing configuration directories and the binary.
    Uninstall,
}

#[derive(Subcommand)]
pub enum PeersCommands {
    /// List all paired devices.
    List,
    /// Show details of a paired device.
    Show { name: String },
    /// Revoke access from a paired device.
    Revoke { name: String },
}

#[derive(Subcommand)]
pub enum ConfigCommands {
    /// Set a configuration value.
    Set { key: String, value: String },
    /// Get a configuration value.
    Get { key: String },
    /// Show all configuration.
    Show,
}

#[derive(Subcommand)]
pub enum RelayAction {
    /// Show relay status and latency.
    Status,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();

    let filter = if cli.verbose {
        EnvFilter::new("arc=debug,arc_core=debug")
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("arc=info"))
    };

    if cli.json {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .init();
    }

    let execution_fut = async {
        if let Some(command) = cli.command {
            match command {
                Commands::Send {
                    path,
                    to,
                    share,
                    stdin,
                    name,
                    clipboard,
                    code,
                } => {
                    commands::send::exec_send(
                        path, to, share, stdin, name, clipboard, code, cli.relay,
                    )
                    .await?;
                }
                Commands::Receive {
                    phrase,
                    dir,
                    stdout,
                } => {
                    commands::receive::exec_receive(phrase, dir, stdout, cli.relay).await?;
                }
                Commands::Pair {
                    name,
                    initiator,
                    code,
                    joiner,
                } => {
                    commands::pair::exec_pair(name, initiator, code, joiner, cli.relay).await?;
                }
                Commands::Peers(command) => commands::peers::exec_peers(command).await?,
                Commands::Config(command) => commands::config::exec_config(command).await?,
                Commands::Discover => commands::discover::exec_discover().await?,
                Commands::Clipboard { phrase } => {
                    commands::clipboard::exec_clipboard_sync(phrase, cli.relay).await?;
                }
                Commands::Relay {
                    action: RelayAction::Status,
                } => commands::relay::exec_relay(cli.relay).await?,
                Commands::Ping { device } => commands::ping::exec_ping(device).await?,
                Commands::Verify { path, hash } => {
                    commands::verify::exec_verify(path, hash).await?;
                }
                Commands::Completions { shell } => {
                    use clap::CommandFactory;
                    use clap_complete::generate;
                    let mut cmd = Cli::command();
                    let name = cmd.get_name().to_string();
                    generate(shell, &mut cmd, name, &mut std::io::stdout());
                }
                Commands::Panic => {
                    wipe_config()?;
                    println!(
                        "Wiped configurations and keys. Run again to generate a new identity."
                    );
                }
                Commands::Uninstall => {
                    commands::uninstall::exec_uninstall().await?;
                }
            }
        } else {
            run_interactive_menu().await?;
        }
        Ok::<(), anyhow::Error>(())
    };

    tokio::select! {
        res = execution_fut => {
            res?;
        }
        _ = tokio::signal::ctrl_c() => {
            println!("\nOperation cancelled by user (Ctrl+C). Exiting gracefully...");
        }
    }

    Ok(())
}

async fn run_interactive_menu() -> anyhow::Result<()> {
    use dialoguer::{Confirm, Input, Select, theme::ColorfulTheme};

    let theme = ColorfulTheme::default();

    loop {
        let (_, config) = arc_core::get_identity_with_merged_config()?;
        println!("\n=== ARC SECURE FILE TRANSFER ===");
        println!("Device Identity Name: {}", config.device_name);
        println!("=================================");

        let selections = &[
            "Send a file or directory",
            "Receive files",
            "Pair with a device",
            "List paired devices",
            "Show device configuration",
            "Discover local network devices",
            "Sync clipboard (Daemon mode)",
            "Panic (Wipe identity)",
            "Exit",
        ];

        let selection = Select::with_theme(&theme)
            .with_prompt("Select an action")
            .default(0)
            .items(&selections[..])
            .interact()?;

        match selection {
            0 => {
                let path: String = Input::with_theme(&theme)
                    .with_prompt("Path to the file or directory to send")
                    .interact_text()?;
                commands::send::exec_send(Some(path), None, false, false, None, false, None, None)
                    .await?;
            }
            1 => {
                let phrase: String = Input::with_theme(&theme)
                    .with_prompt("Enter the 6-word phrase/code")
                    .interact_text()?;
                let dir: String = Input::with_theme(&theme)
                    .with_prompt("Save directory")
                    .default(".".to_string())
                    .interact_text()?;
                commands::receive::exec_receive(phrase, dir, false, None).await?;
            }
            2 => commands::pair::exec_pair(None, false, None, None, None).await?,
            3 => commands::peers::exec_peers(PeersCommands::List).await?,
            4 => commands::config::exec_config(ConfigCommands::Show).await?,
            5 => commands::discover::exec_discover().await?,
            6 => {
                let phrase: String = Input::with_theme(&theme)
                    .with_prompt("Enter the 6-word phrase/code to sync over")
                    .interact_text()?;
                commands::clipboard::exec_clipboard_sync(phrase, None).await?;
            }
            7 => {
                let confirm = Confirm::with_theme(&theme)
                    .with_prompt("WIPE all configuration and identities?")
                    .default(false)
                    .interact()?;
                if confirm {
                    wipe_config()?;
                    println!("Identity wiped. Program will exit.");
                    break;
                }
            }
            _ => {
                println!("Goodbye!");
                break;
            }
        }
    }

    Ok(())
}
