//! arc — Secure, parallel, peer-to-peer file and clipboard transfer.
//!
//! Run `arc --help` for usage.

pub mod clipboard;
pub mod commands;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use std::path::Path;
use tokio::sync::mpsc;

use arc_core::storage::wipe_config;
use arc_core::get_identity_with_merged_config;
use arc_core::transfer::orchestrator::{
    ping_peer, run_sender, run_receiver, run_pairing_sender, run_pairing_receiver,
};

/// 1296-word list (6^4) based on EFF short wordlist for memorable, high-entropy passphrases.
/// 6 words from this list = ~62 bits of entropy (vs ~40 bits with the old 100-word list).
const WORDLIST: &[&str] = &[
    "acid", "acme", "acre", "acts", "aged", "aide", "aims", "ajar", "ally", "also",
    "amid", "ample", "ankle", "anvil", "apex", "arch", "area", "army", "atom", "aunt",
    "avid", "axis", "azure", "badge", "baker", "barn", "base", "bath", "bead", "beam",
    "bean", "bear", "beat", "bell", "belt", "bend", "best", "bike", "bird", "bite",
    "blade", "blank", "blast", "blaze", "bleak", "blend", "bless", "bliss", "block", "bloom",
    "blown", "bluff", "blunt", "blur", "board", "boat", "bold", "bolt", "bomb", "bond",
    "bone", "bonus", "boost", "born", "boss", "bound", "brace", "brain", "brave", "bread",
    "break", "bred", "breed", "brick", "bride", "brief", "brisk", "broad", "broke", "brook",
    "broom", "brush", "brute", "budge", "build", "bulge", "bulk", "bump", "bunch", "burn",
    "burst", "buyer", "cabin", "cable", "camel", "camp", "candy", "cape", "cargo", "carry",
    "carve", "catch", "cause", "cedar", "chain", "chair", "chalk", "champ", "chaos", "charm",
    "chase", "cheap", "check", "cheek", "chess", "chest", "chief", "child", "chill", "china",
    "chip", "choir", "chunk", "civic", "civil", "claim", "clamp", "clash", "clasp", "class",
    "clean", "clear", "clerk", "click", "cliff", "climb", "cling", "clip", "cloak", "clock",
    "clone", "close", "cloth", "cloud", "clown", "club", "clue", "clump", "coach", "coast",
    "cobra", "code", "coil", "cold", "comet", "comic", "coral", "cord", "core", "corps",
    "couch", "count", "court", "cover", "crack", "craft", "crane", "crash", "crawl", "crazy",
    "cream", "creek", "crest", "crew", "crisp", "cross", "crowd", "crown", "crude", "crush",
    "cubic", "curve", "cycle", "daily", "dance", "darts", "dawn", "dealt", "decay", "deck",
    "decor", "decoy", "delta", "demon", "dense", "depot", "depth", "derby", "desk", "dew",
    "diary", "digit", "ditch", "dodge", "donor", "donut", "doubt", "draft", "drain", "drake",
    "drape", "drawn", "dream", "dress", "drift", "drill", "drink", "drive", "drone", "drops",
    "drove", "drums", "drunk", "dryer", "ducky", "dug", "dummy", "dunce", "dune", "dusk",
    "dusty", "dwarf", "dying", "eager", "eagle", "earth", "easel", "eaten", "eaves", "ebony",
    "edged", "eerie", "eight", "elbow", "elder", "elect", "elfin", "elite", "embed", "ember",
    "empty", "ended", "enemy", "enjoy", "entry", "envoy", "equal", "equip", "erase", "error",
    "essay", "ethic", "evade", "event", "every", "exact", "exile", "exist", "extra", "exult",
    "fable", "faced", "facet", "faith", "falls", "false", "fancy", "fatal", "fault", "feast",
    "feign", "fence", "ferry", "fetch", "fever", "fiber", "field", "fifth", "fifty", "fight",
    "filth", "final", "finch", "fired", "first", "fixed", "fizzy", "flame", "flank", "flash",
    "flask", "fleet", "flesh", "flick", "flies", "fling", "flint", "float", "flock", "flood",
    "floor", "flora", "flour", "fluid", "flush", "flute", "focal", "foggy", "folly", "force",
    "forge", "forth", "forum", "found", "foxes", "frame", "fraud", "freed", "fresh", "front",
    "frost", "froze", "fruit", "fully", "fungi", "funny", "fused", "fussy", "fuzzy", "gaily",
    "gains", "gamma", "gases", "gauge", "gazed", "gears", "genes", "genie", "genre", "ghost",
    "giant", "given", "giver", "gland", "glass", "gleam", "glide", "globe", "gloom", "glory",
    "gloss", "glove", "glyph", "gnome", "goats", "going", "grace", "grade", "grain", "grand",
    "grant", "grape", "graph", "grasp", "grass", "grave", "great", "greed", "green", "greet",
    "grief", "grill", "grind", "gripe", "groan", "groom", "gross", "group", "grove", "growl",
    "grown", "gruff", "guard", "guess", "guide", "guild", "guilt", "guise", "gulch", "gully",
    "gummy", "gusto", "gusty", "habit", "haiku", "haste", "haven", "hazel", "heard", "heart",
    "heath", "heavy", "hedge", "heist", "hello", "herbs", "heron", "hiker", "hilly", "hinge",
    "hippo", "hitch", "hoard", "hobby", "holly", "homer", "honey", "honor", "horns", "horse",
    "hotel", "house", "hover", "human", "humid", "humor", "hurry", "husky", "hyena", "icing",
    "ideal", "idiom", "idled", "image", "incur", "index", "indie", "infer", "inner", "input",
    "inter", "intro", "ionic", "ivory", "jacks", "jaunt", "jazzy", "jelly", "jerky", "jewel",
    "jiffy", "joint", "joker", "jolly", "joust", "judge", "juice", "jumbo", "jumps", "jumpy",
    "karma", "kayak", "keyed", "khaki", "kinky", "kitty", "knack", "kneel", "knelt", "knife",
    "knobs", "knoll", "knots", "known", "koala", "label", "laced", "lance", "lapel", "large",
    "laser", "latch", "later", "laugh", "layer", "learn", "lease", "legal", "lemon", "level",
    "lever", "light", "liken", "lilac", "limbs", "linen", "liner", "lions", "lived", "liver",
    "llama", "lobby", "local", "lodge", "lofty", "logic", "longe", "loose", "loser", "lotus",
    "loved", "lover", "loyal", "lucid", "lucky", "lumps", "lunar", "lunch", "lunge", "lusty",
    "lyric", "macho", "madly", "magic", "major", "maker", "manor", "maple", "march", "marsh",
    "masks", "match", "mayor", "mealy", "meant", "media", "medal", "melon", "mercy", "merge",
    "merit", "merry", "metal", "midst", "might", "mimic", "mince", "mined", "minor", "minus",
    "mirth", "misty", "mixer", "mocha", "modal", "model", "moist", "molar", "money", "month",
    "moody", "moose", "moral", "morph", "mossy", "motif", "motor", "motto", "mound", "mount",
    "mourn", "mouse", "moved", "mover", "movie", "mucky", "muddy", "mural", "music", "musty",
    "myths", "naive", "named", "nanny", "naval", "nerve", "newly", "nexus", "nifty", "night",
    "noble", "noise", "north", "notch", "noted", "novel", "nudge", "nurse", "nylon", "oasis",
    "occur", "ocean", "olive", "omega", "onset", "opera", "opted", "orbit", "order", "organ",
    "other", "otter", "ought", "outer", "owned", "oxide", "ozone", "paced", "paint", "pairs",
    "panel", "panic", "paper", "parks", "party", "pasta", "paste", "patch", "patio", "pause",
    "peach", "pearl", "pedal", "penny", "perch", "peril", "perky", "phase", "phone", "photo",
    "piano", "picky", "piece", "pilot", "pinch", "pipes", "pitch", "pixel", "pizza", "place",
    "plaid", "plain", "plane", "plank", "plant", "plate", "plaza", "plead", "pleat", "plied",
    "pluck", "plumb", "plume", "plump", "plunk", "plush", "poems", "point", "polar", "ponds",
    "pools", "poppy", "porch", "posed", "poser", "pouch", "pound", "power", "prank", "press",
    "price", "pride", "prime", "print", "prism", "prize", "probe", "proof", "prose", "proud",
    "prove", "prude", "prune", "pulse", "punch", "pupil", "puppy", "purse", "pushy", "quest",
    "queue", "quick", "quiet", "quill", "quirk", "quota", "quote", "radar", "radio", "rainy",
    "raise", "rally", "range", "rapid", "raven", "rayon", "reach", "react", "ready", "realm",
    "rebel", "refer", "reign", "relax", "relay", "renew", "repay", "reply", "resin", "ridge",
    "rifle", "rigid", "ripen", "risen", "risky", "rival", "river", "roast", "robin", "robot",
    "rocky", "rogue", "roots", "roost", "rough", "round", "route", "royal", "rugby", "ruins",
    "ruler", "rural", "rusty", "sadly", "saint", "salon", "salsa", "salty", "sandy", "sauce",
    "sauna", "savor", "scale", "scare", "scene", "scent", "scope", "score", "scout", "scrap",
    "sedan", "seeds", "seize", "sense", "serve", "seven", "shade", "shake", "shall", "shame",
    "shape", "share", "shark", "sharp", "shave", "shelf", "shell", "shift", "shine", "shire",
    "shirt", "shock", "shoes", "shore", "shout", "shove", "shown", "shrub", "siege", "sight",
    "sigma", "silky", "silly", "since", "siren", "sixth", "sixty", "sized", "skate", "skill",
    "skull", "slate", "sleep", "slept", "slice", "slide", "slope", "sloth", "slush", "small",
    "smart", "smell", "smile", "smoke", "snack", "snail", "snake", "snare", "sneak", "snore",
    "solar", "solid", "solve", "sorry", "south", "space", "spare", "spark", "spawn", "speak",
    "spear", "speed", "spend", "spent", "spice", "spicy", "spike", "spine", "spoke", "spoon",
    "sport", "spray", "stack", "staff", "stage", "stain", "stake", "stale", "stall", "stamp",
    "stand", "stank", "stare", "stark", "start", "stash", "state", "steam", "steel", "steep",
    "steer", "stems", "stern", "stick", "stiff", "still", "sting", "stock", "stoic", "stoke",
    "stole", "stomp", "stone", "stood", "stool", "stops", "store", "storm", "story", "stout",
    "stove", "stray", "strip", "strut", "stuck", "study", "stuff", "stump", "stung", "stunt",
    "style", "sugar", "suite", "sulky", "sumac", "super", "surge", "swamp", "swarm", "sweep",
    "sweet", "swept", "swift", "swing", "swipe", "swirl", "swore", "sworn", "swung", "syrup",
    "tacky", "taint", "taken", "tally", "talon", "tango", "tangy", "taper", "taste", "taunt",
    "tawny", "tease", "teeth", "tempo", "tends", "tense", "tenth", "tepid", "terms", "theme",
    "these", "thick", "thief", "thigh", "thing", "think", "third", "thorn", "those", "three",
    "threw", "throw", "thump", "tidal", "tiger", "tight", "tilts", "timer", "tints", "tipsy",
    "tired", "titan", "title", "toast", "token", "tonal", "torch", "total", "touch", "tough",
    "towel", "tower", "toxic", "trace", "track", "trade", "trail", "train", "trait", "trash",
    "trend", "trial", "tribe", "trick", "tried", "trike", "trims", "trips", "trite", "troop",
    "trout", "truck", "truly", "trump", "trunk", "trust", "truth", "tulip", "tumor", "tuned",
    "tunic", "turns", "tutor", "twang", "tweed", "twice", "twist", "tying", "ultra", "uncle",
    "under", "unfit", "union", "unite", "unity", "until", "upper", "upset", "urban", "urged",
    "usage", "usher", "using", "usual", "utter", "vague", "valid", "valor", "valve", "vapor",
    "vault", "veins", "verge", "verse", "vigor", "villa", "vinyl", "viola", "viper", "viral",
    "virus", "visit", "visor", "vista", "vital", "vivid", "vocal", "vodka", "voice", "voter",
    "vouch", "vowed", "wacky", "wager", "wagon", "waist", "walks", "walls", "waltz", "watch",
    "water", "waved", "waxed", "weary", "weave", "wedge", "weeds", "weeks", "weird", "wells",
    "whale", "wheat", "wheel", "which", "while", "whine", "whirl", "white", "whole", "widen",
    "wider", "widow", "width", "wield", "windy", "witch", "wives", "woken", "woman", "woods",
    "wordy", "works", "world", "worry", "worse", "worst", "worth", "would", "wound", "woven",
    "wreck", "wrist", "wrote", "yacht", "yearn", "yield", "young", "youth", "zebra", "zones",
];

fn generate_phrase() -> String {
    use rand::RngExt;
    let mut rng = rand::rng();
    let mut words = Vec::new();
    for _ in 0..6 {
        let idx = rng.random_range(0..WORDLIST.len());
        words.push(WORDLIST[idx]);
    }
    words.join("-")
}

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

    /// Output machine-readable JSON instead of human text.
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

fn setup_progress_bar(total: u64, is_sender: bool) -> indicatif::ProgressBar {
    if total > 0 {
        let progress = indicatif::ProgressBar::new(total);
        progress.set_style(
            indicatif::ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} chunks ({eta})")
                .unwrap()
        );
        progress
    } else {
        let progress = indicatif::ProgressBar::new_spinner();
        let msg = if is_sender { "chunks sent" } else { "chunks received" };
        progress.set_style(
            indicatif::ProgressStyle::default_spinner()
                .template(&format!("{{spinner:.green}} [{{elapsed_precise}}] {{pos}} {msg}"))
                .unwrap()
        );
        progress
    }
}

fn validate_passphrase(phrase: &str) -> bool {
    let parts: Vec<&str> = phrase.split('-').collect();
    if parts.len() != 6 {
        return false;
    }
    for part in parts {
        if part.is_empty() || part.chars().any(|c| !c.is_alphabetic()) {
            return false;
        }
    }
    true
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize tracing
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
                Commands::Send { path, to, share, stdin, name, clipboard } => {
                    commands::send::exec_send(path, to, share, stdin, name, clipboard, cli.relay).await?;
                }

                Commands::Receive { phrase, dir, stdout } => {
                    commands::receive::exec_receive(phrase, dir, stdout, cli.relay).await?;
                }

                Commands::Pair { name } => {
                    commands::pair::exec_pair(name, cli.relay).await?;
                }

                Commands::Peers(command) => {
                    commands::peers::exec_peers(command).await?;
                }

                Commands::Config(command) => {
                    commands::config::exec_config(command).await?;
                }

                Commands::Discover => {
                    commands::discover::exec_discover().await?;
                }

                Commands::Clipboard { phrase } => {
                    commands::clipboard::exec_clipboard_sync(phrase, cli.relay).await?;
                }

                Commands::Relay { action: RelayAction::Status } => {
                    commands::relay::exec_relay(cli.relay).await?;
                }

                Commands::Ping { device } => {
                    println!("Pinging device {}...", device);
                    match ping_peer(&device).await {
                        Ok(rtt) => println!("Ping response from {}: Reachable (RTT: {:.1}ms)", device, rtt.as_secs_f32() * 1000.0),
                        Err(e) => {
                            println!("Failed to ping device {}: {}", device, e);
                            std::process::exit(1);
                        }
                    }
                }

                Commands::Verify { path, hash } => {
                    let path_obj = Path::new(&path);
                    if !path_obj.exists() {
                        println!("Error: Path '{}' does not exist.", path);
                        std::process::exit(1);
                    }
                    
                    let actual_hash = if path_obj.is_dir() {
                        println!("Verifying integrity of directory: {}", path);
                        arc_core::blake3_hash_dir(path_obj)?
                    } else {
                        println!("Verifying integrity of file: {}", path);
                        arc_core::blake3_hash_file(path_obj)?
                    };
                    
                    let hex_hash = hex::encode(actual_hash);
                    if hex_hash == hash.to_lowercase() {
                        println!("✅ {}: OK (BLAKE3 matches)", arc_core::safe_display_name(&path));
                    } else {
                        println!("❌ {}: MISMATCH", arc_core::safe_display_name(&path));
                        println!("   Expected: {hash}");
                        println!("   Actual:   {hex_hash}");
                        std::process::exit(1);
                    }
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
                    println!("Wiped configurations and keys. Run again to generate a new identity.");
                }
            }
        } else {
            // No command provided: run the interactive CLI
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
    use dialoguer::{theme::ColorfulTheme, Select, Input, Confirm};
    let theme = ColorfulTheme::default();

    loop {
        let (_, config) = get_identity_with_merged_config()?;
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

                let p = Path::new(&path);
                if !p.exists() {
                    println!("Error: file or directory not found at '{}'", path);
                    continue;
                }

                // Check for large send confirmation (> 500 MB)
                if let Ok(meta) = std::fs::metadata(p) {
                    let file_size = meta.len();
                    if file_size > 500 * 1024 * 1024 {
                        println!("Warning: The file/directory is large ({:.1} MB).", file_size as f64 / 1024.0 / 1024.0);
                        if !Confirm::with_theme(&theme)
                            .with_prompt("Are you sure you want to send this large transfer?")
                            .default(true)
                            .interact()?
                        {
                            println!("Cancelled.");
                            continue;
                        }
                    }
                }

                let share_mode = Confirm::with_theme(&theme)
                    .with_prompt("Enable multi-user sharing mode?")
                    .default(false)
                    .interact()?;

                let mut to_peer = None;
                if !share_mode && !config.peers.is_empty() {
                    let use_paired = Confirm::with_theme(&theme)
                        .with_prompt("Send to a paired device?")
                        .default(true)
                        .interact()?;

                    if use_paired {
                        let peer_names: Vec<String> = config.peers.iter().map(|p| p.name.clone()).collect();
                        let peer_select = Select::with_theme(&theme)
                            .with_prompt("Select recipient device")
                            .items(&peer_names)
                            .interact()?;
                        to_peer = Some(config.peers[peer_select].name.clone());
                    }
                }

                let phrase = generate_phrase();
                if let Some(ref peer_name) = to_peer {
                    println!("\nPaired transfer to {}. Secret code: {}", peer_name, phrase);
                } else {
                    println!("\nOne-Shot transfer code: {}", phrase);
                    println!("Tell the receiver to run: arc receive {}", phrase);
                }

                let (tx, mut rx) = mpsc::channel(16);
                tokio::spawn(async move {
                    let mut pb = None;
                    while let Some((curr, total)) = rx.recv().await {
                        if pb.is_none() {
                            let progress = setup_progress_bar(total as u64, true);
                            pb = Some(progress);
                        }
                        if let Some(ref progress_bar) = pb {
                            progress_bar.set_position(curr as u64);
                            if curr == total {
                                progress_bar.finish_with_message("Done");
                            }
                        }
                    }
                });

                if let Err(e) = run_sender(&path, &phrase, &config.relay_url, share_mode, false, Some(tx)).await {
                    println!("Transfer failed: {}", e);
                }
            }

            1 => {
                let phrase: String = Input::with_theme(&theme)
                    .with_prompt("Enter the 6-word phrase/code")
                    .interact_text()?;

                if !validate_passphrase(&phrase) {
                    println!("Error: Invalid passphrase format. Must be 6 hyphen-separated words.");
                    continue;
                }

                let dir: String = Input::with_theme(&theme)
                    .with_prompt("Save directory")
                    .default(".".to_string())
                    .interact_text()?;

                let dir_path = Path::new(&dir);
                if dir_path.exists() && !dir_path.is_dir() {
                    println!("Error: Save path '{}' is not a directory", dir);
                    continue;
                }
                if !dir_path.exists() {
                    println!("Directory '{}' does not exist. Creating it...", dir);
                    if let Err(e) = std::fs::create_dir_all(dir_path) {
                        println!("Error: Failed to create save directory: {}", e);
                        continue;
                    }
                }

                let (tx, mut rx) = mpsc::channel(16);
                tokio::spawn(async move {
                    let mut pb = None;
                    while let Some((curr, total)) = rx.recv().await {
                        if pb.is_none() {
                            let progress = setup_progress_bar(total as u64, false);
                            pb = Some(progress);
                        }
                        if let Some(ref progress_bar) = pb {
                            progress_bar.set_position(curr as u64);
                            if curr == total {
                                progress_bar.finish_with_message("Done");
                            }
                        }
                    }
                });

                 match run_receiver(&dir, &phrase, &config.relay_url, Some(tx), None).await {
                     Ok(Some(text)) => {
                         println!("Writing received text to system clipboard...");
                         if let Ok(mut ctx) = arboard::Clipboard::new() {
                             if let Err(e) = ctx.set_text(text) {
                                 eprintln!("Failed to write to clipboard: {:?}", e);
                             } else {
                                 println!("Clipboard synchronized successfully!");
                             }
                         } else {
                             eprintln!("Failed to initialize arboard clipboard context");
                         }
                     }
                     Ok(None) => {}
                     Err(e) => {
                         println!("Receive failed: {}", e);
                     }
                 }
            }

            2 => {
                let selections = &["1) Initiator (Show code)", "2) Joiner (Enter code)"];
                let selection = Select::with_theme(&theme)
                    .with_prompt("Choose pairing role")
                    .items(selections)
                    .default(0)
                    .interact()?;

                if selection == 0 {
                    let code = generate_phrase();
                    println!("\nPairing code: {}", code);
                    
                    use qrcode::QrCode;
                    if let Ok(code_obj) = QrCode::new(code.as_bytes()) {
                        let image = code_obj.render::<char>()
                            .quiet_zone(false)
                            .build();
                        println!("\n{}", image);
                    }

                    match run_pairing_sender(&code, &config.relay_url, &config.device_name).await {
                        Ok(peer_id) => println!("\nSuccessfully paired with device ID: {}", hex::encode(peer_id)),
                        Err(e) => println!("Pairing failed: {}", e),
                    }
                } else {
                    let code: String = Input::with_theme(&theme)
                        .with_prompt("Enter pairing code")
                        .interact_text()?;
                    match run_pairing_receiver(&code, &config.relay_url, &config.device_name).await {
                        Ok((peer_id, name)) => println!("\nSuccessfully paired with device '{}' (ID: {})", name, hex::encode(peer_id)),
                        Err(e) => println!("Pairing failed: {}", e),
                    }
                }
            }

            3 => {
                println!("\nPaired Peers:");
                if config.peers.is_empty() {
                    println!("  (No devices paired)");
                } else {
                    for peer in &config.peers {
                        println!(" - {} (ID: {})", peer.name, hex::encode(peer.device_id));
                    }
                }
            }

            4 => {
                let (identity, config) = get_identity_with_merged_config()?;
                println!("\nDevice Config:");
                println!("  device_name:             {}", config.device_name);
                println!("  device_id:               {}", hex::encode(identity.device_id()));
                println!("  relay_url:               {}", config.relay_url);
                println!("  max_upload_mbps:         {:?}", config.max_upload_mbps);
                println!("  dns_probe_ipv4:          {}", config.dns_probe_ipv4);
                println!("  dns_probe_ipv6:          {}", config.dns_probe_ipv6);
                println!("  quic_connect_timeout_ms: {}", config.transport.quic_connect_timeout_ms);
                println!("  p2p_racing_timeout_ms:   {}", config.transport.p2p_racing_timeout_ms);
                println!("  mdns_browse_timeout_ms:  {}", config.transport.mdns_browse_timeout_ms);
                println!("  paired_devices:          {}", config.peers.len());
                let keyring_status = if arc_core::keystore::get_identity_secret().is_ok() {
                    "OS keyring (secure)"
                } else {
                    "config file (fallback)"
                };
                println!("  identity_storage:        {}", keyring_status);
            }

            5 => {
                commands::discover::exec_discover().await?;
            }

            6 => {
                let phrase: String = Input::with_theme(&theme)
                    .with_prompt("Enter the 6-word phrase/code to sync over")
                    .interact_text()?;
                if !validate_passphrase(&phrase) {
                    println!("Error: Invalid passphrase format. Must be 6 hyphen-separated words.");
                    continue;
                }
                if let Err(e) = commands::clipboard::exec_clipboard_sync(phrase, None).await {
                    println!("Clipboard sync failed: {}", e);
                }
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
