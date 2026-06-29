//! Shared CLI helpers: passphrases, progress bars, validation.

use rand::RngExt;

/// 1296-word list (6^4) based on EFF short wordlist for memorable, high-entropy passphrases.
const WORDLIST: &[&str] = &[
    "acid", "acme", "acre", "acts", "aged", "aide", "aims", "ajar", "ally", "also", "amid",
    "ample", "ankle", "anvil", "apex", "arch", "area", "army", "atom", "aunt", "avid", "axis",
    "azure", "badge", "baker", "barn", "base", "bath", "bead", "beam", "bean", "bear", "beat",
    "bell", "belt", "bend", "best", "bike", "bird", "bite", "blade", "blank", "blast", "blaze",
    "bleak", "blend", "bless", "bliss", "block", "bloom", "blown", "bluff", "blunt", "blur",
    "board", "boat", "bold", "bolt", "bomb", "bond", "bone", "bonus", "boost", "born", "boss",
    "bound", "brace", "brain", "brave", "bread", "break", "bred", "breed", "brick", "bride",
    "brief", "brisk", "broad", "broke", "brook", "broom", "brush", "brute", "budge", "build",
    "bulge", "bulk", "bump", "bunch", "burn", "burst", "buyer", "cabin", "cable", "camel", "camp",
    "candy", "cape", "cargo", "carry", "carve", "catch", "cause", "cedar", "chain", "chair",
    "chalk", "champ", "chaos", "charm", "chase", "cheap", "check", "cheek", "chess", "chest",
    "chief", "child", "chill", "china", "chip", "choir", "chunk", "civic", "civil", "claim",
    "clamp", "clash", "clasp", "class", "clean", "clear", "clerk", "click", "cliff", "climb",
    "cling", "clip", "cloak", "clock", "clone", "close", "cloth", "cloud", "clown", "club", "clue",
    "clump", "coach", "coast", "cobra", "code", "coil", "cold", "comet", "comic", "coral", "cord",
    "core", "corps", "couch", "count", "court", "cover", "crack", "craft", "crane", "crash",
    "crawl", "crazy", "cream", "creek", "crest", "crew", "crisp", "cross", "crowd", "crown",
    "crude", "crush", "cubic", "curve", "cycle", "daily", "dance", "darts", "dawn", "dealt",
    "decay", "deck", "decor", "decoy", "delta", "demon", "dense", "depot", "depth", "derby",
    "desk", "dew", "diary", "digit", "ditch", "dodge", "donor", "donut", "doubt", "draft", "drain",
    "drake", "drape", "drawn", "dream", "dress", "drift", "drill", "drink", "drive", "drone",
    "drops", "drove", "drums", "drunk", "dryer", "ducky", "dug", "dummy", "dunce", "dune", "dusk",
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

pub fn generate_phrase() -> String {
    let mut rng = rand::rng();
    let mut words = Vec::new();
    for _ in 0..6 {
        let idx = rng.random_range(0..WORDLIST.len());
        words.push(WORDLIST[idx]);
    }
    words.join("-")
}

pub fn validate_passphrase(phrase: &str) -> bool {
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

pub fn setup_progress_bar(total: u64, is_sender: bool) -> indicatif::ProgressBar {
    if total > 0 {
        let progress = indicatif::ProgressBar::new(total);
        progress.set_style(
            indicatif::ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} chunks ({eta})")
                .unwrap(),
        );
        progress
    } else {
        let progress = indicatif::ProgressBar::new_spinner();
        let msg = if is_sender {
            "chunks sent"
        } else {
            "chunks received"
        };
        progress.set_style(
            indicatif::ProgressStyle::default_spinner()
                .template(&format!(
                    "{{spinner:.green}} [{{elapsed_precise}}] {{pos}} {msg}"
                ))
                .unwrap(),
        );
        progress
    }
}

pub fn spawn_progress_task(mut rx: tokio::sync::mpsc::Receiver<(u32, u32)>, is_sender: bool) {
    tokio::spawn(async move {
        let mut pb = None;
        while let Some((curr, total)) = rx.recv().await {
            if pb.is_none() {
                let progress = setup_progress_bar(total as u64, is_sender);
                pb = Some(progress);
            }
            if let Some(ref progress_bar) = pb {
                progress_bar.set_position(curr as u64);
                if total > 0 && curr == total {
                    progress_bar.finish_with_message("Done");
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_passphrase_valid() {
        assert!(validate_passphrase("acid-acme-acre-acts-aged-aide"));
    }

    #[test]
    fn test_validate_passphrase_invalid_count() {
        assert!(!validate_passphrase("acid-acme-acre"));
    }

    #[test]
    fn test_validate_passphrase_invalid_chars() {
        assert!(!validate_passphrase("acid-acme-acre-acts-aged-a1de"));
    }
}
