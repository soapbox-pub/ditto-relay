//! What an event's text says about it: its language, by [whatlang], and
//! its sentiment, by [VADER]. Both are guesses, so they're made once, when
//! an event arrives, and kept in its [record](crate::record): the event is
//! then filed under them, and checked against them live, with no chance of
//! a second guess differing from the first.
//!
//! Text shorter than [`MIN_TEXT`] characters is too little to tell either
//! by, and only the first [`MAX_TEXT`] are read. A language is only
//! recorded when whatlang is at least [`MIN_CONFIDENCE`] sure of it. VADER
//! only knows English, so only text whatlang thinks is English gets a
//! sentiment. Reactions are read by what they react with: `+`, `-`, or an
//! emoji, most of which are common enough to be listed here, as
//! [ditto-relay] reads them; VADER guesses at the rest.
//!
//! [whatlang]: https://github.com/greyblake/whatlang-rs
//! [VADER]: https://github.com/cjhutto/vaderSentiment
//! [ditto-relay]: https://gitlab.com/soapbox-pub/ditto

use std::sync::LazyLock;

use vader_parity::SentimentIntensityAnalyzer;
use whatlang::Lang;

use crate::record::{Content, EventView};

/// The fewest characters of text whose language or sentiment is guessed.
const MIN_TEXT: usize = 10;

/// The most characters of text read.
const MAX_TEXT: usize = 1024;

/// How sure whatlang must be of a language for it to be recorded. Its
/// confidence is how far ahead of the runner-up its guess is, so it's low
/// for short text even when right; below this, it's mostly wrong.
const MIN_CONFIDENCE: f64 = 0.1;

/// How far from neutral VADER's compound score must be to count, as its
/// authors suggest.
const SENTIMENT_THRESHOLD: f64 = 0.05;

/// NIP-25 reactions.
const REACTION: u16 = 7;

static VADER: LazyLock<SentimentIntensityAnalyzer> = LazyLock::new(SentimentIntensityAnalyzer::new);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Sentiment {
    Positive,
    Negative,
    Neutral,
}

impl Sentiment {
    pub fn parse(value: &str) -> Option<Sentiment> {
        match value {
            "positive" => Some(Sentiment::Positive),
            "negative" => Some(Sentiment::Negative),
            "neutral" => Some(Sentiment::Neutral),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Sentiment::Positive => "positive",
            Sentiment::Negative => "negative",
            Sentiment::Neutral => "neutral",
        }
    }

    /// As a record keeps it: never 0, which is none.
    pub fn to_byte(self) -> u8 {
        match self {
            Sentiment::Positive => 1,
            Sentiment::Negative => 2,
            Sentiment::Neutral => 3,
        }
    }

    pub fn from_byte(byte: u8) -> Option<Sentiment> {
        match byte {
            1 => Some(Sentiment::Positive),
            2 => Some(Sentiment::Negative),
            3 => Some(Sentiment::Neutral),
            _ => None,
        }
    }

    fn of_score(compound: f64) -> Sentiment {
        if compound >= SENTIMENT_THRESHOLD {
            Sentiment::Positive
        } else if compound <= -SENTIMENT_THRESHOLD {
            Sentiment::Negative
        } else {
            Sentiment::Neutral
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Analysis {
    /// ISO 639-1, lowercase.
    pub language: Option<[u8; 2]>,
    pub sentiment: Option<Sentiment>,
}

impl Analysis {
    pub fn is_empty(&self) -> bool {
        *self == Analysis::default()
    }
}

/// Kinds whose content isn't prose anyone wrote: lists, encrypted
/// messages, and the like.
fn is_prose(kind: u16) -> bool {
    !matches!(
        kind,
        3 | 4
            | 6
            | 13
            | 16
            | 1059
            | 9735
            | 10000..=10102
            | 30000..=30030
            | 31234
            | 31924
            | 39089
            | 39092
    )
}

/// Guess an event's language and sentiment, if they can be told.
pub fn analyze(view: &EventView) -> Analysis {
    let kind = view.kind();
    let Content::Text(content) = view.content() else {
        return Analysis::default();
    };
    if !is_prose(kind) {
        return Analysis::default();
    }
    if kind == REACTION {
        return Analysis {
            language: None,
            sentiment: reaction(content.trim()),
        };
    }
    let text = crate::search::text(view);
    let text = match text.char_indices().nth(MAX_TEXT) {
        Some((end, _)) => &text[..end],
        None => &text,
    };
    if text.chars().nth(MIN_TEXT - 1).is_none() {
        return Analysis::default();
    }
    let Some(info) = whatlang::detect(text) else {
        return Analysis::default();
    };
    let language = iso639_1(info.lang()).as_bytes().try_into().ok();
    Analysis {
        language: language.filter(|_| info.confidence() >= MIN_CONFIDENCE),
        sentiment: (info.lang() == Lang::Eng).then(|| score(text)),
    }
}

/// VADER's take. It knows emoji, but not with a variation selector.
fn score(text: &str) -> Sentiment {
    let text = text.replace('\u{fe0f}', "");
    Sentiment::of_score(VADER.polarity_scores(&text).compound)
}

/// What a reaction says: a like, a dislike, or what its emoji does. A
/// NIP-30 custom emoji's `:shortcode:` says nothing anyone can read.
fn reaction(content: &str) -> Option<Sentiment> {
    match content {
        "" | "+" => return Some(Sentiment::Positive),
        "-" => return Some(Sentiment::Negative),
        _ => {}
    }
    if let Some(code) = content.strip_prefix(':').and_then(|c| c.strip_suffix(':'))
        && !code.is_empty()
        && code
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        return None;
    }
    // 👍🏼 is 👍, and ❤️ is ❤.
    let emoji: String = content
        .chars()
        .filter(|&c| c != '\u{fe0f}' && !('\u{1f3fb}'..='\u{1f3ff}').contains(&c))
        .collect();
    for (list, sentiment) in [
        (POSITIVE_EMOJI, Sentiment::Positive),
        (NEGATIVE_EMOJI, Sentiment::Negative),
        (NEUTRAL_EMOJI, Sentiment::Neutral),
    ] {
        if list.contains(&emoji.as_str()) {
            return Some(sentiment);
        }
    }
    Some(score(content))
}

/// Reactions that are approval: hearts, thumbs up, fire, and Nostr's own
/// flex emoji (🚀, ⚡, ₿).
const POSITIVE_EMOJI: &[&str] = &[
    "❤",
    "🧡",
    "💛",
    "💚",
    "💙",
    "💜",
    "🤍",
    "🤎",
    "🖤",
    "💖",
    "💕",
    "💗",
    "💘",
    "💝",
    "💞",
    "💟",
    "♥",
    "❤\u{200d}🔥",
    "👍",
    "👏",
    "🙌",
    "🤝",
    "🫶",
    "🤙",
    "👌",
    "🤘",
    "✊",
    "👊",
    "🙏",
    "👋",
    "💪",
    "🤞",
    "🫡",
    "✍",
    "😀",
    "😃",
    "😄",
    "😁",
    "😆",
    "😊",
    "🙂",
    "😇",
    "🥰",
    "😍",
    "🤩",
    "🥳",
    "😎",
    "🤗",
    "😘",
    "😗",
    "😙",
    "😚",
    "🥲",
    "😋",
    "😌",
    "🤤",
    "😂",
    "🤣",
    "😺",
    "😸",
    "😹",
    "😻",
    "✨",
    "🌟",
    "⭐",
    "🎉",
    "🎊",
    "🔥",
    "💯",
    "✅",
    "☑",
    "✔",
    "🚀",
    "🫂",
    "🥂",
    "🍻",
    "🌞",
    "☀",
    "🏆",
    "💥",
    "🍀",
    "👑",
    "🦅",
    "🦞",
    "₿",
    "⚡",
];

/// Reactions that are disapproval, sadness, or derision (🤡).
const NEGATIVE_EMOJI: &[&str] = &[
    "💔", "👎", "🖕", "😢", "😭", "😞", "😔", "😟", "😠", "😡", "🤬", "😤", "😩", "😫", "😨", "😰",
    "😱", "🤮", "🤢", "💀", "☠", "🥺", "😬", "💩", "❌", "🚫", "⛔", "🤡",
];

/// Reactions that acknowledge without feeling either way.
const NEUTRAL_EMOJI: &[&str] = &[
    "☝",
    "👉",
    "👆",
    "🤌",
    "🤔",
    "🤷",
    "🤷\u{200d}♂",
    "🤷\u{200d}♀",
    "😐",
    "😑",
    "😮",
    "😯",
    "😲",
    "🤨",
    "🧐",
    "🙄",
    "😏",
    "😜",
    "😈",
    "🤯",
    "🥴",
    "😅",
    "🤓",
    "🤭",
    "🫠",
    "😳",
    "👁",
    "👀",
    "📜",
    "☕",
    "🎯",
    "🍮",
    "🫧",
    "🐱",
    "🐾",
];

/// A language's ISO 639-1 code, which is what clients know them by.
fn iso639_1(lang: Lang) -> &'static str {
    match lang {
        Lang::Epo => "eo",
        Lang::Eng => "en",
        Lang::Rus => "ru",
        Lang::Cmn => "zh",
        Lang::Spa => "es",
        Lang::Por => "pt",
        Lang::Ita => "it",
        Lang::Ben => "bn",
        Lang::Fra => "fr",
        Lang::Deu => "de",
        Lang::Ukr => "uk",
        Lang::Kat => "ka",
        Lang::Ara => "ar",
        Lang::Hin => "hi",
        Lang::Jpn => "ja",
        Lang::Heb => "he",
        Lang::Yid => "yi",
        Lang::Pol => "pl",
        Lang::Amh => "am",
        Lang::Jav => "jv",
        Lang::Kor => "ko",
        Lang::Nob => "no",
        Lang::Dan => "da",
        Lang::Swe => "sv",
        Lang::Fin => "fi",
        Lang::Tur => "tr",
        Lang::Nld => "nl",
        Lang::Hun => "hu",
        Lang::Ces => "cs",
        Lang::Ell => "el",
        Lang::Bul => "bg",
        Lang::Bel => "be",
        Lang::Mar => "mr",
        Lang::Kan => "kn",
        Lang::Ron => "ro",
        Lang::Slv => "sl",
        Lang::Hrv => "hr",
        Lang::Srp => "sr",
        Lang::Mkd => "mk",
        Lang::Lit => "lt",
        Lang::Lav => "lv",
        Lang::Est => "et",
        Lang::Tam => "ta",
        Lang::Vie => "vi",
        Lang::Urd => "ur",
        Lang::Tha => "th",
        Lang::Guj => "gu",
        Lang::Uzb => "uz",
        Lang::Pan => "pa",
        Lang::Aze => "az",
        Lang::Ind => "id",
        Lang::Tel => "te",
        Lang::Pes => "fa",
        Lang::Mal => "ml",
        Lang::Ori => "or",
        Lang::Mya => "my",
        Lang::Nep => "ne",
        Lang::Sin => "si",
        Lang::Khm => "km",
        Lang::Tuk => "tk",
        Lang::Aka => "ak",
        Lang::Zul => "zu",
        Lang::Sna => "sn",
        Lang::Afr => "af",
        Lang::Lat => "la",
        Lang::Slk => "sk",
        Lang::Cat => "ca",
        Lang::Tgl => "tl",
        Lang::Hye => "hy",
        Lang::Cym => "cy",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::tests::signed;
    use crate::record;

    fn analyzed(kind: u16, content: &str) -> Analysis {
        let record = record::encode(&signed(1, 100, kind, vec![], content));
        let view = EventView::new(&record).unwrap();
        // Kept in the record as guessed.
        assert_eq!(view.analysis(), analyze(&view));
        view.analysis()
    }

    fn language(kind: u16, content: &str) -> Option<String> {
        analyzed(kind, content)
            .language
            .map(|code| String::from_utf8(code.to_vec()).unwrap())
    }

    #[test]
    fn tells_language() {
        assert_eq!(
            language(1, "Nostr is the future of social media").as_deref(),
            Some("en")
        );
        assert_eq!(
            language(1, "Buenos días, ¿cómo están todos?").as_deref(),
            Some("es")
        );
        assert_eq!(
            language(1, "Dzień dobry, jak się macie?").as_deref(),
            Some("pl")
        );
        assert_eq!(
            language(1, "今日はとても良い天気ですね。").as_deref(),
            Some("ja")
        );
        // Too short to tell, or too unsure.
        assert_eq!(language(1, "gm"), None);
        assert_eq!(language(1, "lol same lol"), None);
        // Nobody wrote a follow list.
        let follows = analyzed(3, "Nostr is the future of social media");
        assert_eq!(follows, Analysis::default());
    }

    #[test]
    fn tells_sentiment() {
        let sentiment = |content| analyzed(1, content).sentiment;
        assert_eq!(
            sentiment("I love this, what a wonderful and happy day!"),
            Some(Sentiment::Positive)
        );
        assert_eq!(
            sentiment("This is terrible, I hate it and feel awful."),
            Some(Sentiment::Negative)
        );
        assert_eq!(
            sentiment("just shipped a new release of my relay"),
            Some(Sentiment::Neutral)
        );
        assert_eq!(
            sentiment("This movie is not good."),
            Some(Sentiment::Negative)
        );
        // English only.
        assert_eq!(sentiment("Bonjour à tous, bonne journée"), None);
    }

    #[test]
    fn reads_reactions() {
        let sentiment = |content| analyzed(7, content).sentiment;
        assert_eq!(sentiment("+"), Some(Sentiment::Positive));
        assert_eq!(sentiment(""), Some(Sentiment::Positive));
        assert_eq!(sentiment("-"), Some(Sentiment::Negative));
        assert_eq!(sentiment("❤️"), Some(Sentiment::Positive));
        assert_eq!(sentiment("❤️\u{200d}🔥"), Some(Sentiment::Positive));
        assert_eq!(sentiment("👍🏽"), Some(Sentiment::Positive));
        assert_eq!(sentiment("🤡"), Some(Sentiment::Negative));
        assert_eq!(sentiment("🤔"), Some(Sentiment::Neutral));
        // Not listed: VADER's guess.
        assert_eq!(sentiment("💩💩 awful"), Some(Sentiment::Negative));
        assert_eq!(sentiment(":soapbox:"), None);
    }
}
