//! The HTML page a browser sees at the relay's address, rendered once from
//! its NIP-11 information document, and the images it shows.

use serde_json::Value;

pub const FAVICON: &[u8] = include_bytes!("../assets/favicon.ico");
pub const ICON: &[u8] = include_bytes!("../assets/icon.png");
pub const BANNER: &[u8] = include_bytes!("../assets/banner.jpg");

/// The URL of an asset served at `path` on the host at `public_url`.
pub fn asset_url(public_url: &str, path: &str) -> String {
    let after_scheme = public_url.find("://").map_or(0, |i| i + 3);
    let origin = match public_url[after_scheme..].find(['/', '?', '#']) {
        Some(end) => &public_url[..after_scheme + end],
        None => public_url,
    };
    format!("{origin}{path}")
}

/// Escape text for HTML, inside an element or a quoted attribute.
fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#039;"),
            c => out.push(c),
        }
    }
    out
}

/// `url`, escaped for an attribute, if it has one of `schemes`, so a
/// misconfigured URL can't be `javascript:` or `data:`.
fn safe_url(url: &str, schemes: &[&str]) -> Option<String> {
    let lower = url.trim().to_ascii_lowercase();
    let ok = schemes.iter().any(|scheme| lower.starts_with(scheme))
        && !url.trim().chars().any(char::is_whitespace);
    ok.then(|| esc(url.trim()))
}

const HTTP: &[&str] = &["http://", "https://"];

/// Whether `text` is shaped like `user@host.tld`. No `:` or `/`, so
/// `javascript:alert(1)//@x.com` doesn't pass.
fn is_email(text: &str) -> bool {
    let plain =
        |s: &str| !s.is_empty() && !s.contains(|c: char| c.is_whitespace() || "@:/".contains(c));
    match text.split_once('@') {
        Some((user, host)) => {
            plain(user)
                && plain(host)
                && host
                    .split_once('.')
                    .is_some_and(|(a, b)| !a.is_empty() && plain(b))
        }
        None => false,
    }
}

/// The operator's contact, linked when it's an email address or a web page.
fn contact_html(contact: &str) -> String {
    if let Some(addr) = contact.strip_prefix("mailto:") {
        if is_email(addr) {
            return format!(r#"<a href="mailto:{0}">{0}</a>"#, esc(addr));
        }
    } else if let Some(url) = safe_url(contact, HTTP) {
        return format!(r#"<a href="{url}" target="_blank" rel="noopener">{url}</a>"#);
    } else if is_email(contact) {
        return format!(r#"<a href="mailto:{0}">{0}</a>"#, esc(contact));
    }
    esc(contact)
}

/// The colour browsers that heed `theme-color` paint their own frame in:
/// the page's background, so the two run together.
pub const THEME_COLOR: &str = "#0b0a12";

/// What a NIP the relay supports is for, as the page names it.
fn nip_name(nip: u64) -> Option<&'static str> {
    Some(match nip {
        1 => "Basic protocol",
        9 => "Deletions",
        11 => "Relay information",
        40 => "Expiring events",
        42 => "Authentication",
        45 => "Event counts",
        50 => "Search",
        62 => "Request to vanish",
        70 => "Protected events",
        77 => "Negentropy sync",
        85 => "Trusted assertions",
        _ => return None,
    })
}

/// `n` with thousands separated by commas.
fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// A size in bytes, in the largest binary unit it's at least one of, to a
/// tenth.
fn bytes(n: u64) -> String {
    let (unit, name) = match n {
        n if n >= 1 << 30 => (1u64 << 30, "GiB"),
        n if n >= 1 << 20 => (1 << 20, "MiB"),
        n if n >= 1 << 10 => (1 << 10, "KiB"),
        n => return format!("{n} bytes"),
    };
    let tenths = (n * 10 + unit / 2) / unit;
    match tenths % 10 {
        0 => format!("{} {name}", thousands(tenths / 10)),
        t => format!("{}.{t} {name}", thousands(tenths / 10)),
    }
}

/// A span of seconds, in the largest unit it's a whole number of.
fn seconds(n: u64) -> String {
    let (count, unit) = match n {
        n if n >= 86_400 && n.is_multiple_of(86_400) => (n / 86_400, "day"),
        n if n >= 3_600 && n.is_multiple_of(3_600) => (n / 3_600, "hour"),
        n if n >= 60 && n.is_multiple_of(60) => (n / 60, "minute"),
        n => (n, "second"),
    };
    let s = if count == 1 { "" } else { "s" };
    format!("{} {unit}{s}", thousands(count))
}

/// A 32-byte key in hex as NIP-19 has it shown, with `hrp` (`npub`).
fn bech32(hrp: &str, hex_key: &str) -> Option<String> {
    const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let data = hex::decode(hex_key).ok().filter(|d| d.len() == 32)?;
    // Regrouped from 8 bits to 5.
    let mut words = Vec::with_capacity(52);
    let (mut acc, mut bits) = (0u32, 0);
    for byte in data {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            words.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        words.push(((acc << (5 - bits)) & 31) as u8);
    }
    let polymod = |values: &[u8]| {
        const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
        let mut chk = 1u32;
        for &v in values {
            let top = chk >> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ u32::from(v);
            for (i, g) in GEN.iter().enumerate() {
                if (top >> i) & 1 == 1 {
                    chk ^= g;
                }
            }
        }
        chk
    };
    let mut values: Vec<u8> = hrp.bytes().map(|b| b >> 5).collect();
    values.push(0);
    values.extend(hrp.bytes().map(|b| b & 31));
    values.extend(&words);
    values.extend([0; 6]);
    let checksum = polymod(&values) ^ 1;
    words.extend((0..6).map(|i| ((checksum >> (5 * (5 - i))) & 31) as u8));
    let mut out = format!("{hrp}1");
    out.extend(words.iter().map(|&w| char::from(CHARSET[usize::from(w)])));
    Some(out)
}

/// A field holding `text`, which a button copies.
fn copyable(text: &str) -> String {
    format!(
        r#"<div class="addr"><code>{text}</code><button class="copy" type="button" data-copy="{text}">Copy</button></div>"#
    )
}

/// The NIPs it supports, as linked chips.
fn nips_html(info: &Value) -> String {
    let nips = info["supported_nips"].as_array().into_iter().flatten();
    nips.filter_map(Value::as_u64)
        .map(|nip| {
            let name = nip_name(nip).map(|n| format!(" {n}")).unwrap_or_default();
            format!(
                r#"<a class="chip" href="https://github.com/nostr-protocol/nips/blob/master/{nip:02}.md" target="_blank" rel="noopener"><i>{nip:02}</i>{name}</a>"#
            )
        })
        .collect()
}

/// Its limits, from NIP-11's `limitation`, as a list.
fn limits_html(info: &Value) -> String {
    let limit = |key: &str| info["limitation"][key].as_u64();
    let rows: [(&str, Option<String>); 6] = [
        ("Largest message", limit("max_message_length").map(bytes)),
        ("Events per request", limit("max_limit").map(thousands)),
        (
            "Subscriptions per connection",
            limit("max_subscriptions").map(thousands),
        ),
        ("Filters per request", limit("max_filters").map(thousands)),
        (
            "Values per filter",
            limit("max_filter_values").map(thousands),
        ),
        (
            "Dated ahead by at most",
            limit("created_at_upper_limit").map(seconds),
        ),
    ];
    rows.into_iter()
        .filter_map(|(what, value)| Some(format!("<li><span>{what}</span><b>{}</b></li>", value?)))
        .collect()
}

/// Who runs it, if NIP-11 says.
fn operator_html(info: &Value) -> String {
    let npub = info["pubkey"].as_str().and_then(|pk| bech32("npub", pk));
    let contact = info["contact"]
        .as_str()
        .filter(|c| !c.is_empty())
        .map(contact_html);
    if npub.is_none() && contact.is_none() {
        return String::new();
    }
    let npub = npub.map(|npub| copyable(&npub)).unwrap_or_default();
    let contact = contact
        .map(|c| format!(r#"<div class="contact">{c}</div>"#))
        .unwrap_or_default();
    format!(
        r#"
  <section aria-labelledby="op-h">
    <div class="sec-head"><span class="eyebrow">Operator</span><h2 id="op-h">Who runs it</h2></div>
    <div class="panel op">{npub}{contact}</div>
  </section>"#
    )
}

/// The landing page for the relay at `relay_url`, described by `info`.
pub fn render(info: &Value, relay_url: &str) -> String {
    let field = |key: &str| info[key].as_str().filter(|v| !v.is_empty());
    let name = esc(field("name").unwrap_or("Nostr Relay"));
    let description = field("description").map(esc);
    let icon = field("icon").and_then(|url| safe_url(url, HTTP));
    let banner = field("banner").and_then(|url| safe_url(url, HTTP));
    let version = field("version").map(esc);
    let relay = esc(relay_url);

    let mut head = String::new();
    if let Some(description) = &description {
        head += &format!(
            r#"
  <meta name="description" content="{description}">
  <meta property="og:description" content="{description}">
  <meta name="twitter:description" content="{description}">"#
        );
    }
    if let Some(icon) = &icon {
        head += &format!(
            r#"
  <link rel="apple-touch-icon" href="{icon}">"#
        );
    }
    if let Some(image) = banner.as_ref().or(icon.as_ref()) {
        head += &format!(
            r#"
  <meta property="og:image" content="{image}">
  <meta name="twitter:image" content="{image}">"#
        );
    }
    let card = if banner.is_some() {
        "summary_large_image"
    } else {
        "summary"
    };

    let banner_html = banner
        .as_ref()
        .map(|b| format!(r#"<div class="banner"><img src="{b}" alt=""></div>"#))
        .unwrap_or_default();
    let mast_class = if banner.is_some() {
        "mast has-banner"
    } else {
        "mast"
    };
    let icon_html = icon
        .map(|i| format!(r#"<img class="icon" src="{i}" alt="">"#))
        .unwrap_or_default();
    let description = description
        .map(|d| format!(r#"<p class="lead">{d}</p>"#))
        .unwrap_or_default();
    let version = version
        .map(|v| format!(r#" <span class="version">v{v}</span>"#))
        .unwrap_or_default();
    let address = copyable(&relay);
    let nips = nips_html(info);
    let limits = limits_html(info);
    let operator = operator_html(info);

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <title>{name}</title>
  <meta name="theme-color" content="{THEME_COLOR}">
  <meta name="color-scheme" content="dark">
  <link rel="icon" href="/favicon.ico">
  <meta property="og:type" content="website">
  <meta property="og:title" content="{name}">
  <meta name="twitter:card" content="{card}">
  <meta name="twitter:title" content="{name}">{head}
  <style>{STYLE}</style>
</head>
<body>
<main class="wrap">
  <header>
    {banner_html}
    <div class="{mast_class}">
      {icon_html}
      <div class="mast-text">
        <h1>{name}</h1>
        {description}
        <div class="status" id="status"><span class="dot"></span><b id="state">Online</b><span id="since"></span></div>
      </div>
    </div>
  </header>

  <section aria-label="Live numbers">
    <div class="tiles">
      <div class="tile"><span class="v"><span class="roll" id="t-events">–</span></span><span class="k">events stored</span></div>
      <div class="tile"><span class="v"><span class="roll" id="t-open">–</span></span><span class="k">connected now</span></div>
      <div class="tile"><span class="v"><span class="roll" id="t-answer">–</span><small>ms</small></span><span class="k">average answer</span></div>
      <div class="tile"><span class="v"><span class="roll" id="t-requests">–</span></span><span class="k">requests answered</span></div>
    </div>
  </section>

  <section aria-labelledby="connect-h">
    <div class="sec-head">
      <span class="eyebrow">Connect</span>
      <h2 id="connect-h">Add it to your Nostr client</h2>
      <p>Paste this address wherever your client lists its relays.</p>
    </div>
    <div class="panel connect">{address}</div>
  </section>

  <section aria-labelledby="carry-h">
    <div class="sec-head">
      <span class="eyebrow">What it speaks</span>
      <h2 id="carry-h">Supported features</h2>
    </div>
    <div class="carry">
      <div class="panel"><h3>NIPs</h3><div class="chips">{nips}</div></div>
      <div class="panel"><h3>Limits</h3><ul class="limits">{limits}</ul></div>
    </div>
  </section>
{operator}
  <footer>
    <span>Runs <a href="{REPOSITORY}" target="_blank" rel="noopener">Ditto Relay</a>{version}</span>
    <a href="stats">Stats as JSON</a>
  </footer>
</main>
<script>{SCRIPT}</script>
</body>
</html>
"#
    )
}

pub const REPOSITORY: &str = "https://gitworkshop.dev/soapbox.pub/ditto-relay";

const STYLE: &str = r#"
:root{--bg:#0b0a12;--card:#12111b;--raise:#191726;--line:#232036;--edge:#363052;
  --text:#f3f1fb;--text-2:#c0bbd8;--text-3:#8f89ab;--text-4:#625c80;
  --accent:#8b6cff;--accent-2:#b9a3ff;--accent-3:#6a4ff0;--pink:#e47cf5;--warn:#fbbf6a;
  --ease:cubic-bezier(.22,1,.36,1);
  --font:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color-scheme:dark}
*,*::before,*::after{box-sizing:border-box}
h1,h2,h3,p{margin:0}
body{margin:0;min-height:100vh;background:var(--bg);color:var(--text);font-family:var(--font);
  line-height:1.5;-webkit-font-smoothing:antialiased;-webkit-text-size-adjust:100%;
  background-image:radial-gradient(1100px 560px at 50% -200px,rgba(139,108,255,.2),transparent 70%),
    radial-gradient(700px 400px at 90% -100px,rgba(228,124,245,.08),transparent 70%);background-repeat:no-repeat}
.wrap{max-width:980px;margin:0 auto;display:grid;grid-template-columns:minmax(0,1fr);gap:56px;
  padding:48px max(16px,env(safe-area-inset-right)) 40px max(16px,env(safe-area-inset-left))}
h2{font-size:1.35rem;font-weight:650;letter-spacing:-.01em}
.eyebrow{font-family:var(--mono);font-size:.72rem;letter-spacing:.14em;text-transform:uppercase;color:var(--text-4)}
.sec-head{display:grid;gap:6px;margin-bottom:20px}
.sec-head p{color:var(--text-3)}

.banner{position:relative;aspect-ratio:3/1;border-radius:20px;overflow:hidden;border:1px solid var(--line);background:var(--card)}
.banner img{width:100%;height:100%;object-fit:cover;display:block}
.banner::after{content:"";position:absolute;inset:0;background:linear-gradient(180deg,transparent 45%,rgba(11,10,18,.75))}
.mast{display:grid;grid-template-columns:auto minmax(0,1fr);gap:28px;align-items:center}
.mast:not(:has(.icon)){grid-template-columns:minmax(0,1fr)}
.has-banner{align-items:start;margin-top:-56px;padding:0 24px;position:relative}
.has-banner .mast-text{padding-top:72px}
.icon{width:120px;height:120px;border-radius:30px;object-fit:cover;background:var(--raise);
  box-shadow:0 0 0 4px var(--bg),0 0 48px rgba(139,108,255,.45)}
.mast:not(.has-banner) .icon{animation:float 6s ease-in-out infinite}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}
.mast h1{font-size:clamp(2.1rem,6.4vw,3.4rem);font-weight:700;line-height:1.05;letter-spacing:-.025em;
  background:linear-gradient(120deg,#e2d9ff 0%,var(--accent-2) 35%,var(--accent) 65%,var(--pink) 110%);
  -webkit-background-clip:text;background-clip:text;color:transparent;overflow-wrap:anywhere;padding-bottom:.06em}
.lead{margin-top:10px;font-size:1.08rem;color:var(--text-2);max-width:62ch}
.status{display:inline-flex;align-items:center;gap:9px;margin-top:18px;padding:6px 14px 6px 11px;
  border:1px solid rgba(139,108,255,.35);background:rgba(139,108,255,.08);border-radius:999px;font-size:.86rem;color:var(--text-2)}
.status b{color:var(--accent-2);font-weight:600}
.status #since:empty{display:none}
.dot{width:8px;height:8px;border-radius:50%;background:var(--accent-2);animation:pulse 2.4s var(--ease) infinite}
.status.off{border-color:rgba(251,191,106,.4);background:rgba(251,191,106,.07)}
.status.off b{color:var(--warn)}
.status.off .dot{background:var(--warn);animation:none}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(185,163,255,.6)}70%{box-shadow:0 0 0 9px rgba(185,163,255,0)}100%{box-shadow:0 0 0 0 rgba(185,163,255,0)}}

.tiles{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}
.tile{position:relative;overflow:hidden;display:grid;gap:6px;padding:20px 18px 16px;border-radius:16px;
  background:linear-gradient(180deg,var(--raise),var(--card));border:1px solid var(--line)}
.tile::before{content:"";position:absolute;inset:0 0 auto;height:1px;background:linear-gradient(90deg,transparent,rgba(185,163,255,.5),transparent)}
.tile::after{content:"";position:absolute;width:160px;height:160px;right:-60px;top:-90px;border-radius:50%;
  background:radial-gradient(closest-side,rgba(139,108,255,.14),transparent);pointer-events:none}
.tile .v{font-size:clamp(1.45rem,3.6vw,2.15rem);font-weight:650;line-height:1.15;letter-spacing:-.01em;
  font-variant-numeric:tabular-nums;white-space:nowrap}
.tile .v small{font-size:.55em;font-weight:400;color:var(--text-3);margin-left:3px}
.tile .k{font-size:.84rem;color:var(--text-3)}
.roll{display:inline-flex}
.slot{display:inline-block;height:1.15em;overflow:hidden;vertical-align:top}
.reel{display:block;transition:transform 1.1s var(--ease)}
.reel span{display:block;height:1.15em}

.panel{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:20px}
.panel h3{font-size:.95rem;font-weight:600;margin-bottom:14px}
.connect{max-width:720px}
.addr{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;gap:8px;background:#08070d;
  border:1px solid var(--line);border-radius:12px;padding:8px 8px 8px 14px;transition:border-color .2s var(--ease)}
.addr:hover{border-color:var(--edge)}
.addr code{font-family:var(--mono);font-size:.86rem;overflow-wrap:anywhere;line-height:1.35}
.copy{font:inherit;font-size:.8rem;font-weight:600;color:#fff;border:0;border-radius:8px;padding:7px 12px;min-height:32px;cursor:pointer;
  background:linear-gradient(135deg,var(--accent),var(--accent-3));transition:filter .2s var(--ease),transform .15s var(--ease)}
.copy:hover{filter:brightness(1.15)}
.copy:active{transform:scale(.96)}
.copy.done{background:var(--raise);color:var(--accent-2)}

.carry{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(0,1fr);gap:12px}
.chips{display:flex;flex-wrap:wrap;gap:8px}
.chip{display:inline-flex;align-items:baseline;gap:7px;padding:6px 12px;border-radius:999px;background:var(--raise);
  border:1px solid var(--line);font-size:.85rem;color:var(--text-2);text-decoration:none;
  transition:border-color .2s var(--ease),color .2s var(--ease),background .2s var(--ease)}
.chip i{font-style:normal;font-family:var(--mono);font-size:.72rem;color:var(--accent-2)}
.chip:hover,.chip:focus-visible{border-color:rgba(139,108,255,.55);color:var(--text);background:rgba(139,108,255,.1);outline:none}
.limits{list-style:none;margin:0;padding:0;display:grid;gap:10px}
.limits li{display:flex;justify-content:space-between;gap:12px;font-size:.9rem;color:var(--text-3);border-bottom:1px dashed var(--line);padding-bottom:9px}
.limits li:last-child{border-bottom:0;padding-bottom:0}
.limits b{color:var(--text);font-weight:500;font-variant-numeric:tabular-nums;white-space:nowrap}
.op{display:grid;gap:10px;max-width:720px}
.contact{font-size:.92rem;color:var(--text-3);overflow-wrap:anywhere}
.contact a{color:var(--accent-2);text-decoration:none}
.contact a:hover{text-decoration:underline}

footer{display:flex;flex-wrap:wrap;justify-content:space-between;gap:12px;padding-top:22px;border-top:1px solid var(--line);color:var(--text-4);font-size:.84rem}
footer a{color:var(--text-3);text-decoration:none}
footer a:hover{color:var(--accent-2)}
.version{opacity:.8}

@media (max-width:820px){.tiles{grid-template-columns:repeat(2,minmax(0,1fr))}.carry{grid-template-columns:minmax(0,1fr)}}
@media (max-width:560px){
  .wrap{padding-top:28px;gap:44px}
  .mast{grid-template-columns:minmax(0,1fr);gap:16px}
  .has-banner{margin-top:-44px;padding:0 16px}
  .has-banner .mast-text{padding-top:0}
  .icon{width:88px;height:88px;border-radius:24px}
  .banner{aspect-ratio:2/1}
}
@media (prefers-reduced-motion:reduce){.dot,.icon{animation:none!important}.reel,.copy,.chip{transition:none}}
"#;

const SCRIPT: &str = r#"
(() => {
  for (const b of document.querySelectorAll(".copy")) {
    b.addEventListener("click", async () => {
      const text = b.dataset.copy;
      try { await navigator.clipboard.writeText(text); } catch {
        const t = document.createElement("textarea");
        t.value = text; document.body.append(t); t.select(); document.execCommand("copy"); t.remove();
      }
      b.textContent = "Copied"; b.classList.add("done");
      setTimeout(() => { b.textContent = "Copy"; b.classList.remove("done"); }, 1600);
    });
  }

  const fmt = (n) => n.toLocaleString("en-US");
  const short = (n) => n >= 1e9 ? (n / 1e9).toFixed(2) + "B" : n >= 1e7 ? (n / 1e6).toFixed(1) + "M" : fmt(n);
  const ms = (n) => n >= 100 ? Math.round(n).toString() : n >= 10 ? n.toFixed(1) : n.toFixed(2);
  const uptime = (s) => {
    const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
    return "up " + (d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`);
  };

  // Each digit sits on a reel of 0 to 9, turned to it. When a number keeps
  // its shape only the reels turn; when it changes, it's rebuilt with each
  // reel where the digit in its place stood, counted from the right.
  const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const digit = (c) => c >= "0" && c <= "9";
  const shape = (s) => s.replace(/[0-9]/g, "0");
  const turn = (reel, d) => { reel.style.transform = `translateY(${-1.15 * d}em)`; };
  function show(id, text) {
    const el = document.getElementById(id);
    const was = el.dataset.v || "";
    if (was === text) return;
    el.dataset.v = text;
    el.setAttribute("aria-label", text);
    const chars = [...text];
    if (shape(was) !== shape(text) || !el.querySelector(".reel")) {
      const old = [...was];
      el.textContent = "";
      chars.forEach((c, i) => {
        const span = document.createElement("span");
        span.setAttribute("aria-hidden", "true");
        if (!digit(c)) { span.textContent = c; el.append(span); return; }
        span.className = "slot";
        const reel = document.createElement("span");
        reel.className = "reel";
        for (let n = 0; n < 10; n++) reel.append(Object.assign(document.createElement("span"), { textContent: n }));
        const before = old[old.length - chars.length + i];
        reel.style.transition = "none";
        turn(reel, digit(before || "") ? +before : 0);
        span.append(reel);
        el.append(span);
      });
      el.offsetHeight;
    }
    const reels = [...el.querySelectorAll(".reel")];
    const digits = chars.filter(digit);
    reels.forEach((reel, j) => {
      reel.style.transition = "";
      reel.style.transitionDelay = still ? "0s" : `${(reels.length - 1 - j) * 45}ms`;
      turn(reel, +digits[j]);
    });
  }

  const status = document.getElementById("status");
  const state = document.getElementById("state");
  const since = document.getElementById("since");
  async function tick() {
    if (document.hidden) return;
    try {
      const r = await fetch("stats", { cache: "no-store" });
      if (!r.ok) throw new Error(r.status);
      const s = await r.json();
      show("t-events", short(s.events));
      show("t-open", fmt(s.connections));
      show("t-answer", ms(s.answer_ms));
      show("t-requests", short(s.requests));
      since.textContent = uptime(s.uptime_secs);
      state.textContent = "Online";
      status.classList.remove("off");
    } catch {
      state.textContent = "Reconnecting";
      since.textContent = "";
      status.classList.add("off");
    }
  }
  tick();
  setInterval(tick, 5000);
  document.addEventListener("visibilitychange", tick);
})();
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn links_assets_at_the_origin() {
        assert_eq!(
            asset_url("https://relay.example", "/icon.png"),
            "https://relay.example/icon.png"
        );
        assert_eq!(
            asset_url("https://relay.example/", "/icon.png"),
            "https://relay.example/icon.png"
        );
        assert_eq!(
            asset_url("http://h:8080/a/b?c", "/icon.png"),
            "http://h:8080/icon.png"
        );
    }

    #[test]
    fn escapes_what_it_shows() {
        let html = render(
            &json!({"name": "<script>alert(1)</script>", "description": "\"quoted\" & more"}),
            "wss://relay.example/\"><script>",
        );
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(html.contains("&quot;quoted&quot; &amp; more"));
        assert!(html.contains(r#"data-copy="wss://relay.example/&quot;&gt;&lt;script&gt;""#));
        assert!(html.contains(r#"<code>wss://relay.example/&quot;&gt;&lt;script&gt;</code>"#));
    }

    #[test]
    fn links_only_safe_urls() {
        let html = render(
            &json!({"icon": "javascript:alert(1)", "banner": "https://x.example/b.jpg"}),
            "wss://x.example",
        );
        assert!(!html.contains("javascript:"));
        assert!(html.contains(r#"src="https://x.example/b.jpg""#));
        assert!(html.contains("summary_large_image"));
    }

    #[test]
    fn shows_the_version() {
        let html = render(&json!({"version": "2.0.0"}), "wss://x.example");
        assert!(html.contains(r#"<span class="version">v2.0.0</span>"#));
        assert!(!render(&json!({}), "wss://x.example").contains(r#"class="version""#));
    }

    #[test]
    fn sets_a_theme_color() {
        let html = render(&json!({}), "wss://x.example");
        assert!(html.contains(&format!(
            r#"<meta name="theme-color" content="{THEME_COLOR}">"#
        )));
    }

    #[test]
    fn shows_nips_limits_and_the_operator() {
        let pubkey = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
        let html = render(
            &json!({
                "supported_nips": [1, 77, 1234],
                "limitation": {"max_message_length": 131072, "max_limit": 5000, "created_at_upper_limit": 900},
                "pubkey": pubkey,
            }),
            "wss://x.example",
        );
        assert!(html.contains("<i>01</i> Basic protocol</a>"));
        assert!(html.contains("<i>77</i> Negentropy sync</a>"));
        assert!(html.contains("<i>1234</i></a>"));
        assert!(html.contains("<b>128 KiB</b>"));
        assert!(html.contains("<b>5,000</b>"));
        assert!(html.contains("<b>15 minutes</b>"));
        assert!(html.contains("npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6"));
        assert!(!render(&json!({}), "wss://x.example").contains("Who runs it"));
    }

    #[test]
    fn formats_numbers() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_234_567), "1,234,567");
        assert_eq!(bytes(1 << 20), "1 MiB");
        assert_eq!(bytes(4_000_000), "3.8 MiB");
        assert_eq!(bytes(1000), "1000 bytes");
        assert_eq!(seconds(3600), "1 hour");
        assert_eq!(seconds(90), "90 seconds");
        assert_eq!(bech32("npub", "zz"), None);
    }

    #[test]
    fn links_contacts() {
        assert_eq!(
            contact_html("a@b.co"),
            r#"<a href="mailto:a@b.co">a@b.co</a>"#
        );
        assert_eq!(
            contact_html("mailto:a@b.co"),
            r#"<a href="mailto:a@b.co">a@b.co</a>"#
        );
        assert!(contact_html("https://b.co/me").starts_with(r#"<a href="https://b.co/me""#));
        assert_eq!(
            contact_html("javascript:alert(1)//@x.com"),
            "javascript:alert(1)//@x.com"
        );
        assert_eq!(contact_html("npub1 <b>"), "npub1 &lt;b&gt;");
    }
}
