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

/// The landing page for the relay at `relay_url`, described by `info`.
pub fn render(info: &Value, relay_url: &str) -> String {
    let field = |key: &str| info[key].as_str().filter(|v| !v.is_empty());
    let name = esc(field("name").unwrap_or("Nostr Relay"));
    let description = field("description").map(esc);
    let icon = field("icon").and_then(|url| safe_url(url, HTTP));
    let banner = field("banner").and_then(|url| safe_url(url, HTTP));
    let contact = field("contact").map(contact_html);
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

    let top = match (&banner, &icon) {
        (Some(banner), icon) => {
            let icon = icon
                .as_ref()
                .map(|icon| format!(r#"<img class="icon" src="{icon}" alt="">"#))
                .unwrap_or_default();
            format!(
                r#"<div class="banner-wrap"><img class="banner-img" src="{banner}" alt=""></div>
    <div class="icon-row">{icon}</div>
    <div class="card-body">"#
            )
        }
        (None, Some(icon)) => format!(
            r#"<div class="no-banner-body"><div style="margin-bottom:16px"><img class="icon icon-static" src="{icon}" alt=""></div>"#
        ),
        (None, None) => r#"<div class="no-banner-body">"#.to_string(),
    };
    let description = description
        .map(|d| format!(r#"<p class="description">{d}</p>"#))
        .unwrap_or_default();
    let contact = contact
        .map(|c| format!(r#"<div class="meta"><span>{c}</span></div>"#))
        .unwrap_or_default();
    let version = version
        .map(|v| format!(r#" <span class="version">v{v}</span>"#))
        .unwrap_or_default();

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{name}</title>
  <link rel="icon" href="/favicon.ico">
  <meta property="og:type" content="website">
  <meta property="og:title" content="{name}">
  <meta name="twitter:card" content="{card}">
  <meta name="twitter:title" content="{name}">{head}
  <style>{STYLE}</style>
</head>
<body>
  <div class="card">
    {top}
      <h1 class="relay-name">{name}</h1>
      {description}
      {contact}
    </div>
    <div class="relay-url-wrap">
      <div class="relay-url-group">
        <input class="relay-url-input" type="text" value="{relay}" readonly>
        <button class="copy-btn" type="button" onclick="copyUrl(this)" aria-label="Copy relay URL">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
          <span class="label">Copy</span>
        </button>
      </div>
    </div>
  </div>
  <div class="footer"><a href="{REPOSITORY}" target="_blank" rel="noopener">Ditto Relay</a>{version}</div>
  <script>{SCRIPT}</script>
</body>
</html>
"#
    )
}

pub const REPOSITORY: &str = "https://gitworkshop.dev/soapbox.pub/ditto-relay";

const STYLE: &str = r#"
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    :root{--bg:#0a0a0c;--surface:#12121a;--border:#1e1e2e;--text:#e0e0e8;--text-dim:#7f7f96;--accent:#7c5cfc;--radius:16px}
    html{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
      background:var(--bg);color:var(--text);line-height:1.6;-webkit-font-smoothing:antialiased}
    body{min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:24px}
    .card{width:100%;max-width:600px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);overflow:visible}
    .banner-wrap{position:relative;aspect-ratio:21/9;overflow:hidden;border-radius:var(--radius) var(--radius) 0 0;background:var(--border)}
    .banner-img{width:100%;height:100%;object-fit:cover;display:block}
    .icon-row{position:relative;height:0}
    .icon{position:absolute;bottom:0;left:24px;transform:translateY(50%);width:80px;height:80px;border-radius:20px;
      border:4px solid var(--surface);object-fit:cover;background:var(--border);box-shadow:0 4px 24px #0004}
    .icon-static{position:static;transform:none;border-color:var(--border)}
    .card-body{padding:56px 24px 24px}
    .no-banner-body{padding:32px 24px 24px}
    .relay-name{font-size:1.4rem;font-weight:700;letter-spacing:-0.02em}
    .description{margin-top:8px;color:var(--text-dim);font-size:0.92rem;line-height:1.55}
    .meta{margin-top:12px;display:flex;flex-wrap:wrap;gap:6px 20px;font-size:0.82rem;color:var(--text-dim)}
    .meta a{color:var(--accent);text-decoration:none}
    .meta a:hover{text-decoration:underline}
    .version{opacity:0.7}
    .relay-url-wrap{padding:0 24px 24px}
    .relay-url-group{display:flex;align-items:center;background:#0a0a0c;border:1px solid var(--border);
      border-radius:100px;overflow:hidden;transition:border-color .15s}
    .relay-url-group:hover{border-color:#2a2a40}
    .relay-url-group:focus-within{border-color:var(--accent);box-shadow:0 0 0 2px rgba(124,92,252,0.15)}
    .relay-url-input{flex:1;background:none;border:none;color:var(--text);font-size:0.88rem;
      padding:12px 0 12px 20px;outline:none;font-family:inherit;min-width:0;letter-spacing:0.01em}
    .relay-url-input::selection{background:rgba(124,92,252,0.3)}
    .copy-btn{display:flex;align-items:center;gap:6px;background:none;border:none;color:var(--text-dim);
      cursor:pointer;padding:10px 16px 10px 12px;font-size:0.78rem;font-family:inherit;
      border-radius:0 100px 100px 0;transition:color .15s,background .15s;white-space:nowrap;letter-spacing:0.02em}
    .copy-btn:hover{color:var(--text);background:rgba(255,255,255,0.04)}
    .copy-btn:active{background:rgba(255,255,255,0.07)}
    .copy-btn svg{width:16px;height:16px;flex-shrink:0}
    .copy-btn .label{transition:opacity .1s}
    .footer{margin-top:24px;text-align:center;color:var(--text-dim);font-size:0.7rem}
    .footer a{color:inherit;text-decoration:none}
    .footer a:hover{text-decoration:underline}
  "#;

const SCRIPT: &str = r#"
    function copyUrl(btn){
      var input=btn.parentNode.querySelector('.relay-url-input');
      navigator.clipboard.writeText(input.value).then(function(){
        var label=btn.querySelector('.label');
        label.textContent='Copied!';
        btn.style.color='var(--accent)';
        setTimeout(function(){label.textContent='Copy';btn.style.color='';},1500);
      });
    }
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
        assert!(html.contains(r#"value="wss://relay.example/&quot;&gt;&lt;script&gt;""#));
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
