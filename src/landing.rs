//! The HTML page a browser sees at the relay's address, rendered once from
//! its NIP-11 information document, and the images it shows.

use serde_json::Value;

pub const FAVICON: &[u8] = include_bytes!("../assets/favicon.ico");
pub const ICON: &[u8] = include_bytes!("../assets/icon.png");
pub const BANNER: &[u8] = include_bytes!("../assets/banner.jpg");
/// What a link to the page is previewed with: the silk, with the name.
pub const OG_IMAGE: &[u8] = include_bytes!("../assets/og.jpg");

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
/// The colour browsers that heed `theme-color` paint their own frame in:
/// the silk's, at the top of the page, so the two run together.
pub const THEME_COLOR: &str = "#3f1a6a";

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

/// Where a profile's kind 0 is looked for, after the relay itself.
const PROFILE_RELAYS: [&str; 2] = ["wss://relay.ditto.pub", "wss://purplepag.es"];

/// Who runs it, if NIP-11 says: a link to their Ditto profile, which the
/// page fills in with their name and picture from their kind 0, looked for
/// on the relay itself, then, unless it's an onion, on a couple of others.
fn operator_html(info: &Value, relay_url: &str) -> String {
    let Some((pubkey, npub)) = info["pubkey"]
        .as_str()
        .and_then(|pk| Some((pk, bech32("npub", pk)?)))
    else {
        return String::new();
    };
    let mut relays = vec![relay_url];
    if !relay_url.contains(".onion") {
        relays.extend(PROFILE_RELAYS);
    }
    let relays = esc(&serde_json::to_string(&relays).expect("strings serialize"));
    let short = format!("{}…{}", &npub[..12], &npub[npub.len() - 6..]);
    let pubkey = esc(pubkey);
    format!(
        r#"<a class="op glass" id="op" href="https://ditto.pub/{npub}" target="_blank" rel="noopener" data-pubkey="{pubkey}" data-relays="{relays}"><span class="avatar"><img alt="" referrerpolicy="no-referrer" hidden></span><span class="op-text"><span class="op-label">Run by</span><span class="op-name">{short}</span></span></a>"#
    )
}

/// The landing page for the relay at `relay_url`, described by `info`, its
/// links previewed with `og_image`, else its banner, else its icon.
pub fn render(info: &Value, relay_url: &str, og_image: Option<&str>) -> String {
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
    let og_image = og_image.and_then(|url| safe_url(url, HTTP));
    if let Some(image) = og_image.as_ref().or(banner.as_ref()).or(icon.as_ref()) {
        head += &format!(
            r#"
  <meta property="og:image" content="{image}">
  <meta name="twitter:image" content="{image}">"#
        );
    }
    let card = if og_image.is_some() || banner.is_some() {
        "summary_large_image"
    } else {
        "summary"
    };

    let icon = icon
        .map(|i| format!(r#"<img class="icon" src="{i}" alt="">"#))
        .unwrap_or_default();
    let description = description
        .map(|d| format!(r#"<p class="lead">{d}</p>"#))
        .unwrap_or_default();
    let version = version
        .map(|v| format!(r#" <span class="version">v{v}</span>"#))
        .unwrap_or_default();
    let contact = contact
        .map(|c| format!(r#"<span class="sep">·</span><span class="contact">{c}</span>"#))
        .unwrap_or_default();
    let operator = operator_html(info, relay_url);

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
<canvas class="silk" aria-hidden="true"></canvas>
<div class="page">
  <main class="hero">
    {icon}
    <h1>{name}</h1>
    {description}
    <div class="addr glass"><code>{relay}</code><button class="copy" type="button" data-copy="{relay}">Copy</button></div>
    <div class="status" id="status"><span class="dot"></span><span id="state">Online</span><span id="since"></span></div>
    <section class="stats glass" aria-label="Live numbers">
      <div class="stat"><span class="v roll" id="t-events">–</span><span class="k">Events</span></div>
      <div class="stat"><span class="v roll" id="t-open">–</span><span class="k">Connected</span></div>
      <div class="stat"><span class="v"><span class="roll" id="t-answer">–</span><small>ms</small></span><span class="k">Response</span></div>
      <div class="stat"><span class="v roll" id="t-requests">–</span><span class="k">Requests</span></div>
    </section>
    {operator}
  </main>
  <footer><a href="{REPOSITORY}" target="_blank" rel="noopener">Ditto Relay</a>{version}{contact}</footer>
</div>
<script>{SILK}</script>
<script>{SCRIPT}</script>
</body>
</html>
"#
    )
}

pub const REPOSITORY: &str = "https://gitworkshop.dev/soapbox.pub/ditto-relay";

const STYLE: &str = r#"
:root{--text-2:rgba(255,255,255,.8);--text-3:rgba(255,255,255,.62);--shade:rgba(20,4,50,.5);
  --font:-apple-system,BlinkMacSystemFont,"SF Pro Display","Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;--ease:cubic-bezier(.22,1,.36,1);color-scheme:dark}
*,*::before,*::after{box-sizing:border-box}
html{background:#3f1a6a linear-gradient(180deg,#3f1a6a,#5a24ad 45%,#7b3bd2) fixed}
body{margin:0;min-height:100vh;color:#fff;font-family:var(--font);line-height:1.5;
  -webkit-font-smoothing:antialiased;-webkit-text-size-adjust:100%}
.silk{position:fixed;inset:0;width:100%;height:100%;pointer-events:none;opacity:0;transition:opacity .8s ease}
.silk.ready{opacity:1}
.page{position:relative;min-height:100svh;display:grid;grid-template-rows:1fr auto;
  padding:env(safe-area-inset-top) max(20px,env(safe-area-inset-right)) env(safe-area-inset-bottom) max(20px,env(safe-area-inset-left))}
.hero{display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:88px 0 40px}
.glass{background:rgba(24,8,52,.26);border:1px solid rgba(255,255,255,.16);
  -webkit-backdrop-filter:blur(30px) saturate(115%);backdrop-filter:blur(30px) saturate(115%);
  box-shadow:0 16px 48px rgba(20,4,50,.3),inset 0 1px 0 rgba(255,255,255,.1)}
.icon{width:72px;height:72px;border-radius:18px;object-fit:cover;margin-bottom:28px;
  box-shadow:0 0 0 1px rgba(255,255,255,.22),0 12px 40px rgba(20,4,50,.45)}
h1{margin:0;max-width:12ch;font-size:clamp(3rem,10vw,7.5rem);font-weight:800;line-height:.98;letter-spacing:-.045em;
  overflow-wrap:anywhere;text-shadow:0 2px 4px rgba(20,4,50,.45),0 6px 30px rgba(20,4,50,.55)}
.lead{margin:22px 0 0;max-width:38ch;font-size:clamp(1.05rem,2.2vw,1.3rem);line-height:1.45;color:var(--text-2);
  text-shadow:0 1px 14px var(--shade)}
.addr{margin-top:44px;display:flex;align-items:center;gap:10px;max-width:100%;padding:6px 6px 6px 22px;border-radius:999px}
.addr code{font-family:var(--mono);font-size:.95rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0}
.copy{flex:none;font:inherit;font-size:.9rem;font-weight:600;color:#3f1a6a;background:#fff;border:0;border-radius:999px;
  padding:10px 18px;cursor:pointer;transition:background .2s var(--ease),transform .15s var(--ease)}
.copy:hover{background:rgba(255,255,255,.86)}
.copy:active{transform:scale(.96)}
.status{margin-top:16px;display:inline-flex;align-items:center;gap:8px;font-size:.86rem;color:var(--text-3);text-shadow:0 1px 10px var(--shade)}
.status #since:not(:empty)::before{content:"·";margin-right:8px}
.dot{width:7px;height:7px;border-radius:50%;background:#7cf5c0;box-shadow:0 0 10px #7cf5c0;animation:breathe 2.8s ease-in-out infinite}
.status.off .dot{background:#fcd36a;box-shadow:0 0 10px #fcd36a;animation:none}
@keyframes breathe{50%{opacity:.45}}
.stats{margin-top:56px;display:grid;grid-template-columns:repeat(4,minmax(0,1fr));border-radius:24px;width:min(100%,640px)}
.stat{display:grid;gap:2px;padding:18px 12px}
.stat+.stat{border-left:1px solid rgba(255,255,255,.14)}
.stat .v{font-size:clamp(1.4rem,3.2vw,2rem);font-weight:700;line-height:1.15;letter-spacing:-.02em;font-variant-numeric:tabular-nums;white-space:nowrap}
.stat .v small{font-size:.5em;font-weight:500;color:var(--text-3);margin-left:2px}
.stat .k{font-size:.76rem;color:var(--text-3)}
.roll{display:inline-flex;justify-content:center}
.slot{display:inline-block;height:1.15em;overflow:hidden;vertical-align:top}
.reel{display:block;transition:transform 1.1s var(--ease)}
.reel span{display:block;height:1.15em}
.op{margin-top:28px;display:inline-flex;align-items:center;gap:12px;padding:6px 20px 6px 6px;border-radius:999px;
  color:#fff;text-decoration:none;text-align:left;transition:background .2s var(--ease),transform .2s var(--ease)}
.op:hover{background:rgba(24,8,52,.4);transform:translateY(-1px)}
.avatar{width:38px;height:38px;flex:none;border-radius:50%;overflow:hidden;background:linear-gradient(135deg,#c9a6ff,#5a24ad)}
.avatar img{width:100%;height:100%;object-fit:cover;display:block}
.op-text{display:grid;line-height:1.2}
.op-label{font-size:.72rem;color:var(--text-3)}
.op-name{font-size:.95rem;font-weight:600;max-width:22ch;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
footer{padding:24px 0 28px;text-align:center;font-size:.78rem;color:rgba(255,255,255,.55)}
footer a{color:inherit;text-decoration:none}
footer a:hover{color:#fff}
.sep{margin:0 8px}
@media (max-width:600px){
  .hero{padding-top:64px}
  .addr{padding-left:16px}
  .addr code{font-size:.82rem}
  .stats{grid-template-columns:repeat(2,minmax(0,1fr))}
  .stat:nth-child(3){border-left:0}
  .stat:nth-child(n+3){border-top:1px solid rgba(255,255,255,.14)}
}
@media (prefers-reduced-motion:reduce){.dot{animation:none}.reel,.copy,.op{transition:none}}
"#;

/// Din's default wallpaper as a shader, from din-website's hero: purple silk
/// rippling slowly, with strands of light and sparkles along them, which the
/// pointer presses into and lights. The page's own background shows where
/// there's no WebGL.
const SILK: &str = r#"
(() => {
  const canvas = document.querySelector(".silk");
  const gl = canvas.getContext("webgl", { antialias: false, premultipliedAlpha: false });
  if (!gl) return;
  const reduce = matchMedia("(prefers-reduced-motion: reduce)");

  const VERT = "attribute vec2 pos; void main() { gl_Position = vec4(pos, 0.0, 1.0); }";
  const FRAG = `
    precision highp float;
    uniform vec2 res;
    uniform float time;
    uniform vec2 mouse;   // in p space
    uniform float press;  // 0..1, how present the pointer is
    uniform vec2 text;    // the headline's center, in uv (y down)

    const vec3 DEEP = vec3(0.27, 0.04, 0.60);
    const vec3 MID = vec3(0.49, 0.21, 0.81);
    const vec3 LIGHT = vec3(0.72, 0.44, 0.98);
    const vec3 GLINT = vec3(1.00, 0.93, 1.00);

    float hash(vec2 p) { return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453); }

    // The silk's height: long waves running across, bent by the pointer.
    float silk(vec2 p, float t) {
      float v = p.y;
      v += 0.15 * sin(p.x * 2.1 + t * 0.2 + 1.3);
      v += 0.05 * sin(p.x * 3.3 - t * 0.15 + p.y * 1.2);
      v += 0.02 * sin(p.x * 6.1 + t * 0.27 + p.y * 2.3);
      vec2 d = p - mouse;
      v += press * 0.11 * exp(-dot(d, d) / 0.05);
      return v;
    }

    float strand(float v, float at, float width) { float d = (v - at) / width; return exp(-d * d); }

    float strandY(float x, float y, float at, float wob, float t) {
      float off = silk(vec2(x, y), t) - y + wob;
      float y1 = at - off;
      return at - (silk(vec2(x, y1), t) - y1 + wob);
    }

    float sparkle(vec2 d, float size) {
      d /= size;
      float core = exp(-dot(d, d) * 0.5);
      float rays = exp(-abs(d.x) * 2.0) * exp(-abs(d.y) * 0.25) + exp(-abs(d.y) * 2.0) * exp(-abs(d.x) * 0.25);
      float halo = exp(-dot(d, d) * 0.04);
      return core + rays * 0.5 + halo * 0.18;
    }

    void main() {
      vec2 uv = gl_FragCoord.xy / res;
      float aspect = res.x / res.y;
      vec2 p = vec2(uv.x * aspect, uv.y);
      float t = time;
      float px = 1.0 / res.y;

      float v = silk(p, t);

      vec2 e = vec2(0.002, 0.0);
      vec2 grad = vec2(silk(p + e.xy, t) - silk(p - e.xy, t), silk(p + e.yx, t) - silk(p - e.yx, t)) / 0.004;
      vec3 n = normalize(vec3(-grad * 0.6, 1.0));
      vec3 l = normalize(vec3(mouse - p, 0.7));
      float diffuse = max(dot(n, l), 0.0);

      float fold = 0.5 + 0.5 * sin(v * 9.0 + 0.9 * sin(p.x * 1.1 + t * 0.12) - 2.2);
      vec3 col = mix(DEEP, MID, smoothstep(0.0, 1.0, fold));
      col = mix(col, LIGHT, pow(fold, 3.0) * 0.55);

      float v2 = p.y - 0.25 * p.x + 0.07 * sin(p.x * 2.6 - t * 0.18 + 0.5) + 0.04 * sin(p.x * 4.4 + t * 0.22);
      float wisp = 0.5 + 0.5 * sin(v2 * 13.0 + 1.5 * sin(p.x * 0.7 + t * 0.1));
      float wisps = pow(wisp, 3.0) * (0.5 + 0.5 * sin(p.x * 1.6 - v2 * 3.0 + t * 0.09));
      col = mix(col, LIGHT, wisps * 0.4);
      float sheen = pow(0.5 + 0.5 * sin(v * 22.0 - p.x * 1.4 + t * 0.15), 8.0);
      col += LIGHT * sheen * 0.06;

      col *= 0.78 + 0.4 * diffuse;

      vec2 corner = vec2(p.x / aspect, 1.0 - p.y);
      col *= 1.0 - 0.3 * exp(-dot(corner, corner) * 3.0);

      float glow = 0.0;
      float lines = 0.0;
      float spark = 0.0;
      for (int i = 0; i < 4; i++) {
        float fi = float(i);
        float at = 0.1 + fi * 0.25;
        float wob = 0.02 * sin(p.x * 3.0 + fi * 2.0 + t * 0.3);
        float fade = smoothstep(0.1, 0.8, sin(p.x * 1.2 + fi * 2.1 + t * 0.06) * 0.5 + 0.5);
        float sv = v + wob;
        lines += strand(sv, at, 0.0028) * fade;
        glow += strand(sv, at, 0.04) * fade;

        if (abs(sv - at) > 0.05) continue;
        float cw = 0.11;
        float c = floor(p.x / cw);
        float h = hash(vec2(c, fi));
        if (h < 0.45) {
          float sx = (c + 0.3 + 0.4 * hash(vec2(c, fi + 9.0))) * cw;
          float swob = 0.02 * sin(sx * 3.0 + fi * 2.0 + t * 0.3);
          float sfade = smoothstep(0.1, 0.8, sin(sx * 1.2 + fi * 2.1 + t * 0.06) * 0.5 + 0.5);
          vec2 at2 = vec2(sx, strandY(sx, p.y, at, swob, t));
          float tw = 0.35 + 0.65 * pow(0.5 + 0.5 * sin(t * (0.8 + h * 2.5) + h * 50.0), 2.0);
          float size = (1.5 + 3.5 * hash(vec2(c, fi + 4.0))) * px;
          spark += sparkle(p - at2, size) * tw * sfade;
        }
      }
      col += LIGHT * glow * 0.14 + GLINT * lines * 0.45 + GLINT * spark;

      vec2 dm = p - mouse;
      col += mix(MID, LIGHT, 0.4) * press * 0.4 * exp(-dot(dm, dm) / 0.04);

      // Deeper behind the headline, and toward the top, so the words stand out.
      vec2 dt = (uv - vec2(text.x, 1.0 - text.y)) * vec2(1.3, 2.4);
      col *= 1.0 - 0.25 * exp(-dot(dt, dt) * 2.2);
      col = mix(col, DEEP * 0.8, smoothstep(0.75, 1.0, uv.y) * 0.3);

      gl_FragColor = vec4(col, 1.0);
    }
  `;

  const shader = (type, src) => {
    const s = gl.createShader(type);
    gl.shaderSource(s, src);
    gl.compileShader(s);
    if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(s) || "shader");
    return s;
  };
  const prog = gl.createProgram();
  gl.attachShader(prog, shader(gl.VERTEX_SHADER, VERT));
  gl.attachShader(prog, shader(gl.FRAGMENT_SHADER, FRAG));
  gl.linkProgram(prog);
  gl.useProgram(prog);
  gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer());
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
  const pos = gl.getAttribLocation(prog, "pos");
  gl.enableVertexAttribArray(pos);
  gl.vertexAttribPointer(pos, 2, gl.FLOAT, false, 0, 0);
  const u = (name) => gl.getUniformLocation(prog, name);
  const uRes = u("res"), uTime = u("time"), uMouse = u("mouse"), uPress = u("press"), uText = u("text");

  const headline = document.querySelector("h1");
  let w = 1, h = 1, text = [0.5, 0.3];
  const place = () => {
    if (!headline) return;
    const t = headline.getBoundingClientRect();
    text = [(t.left + t.width / 2) / w, (t.top + t.height / 2) / h];
  };
  const size = () => {
    // Soft enough to draw at one pixel per CSS pixel, even on HiDPI screens.
    w = canvas.clientWidth;
    h = canvas.clientHeight;
    canvas.width = Math.max(1, Math.round(w));
    canvas.height = Math.max(1, Math.round(h));
    gl.viewport(0, 0, canvas.width, canvas.height);
    place();
  };

  // The pointer, as a fraction of the screen, easing toward where it is.
  let mx = 0.7, my = 0.3, tx = mx, ty = my, press = 0, pressTarget = 0, frame = 0;
  const start = performance.now();
  const draw = (now) => {
    mx += (tx - mx) * 0.08;
    my += (ty - my) * 0.08;
    press += (pressTarget - press) * 0.05;
    gl.uniform2f(uRes, canvas.width, canvas.height);
    gl.uniform1f(uTime, reduce.matches ? 20 : (now - start) / 1000);
    gl.uniform2f(uMouse, mx * (w / h), 1 - my);
    gl.uniform1f(uPress, press);
    gl.uniform2f(uText, text[0], text[1]);
    gl.drawArrays(gl.TRIANGLES, 0, 3);
  };
  const tick = (now) => {
    frame = 0;
    draw(now);
    const settling = Math.abs(tx - mx) + Math.abs(ty - my) > 0.001 || Math.abs(pressTarget - press) > 0.01;
    if (!reduce.matches || settling) schedule();
  };
  const schedule = () => { if (!frame && !document.hidden) frame = requestAnimationFrame(tick); };

  addEventListener("pointermove", (e) => {
    tx = e.clientX / w;
    ty = e.clientY / h;
    pressTarget = e.pointerType === "mouse" ? 1 : 0.6;
    schedule();
  });
  document.documentElement.addEventListener("pointerleave", () => { pressTarget = 0; schedule(); });
  addEventListener("scroll", () => { place(); schedule(); }, { passive: true });
  new ResizeObserver(() => { size(); draw(performance.now()); }).observe(canvas);
  document.addEventListener("visibilitychange", schedule);
  size();
  schedule();
  canvas.classList.add("ready");
})();
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
      b.textContent = "Copied";
      setTimeout(() => { b.textContent = "Copy"; }, 1600);
    });
  }

  // The operator's name and picture, from the newest kind 0 the first relay
  // to have one answers with.
  const op = document.getElementById("op");
  if (op) {
    const pubkey = op.dataset.pubkey;
    const profile = (url) => new Promise((resolve) => {
      let ws, best = null, timer;
      const done = () => { clearTimeout(timer); try { ws.close(); } catch {} resolve(best); };
      try { ws = new WebSocket(url); } catch { return resolve(null); }
      timer = setTimeout(done, 4000);
      ws.onopen = () => ws.send(JSON.stringify(["REQ", "p", { kinds: [0], authors: [pubkey], limit: 1 }]));
      ws.onmessage = (e) => {
        let m;
        try { m = JSON.parse(e.data); } catch { return; }
        const ev = m[2];
        if (m[0] === "EVENT" && ev && ev.kind === 0 && ev.pubkey === pubkey && (!best || ev.created_at > best.created_at)) best = ev;
        if (m[0] === "EOSE" || m[0] === "CLOSED") done();
      };
      ws.onerror = done;
    });
    (async () => {
      for (const url of JSON.parse(op.dataset.relays)) {
        const ev = await profile(url);
        if (!ev) continue;
        let meta;
        try { meta = JSON.parse(ev.content); } catch { continue; }
        const name = [meta.display_name, meta.name].find((n) => typeof n === "string" && n.trim());
        if (name) op.querySelector(".op-name").textContent = name.trim();
        if (typeof meta.picture === "string" && /^https:\/\//i.test(meta.picture)) {
          const img = op.querySelector("img");
          img.onload = () => { img.hidden = false; };
          img.src = meta.picture;
        }
        return;
      }
    })();
  }

  const fmt = (n) => n.toLocaleString("en-US");
  const short = (n) => n >= 1e9 ? (n / 1e9).toFixed(2) + "B" : n >= 1e6 ? (n / 1e6).toFixed(1) + "M" : n >= 1e5 ? Math.round(n / 1e3) + "K" : fmt(n);
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
            None,
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
            None,
        );
        assert!(!html.contains("javascript:"));
        assert!(html.contains(r#"content="https://x.example/b.jpg""#));
        assert!(html.contains("summary_large_image"));
    }

    #[test]
    fn shows_the_version() {
        let html = render(&json!({"version": "2.0.0"}), "wss://x.example", None);
        assert!(html.contains(r#"<span class="version">v2.0.0</span>"#));
        assert!(!render(&json!({}), "wss://x.example", None).contains(r#"class="version""#));
    }

    #[test]
    fn sets_a_theme_color() {
        let html = render(&json!({}), "wss://x.example", None);
        assert!(html.contains(&format!(
            r#"<meta name="theme-color" content="{THEME_COLOR}">"#
        )));
    }

    #[test]
    fn previews_links_with_the_og_image() {
        let info = json!({"banner": "https://x.example/b.jpg"});
        let html = render(&info, "wss://x.example", Some("https://x.example/og.jpg"));
        assert!(html.contains(r#"<meta property="og:image" content="https://x.example/og.jpg">"#));
        assert!(html.contains("summary_large_image"));
        let html = render(&info, "wss://x.example", None);
        assert!(html.contains(r#"<meta property="og:image" content="https://x.example/b.jpg">"#));
    }

    #[test]
    fn links_the_operator() {
        let pubkey = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
        let npub = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";
        let html = render(&json!({"pubkey": pubkey}), "wss://x.example", None);
        assert!(html.contains(&format!(r#"href="https://ditto.pub/{npub}""#)));
        assert!(html.contains(&format!(r#"data-pubkey="{pubkey}""#)));
        assert!(html.contains(r#"<span class="op-name">npub180cvv07…yjh6w6</span>"#));
        assert!(html.contains("relay.ditto.pub"));
        // Over the onion, it's looked for on the onion alone.
        let onion = render(&json!({"pubkey": pubkey}), "ws://x.onion", None);
        assert!(!onion.contains("relay.ditto.pub"));
        assert!(!render(&json!({}), "wss://x.example", None).contains(r#"id="op""#));
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
