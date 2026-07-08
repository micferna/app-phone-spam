//! Pages HTML publiques (accueil + confirmations).

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub fn confirmation_page(title: &str, body_html: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{t}</title>
<style>:root{{color-scheme:light dark;}}
body{{font:17px/1.6 system-ui,sans-serif;max-width:560px;margin:0 auto;padding:56px 24px;}}
a{{color:#c43c2e;}}</style></head>
<body><h1>{t}</h1><p>{b}</p><p><a href="/">← Retour à l'accueil</a></p></body></html>"#,
        t = escape_html(title),
        b = body_html
    )
}

pub fn landing_page(numbers: i64, prefixes: i64, users: i64) -> String {
    format!(
        r#"<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Anti-Spam Collectif</title>
<style>
  :root {{ color-scheme: light dark;
    --bg:#fdfaf7; --fg:#2b2320; --muted:#8a7a72; --accent:#c43c2e;
    --card:#f4ece6; --border:#e5d8cf; }}
  @media (prefers-color-scheme: dark) {{ :root {{
    --bg:#191412; --fg:#ece4de; --muted:#a08d84; --accent:#e05548;
    --card:#231c19; --border:#372c27; }} }}
  * {{ margin:0; box-sizing:border-box; }}
  body {{ background:var(--bg); color:var(--fg);
    font:17px/1.65 system-ui, sans-serif; max-width:680px; margin:0 auto; padding:48px 24px; }}
  h1 {{ font-size:2rem; line-height:1.2; letter-spacing:-.02em; }}
  h1 span {{ color:var(--accent); }}
  .pitch {{ color:var(--muted); margin:12px 0 32px; font-size:1.05rem; }}
  .stats {{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:36px; }}
  .stat {{ background:var(--card); border:1px solid var(--border);
    border-radius:12px; padding:14px 20px; flex:1; min-width:150px; }}
  .stat b {{ display:block; font-size:1.6rem; }}
  .stat small {{ color:var(--muted); }}
  h2 {{ font-size:1.1rem; margin:28px 0 10px; }}
  ol {{ padding-left:22px; }} li {{ margin-bottom:8px; }}
  a {{ color:var(--accent); }}
  .foot {{ margin-top:40px; padding-top:20px; border-top:1px solid var(--border);
    color:var(--muted); font-size:.9rem; }}
  code {{ background:var(--card); padding:2px 6px; border-radius:6px; font-size:.88em; }}
  form {{ display:flex; flex-direction:column; gap:10px; margin-top:12px; }}
  input, textarea {{ font:inherit; padding:10px 12px; border-radius:10px;
    border:1px solid var(--border); background:var(--card); color:var(--fg); }}
  textarea {{ resize:vertical; min-height:64px; }}
  button {{ font:inherit; font-weight:600; padding:12px; border:none;
    border-radius:10px; background:var(--accent); color:#fff; cursor:pointer; }}
</style>
</head>
<body>
<h1>📵 Anti-Spam <span>Collectif</span></h1>
<p class="pitch">Le démarchage harcèle chacun de nous séparément. Ici, un seul
signalement protège tout le groupe : quand quelqu'un signale un numéro, tous
les téléphones sont alertés dès que ce numéro rappelle.</p>

<div class="stats">
  <div class="stat"><b>{numbers}</b><small>numéros signalés par le groupe</small></div>
  <div class="stat"><b>{prefixes}</b><small>préfixes suivis (ARCEP + listes publiques)</small></div>
  <div class="stat"><b>{users}</b><small>membres protégés</small></div>
</div>

<h2>Comment ça marche</h2>
<ol>
  <li>Installe l'app Android et entre ta clé personnelle.</li>
  <li>À chaque appel entrant, ton téléphone vérifie le numéro ici : s'il est
      connu, tu vois <em>« ⚠️ Signalé par N personnes »</em> pendant la sonnerie.</li>
  <li>Numéro inconnu et c'était du démarchage ? Un bouton <em>« Signaler »</em>
      dans la notification, et tout le groupe est protégé.</li>
</ol>

<h2>Rejoindre le groupe</h2>
<p>L'accès se fait sur invitation (une clé par membre). Envoie une demande,
l'administrateur te transmettra ta clé.</p>
<form method="POST" action="/api/join-requests">
  <input name="name" maxlength="64" required placeholder="Prénom ou pseudo" autocomplete="off">
  <input name="contact" maxlength="128" placeholder="Comment te joindre ? (Signal, e-mail, tel…)" autocomplete="off">
  <textarea name="message" maxlength="280" placeholder="Un mot (facultatif)…"></textarea>
  <button type="submit">Envoyer ma demande</button>
</form>

<h2>Code source</h2>
<p>Projet libre :
<a href="https://github.com/micferna/app-phone-spam">github.com/micferna/app-phone-spam</a>
— backend Rust (axum) + SQLite, app Flutter. Auto-hébergeable.</p>

<p class="foot">API : <code>GET /api/health</code> ·
<code>GET /api/lookup/:numero</code> · <code>POST /api/reports</code>
— accès sur invitation.</p>
</body>
</html>"#,
        numbers = numbers,
        prefixes = prefixes,
        users = users
    )
}
