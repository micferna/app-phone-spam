//! Pages HTML publiques (accueil + confirmations).

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

const ADMIN_STYLE: &str = r#"<style>
:root{color-scheme:light dark;--bg:#fdfaf7;--fg:#2b2320;--muted:#8a7a72;
--accent:#c43c2e;--card:#f4ece6;--border:#e5d8cf;}
@media(prefers-color-scheme:dark){:root{--bg:#191412;--fg:#ece4de;--muted:#a08d84;
--accent:#e05548;--card:#231c19;--border:#372c27;}}
*{margin:0;box-sizing:border-box;}
body{background:var(--bg);color:var(--fg);font:16px/1.6 system-ui,sans-serif;
max-width:900px;margin:0 auto;padding:32px 20px;}
h1{font-size:1.6rem;} h2{font-size:1.1rem;margin:28px 0 10px;}
.grid{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0;}
.kpi{background:var(--card);border:1px solid var(--border);border-radius:12px;
padding:14px 18px;flex:1;min-width:130px;}
.kpi b{display:block;font-size:1.7rem;} .kpi small{color:var(--muted);}
table{width:100%;border-collapse:collapse;margin-top:8px;}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--border);font-size:.92rem;}
th{color:var(--muted);font-weight:600;}
.tag{background:var(--accent);color:#fff;border-radius:6px;padding:1px 7px;font-size:.8rem;}
input,button{font:inherit;padding:11px 13px;border-radius:10px;border:1px solid var(--border);}
button{background:var(--accent);color:#fff;border:none;cursor:pointer;font-weight:600;}
form.rf{display:inline;} .muted{color:var(--muted);}
</style>"#;

pub fn admin_login_page(error: bool) -> String {
    let msg = if error {
        "<p style=\"color:#c43c2e\">Clé admin invalide.</p>"
    } else {
        ""
    };
    format!(
        r#"<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Admin — Anti-Spam</title>{style}</head>
<body><h1>🔐 Dashboard admin</h1>{msg}
<form method="POST" action="/admin" style="margin-top:16px;display:flex;gap:10px;max-width:420px">
  <input name="key" type="password" placeholder="Clé admin" autocomplete="off" style="flex:1">
  <button type="submit">Entrer</button>
</form></body></html>"#,
        style = ADMIN_STYLE,
        msg = msg
    )
}

pub fn admin_dashboard_page(s: &serde_json::Value, key: &str) -> String {
    let n = |k: &str| s.get(k).and_then(|v| v.as_i64()).unwrap_or(0);
    let kpi = |label: &str, val: i64| {
        format!("<div class=\"kpi\"><b>{val}</b><small>{label}</small></div>")
    };

    let mut ops = String::new();
    if let Some(arr) = s.get("topOperators").and_then(|v| v.as_array()) {
        for o in arr {
            let name = o.get("name").and_then(|v| v.as_str());
            let mnemo = o.get("mnemo").and_then(|v| v.as_str()).unwrap_or("");
            let c = o.get("count").and_then(|v| v.as_i64()).unwrap_or(0);
            let label = name
                .map(|x| x.to_string())
                .unwrap_or_else(|| mnemo.to_string());
            ops.push_str(&format!(
                "<tr><td>{}</td><td>{}</td></tr>",
                escape_html(&label),
                c
            ));
        }
    }
    if ops.is_empty() {
        ops = "<tr><td colspan=2 class=muted>—</td></tr>".into();
    }

    let mut camps = String::new();
    if let Some(arr) = s.get("activeCampaigns").and_then(|v| v.as_array()) {
        for c in arr {
            let p = c.get("prefix").and_then(|v| v.as_str()).unwrap_or("");
            let cnt = c.get("count").and_then(|v| v.as_i64()).unwrap_or(0);
            camps.push_str(&format!(
                "<tr><td>{}xx…</td><td><span class=tag>{} numéros / 24 h</span></td></tr>",
                escape_html(p),
                cnt
            ));
        }
    }
    if camps.is_empty() {
        camps = "<tr><td colspan=2 class=muted>Aucune campagne active</td></tr>".into();
    }

    let mut recent = String::new();
    if let Some(arr) = s.get("recentReports").and_then(|v| v.as_array()) {
        for r in arr {
            let num = r.get("number").and_then(|v| v.as_str()).unwrap_or("");
            let c = r.get("reportCount").and_then(|v| v.as_i64()).unwrap_or(0);
            let last = r.get("lastReport").and_then(|v| v.as_str()).unwrap_or("");
            recent.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td class=muted>{}</td></tr>",
                escape_html(num),
                c,
                escape_html(last)
            ));
        }
    }
    if recent.is_empty() {
        recent = "<tr><td colspan=3 class=muted>—</td></tr>".into();
    }

    format!(
        r#"<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Admin — Anti-Spam</title>{style}</head>
<body>
<h1>📊 Dashboard admin</h1>
<div class="grid">
  {k1}{k2}{k3}{k4}
</div>
<div class="grid">
  {k5}{k6}{k7}{k8}
</div>

<h2>⚡ Campagnes actives (pics de signalements sur une plage, 24 h)</h2>
<table><tr><th>Plage</th><th>Activité</th></tr>{camps}</table>

<h2>📞 Top opérateurs (grossistes concentrant le spam)</h2>
<table><tr><th>Opérateur</th><th>Numéros signalés</th></tr>{ops}</table>

<h2>🕑 Signalements récents</h2>
<table><tr><th>Numéro</th><th>Signalé</th><th>Dernier</th></tr>{recent}</table>

<p style="margin-top:24px">
  <form class="rf" method="POST" action="/admin">
    <input type="hidden" name="key" value="{key}">
    <button type="submit">↻ Rafraîchir</button>
  </form>
  <span class="muted"> · Feedback : {fbs} spam / {fbo} légitime</span>
</p>
</body></html>"#,
        style = ADMIN_STYLE,
        k1 = kpi("membres", n("members")),
        k2 = kpi("numéros signalés", n("reportedNumbers")),
        k3 = kpi("signalements (24 h)", n("reportsLast24h")),
        k4 = kpi("demandes en attente", n("pendingJoinRequests")),
        k5 = kpi("total signalements", n("totalReports")),
        k6 = kpi("numéros importés", n("importedNumbers")),
        k7 = kpi("préfixes suivis", n("importedPrefixes")),
        k8 = kpi("feedback reçus", n("feedbackSpam") + n("feedbackLegit")),
        camps = camps,
        ops = ops,
        recent = recent,
        key = escape_html(key),
        fbs = n("feedbackSpam"),
        fbo = n("feedbackLegit"),
    )
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
