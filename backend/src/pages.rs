//! Pages HTML publiques (accueil + confirmations + dashboard admin).
//! Design server-rendered, sans JS (CSP stricte) : le « dynamique » vient
//! d'animations CSS (fade-in échelonné, barres qui poussent, pulse).

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Tokens + reset + animations partagés par toutes les pages.
const BASE_CSS: &str = r#"
:root{color-scheme:light dark;
  --bg:#fbf6f2;--surface:#ffffff;--surface2:#f6efe9;--fg:#241d1a;--muted:#7c6d65;
  --faint:#a89890;--border:#efe3db;--accent:#d6402f;--accent2:#f0623f;
  --good:#2e9e5b;--warn:#e08a1e;--danger:#d6402f;
  --grad:linear-gradient(135deg,#f0623f 0%,#d6402f 55%,#b52d24 100%);
  --shadow:0 1px 2px rgba(70,30,20,.05),0 10px 30px rgba(70,30,20,.07);
  --radius:18px;--r-sm:12px;}
@media(prefers-color-scheme:dark){:root{
  --bg:#17110f;--surface:#211917;--surface2:#2a201d;--fg:#ede4de;--muted:#a5948b;
  --faint:#7c6b63;--border:#382a25;--accent:#f0623f;--accent2:#ff7a54;
  --grad:linear-gradient(135deg,#ff7a54 0%,#f0623f 55%,#d6402f 100%);
  --shadow:0 1px 2px rgba(0,0,0,.3),0 12px 34px rgba(0,0,0,.4);}}
*{margin:0;box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{background:var(--bg);color:var(--fg);
  font:16px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
  -webkit-font-smoothing:antialiased;padding:0 20px 64px}
.wrap{max-width:960px;margin:0 auto}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
@keyframes fadeUp{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
@keyframes grow{from{transform:scaleX(0)}to{transform:scaleX(1)}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}
.anim{animation:fadeUp .6s cubic-bezier(.2,.7,.3,1) both}
@media(prefers-reduced-motion:reduce){*{animation:none!important}}
"#;

// ---------------------------------------------------------------------------
// Page d'accueil
// ---------------------------------------------------------------------------
pub fn landing_page(numbers: i64, prefixes: i64, users: i64) -> String {
    let stat = |v: i64, label: &str, delay: f32| {
        format!(
            "<div class=\"stat anim\" style=\"animation-delay:{delay}s\"><b>{v}</b><span>{label}</span></div>"
        )
    };
    format!(
        r#"<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Anti-Spam Collectif</title>
<style>{base}
.hero{{text-align:center;padding:64px 0 8px}}
.badge{{display:inline-flex;align-items:center;gap:8px;background:var(--surface2);
  border:1px solid var(--border);border-radius:999px;padding:6px 14px;font-size:.85rem;
  color:var(--muted);margin-bottom:22px}}
.badge .dot{{width:8px;height:8px;border-radius:50%;background:var(--good);animation:pulse 2s infinite}}
h1{{font-size:clamp(2.1rem,6vw,3.4rem);line-height:1.05;letter-spacing:-.03em;font-weight:800}}
h1 .g{{background:var(--grad);-webkit-background-clip:text;background-clip:text;color:transparent}}
.emoji{{font-size:3rem;display:inline-block;animation:float 4s ease-in-out infinite}}
.pitch{{color:var(--muted);max-width:560px;margin:18px auto 0;font-size:1.1rem}}
.stats{{display:flex;gap:14px;flex-wrap:wrap;margin:40px 0}}
.stat{{flex:1;min-width:150px;background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);padding:22px;box-shadow:var(--shadow);position:relative;overflow:hidden}}
.stat::before{{content:"";position:absolute;inset:0 auto 0 0;width:4px;background:var(--grad)}}
.stat b{{display:block;font-size:2.3rem;font-weight:800;letter-spacing:-.02em}}
.stat span{{color:var(--muted);font-size:.92rem}}
.card{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:26px;box-shadow:var(--shadow);margin-top:20px}}
h2{{font-size:1.15rem;margin-bottom:6px;letter-spacing:-.01em}}
ol{{padding-left:20px;color:var(--muted)}}ol li{{margin:8px 0}}ol li b{{color:var(--fg)}}
.muted{{color:var(--muted)}}
form{{display:flex;flex-direction:column;gap:12px;margin-top:14px}}
input,textarea{{font:inherit;padding:13px 15px;border-radius:var(--r-sm);
  border:1px solid var(--border);background:var(--surface2);color:var(--fg);transition:border .2s}}
input:focus,textarea:focus{{outline:none;border-color:var(--accent)}}
textarea{{resize:vertical;min-height:70px}}
button{{font:inherit;font-weight:700;padding:14px;border:none;border-radius:var(--r-sm);
  background:var(--grad);color:#fff;cursor:pointer;box-shadow:var(--shadow);transition:transform .15s,filter .15s}}
button:hover{{transform:translateY(-1px);filter:brightness(1.05)}}
.foot{{margin-top:36px;color:var(--faint);font-size:.88rem;text-align:center}}
code{{background:var(--surface2);padding:2px 7px;border-radius:7px;font-size:.85em}}
</style></head>
<body><div class="wrap">
<div class="hero anim">
  <div class="badge"><span class="dot"></span> Protection communautaire active</div>
  <div><span class="emoji">📵</span></div>
  <h1>Anti-Spam <span class="g">Collectif</span></h1>
  <p class="pitch">Le démarchage nous harcèle chacun séparément. Ici, <b>un seul
  signalement protège tout le groupe</b> : dès qu'un numéro est signalé, tous les
  téléphones sont prévenus quand il rappelle.</p>
</div>

<div class="stats">
  {s1}{s2}{s3}
</div>

<div class="card anim" style="animation-delay:.15s">
  <h2>Comment ça marche</h2>
  <ol>
    <li>Installe l'app Android, entre ta clé ou scanne une invitation.</li>
    <li>À chaque appel, ton téléphone vérifie le numéro et t'affiche
        <b>« ⚠️ Signalé par N personnes »</b> pendant la sonnerie — ou le bloque.</li>
    <li>Un numéro inconnu qui te démarche ? Un tap sur <b>Signaler</b> et tout le
        groupe est protégé.</li>
  </ol>
</div>

<div class="card anim" style="animation-delay:.25s">
  <h2>Rejoindre le groupe</h2>
  <p class="muted">L'accès se fait sur invitation (une clé par membre). Laisse une
  demande, l'administrateur te recontacte.</p>
  <form method="POST" action="/api/join-requests">
    <input name="name" maxlength="64" required placeholder="Prénom ou pseudo" autocomplete="off">
    <input name="contact" maxlength="128" placeholder="Comment te joindre ? (Signal, e-mail, tél…)" autocomplete="off">
    <textarea name="message" maxlength="280" placeholder="Un mot (facultatif)…"></textarea>
    <button type="submit">Envoyer ma demande</button>
  </form>
</div>

<p class="foot">Projet libre —
<a href="https://github.com/micferna/app-phone-spam">github.com/micferna/app-phone-spam</a>
· backend Rust + SQLite, app Flutter · <code>GET /api/health</code></p>
</div></body></html>"#,
        base = BASE_CSS,
        s1 = stat(numbers, "numéros signalés par le groupe", 0.05),
        s2 = stat(prefixes, "préfixes suivis (ARCEP + listes)", 0.12),
        s3 = stat(users, "membres protégés", 0.19),
    )
}

// ---------------------------------------------------------------------------
// Confirmation
// ---------------------------------------------------------------------------
pub fn confirmation_page(title: &str, body_html: &str) -> String {
    format!(
        r#"<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{t}</title><style>{base}
.box{{max-width:520px;margin:14vh auto 0;background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);box-shadow:var(--shadow);padding:34px;text-align:center}}
h1{{font-size:1.5rem;letter-spacing:-.01em}}p{{color:var(--muted);margin-top:10px}}
</style></head><body><div class="box anim"><h1>{t}</h1><p>{b}</p>
<p style="margin-top:20px"><a href="/">← Retour à l'accueil</a></p></div></body></html>"#,
        base = BASE_CSS,
        t = escape_html(title),
        b = body_html
    )
}

// ---------------------------------------------------------------------------
// Admin — écran de connexion
// ---------------------------------------------------------------------------
pub fn admin_login_page(error: bool) -> String {
    let msg = if error {
        "<p class=\"err\">Clé admin invalide.</p>"
    } else {
        ""
    };
    format!(
        r#"<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Admin — Anti-Spam</title><style>{base}
.box{{max-width:420px;margin:16vh auto 0;background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);box-shadow:var(--shadow);padding:32px;text-align:center}}
.ic{{font-size:2.4rem}}h1{{font-size:1.4rem;margin:6px 0 4px}}
p{{color:var(--muted)}}.err{{color:var(--danger);margin-top:10px}}
form{{display:flex;gap:10px;margin-top:20px}}
input{{flex:1;font:inherit;padding:13px 15px;border-radius:12px;border:1px solid var(--border);
  background:var(--surface2);color:var(--fg)}}input:focus{{outline:none;border-color:var(--accent)}}
button{{font:inherit;font-weight:700;padding:13px 20px;border:none;border-radius:12px;
  background:var(--grad);color:#fff;cursor:pointer}}
</style></head><body><div class="box anim">
<div class="ic">🔐</div><h1>Dashboard admin</h1>
<p>Entre ta clé admin pour accéder aux statistiques.</p>{msg}
<form method="POST" action="/admin">
  <input name="key" type="password" placeholder="Clé admin" autocomplete="off">
  <button type="submit">Entrer</button>
</form></div></body></html>"#,
        base = BASE_CSS,
        msg = msg
    )
}

// ---------------------------------------------------------------------------
// Admin — dashboard
// ---------------------------------------------------------------------------
pub fn admin_dashboard_page(s: &serde_json::Value) -> String {
    let n = |k: &str| s.get(k).and_then(|v| v.as_i64()).unwrap_or(0);

    // Tuiles KPI (label, valeur, icône, accent?)
    let kpis = [
        ("👥", n("members"), "membres"),
        ("🚫", n("reportedNumbers"), "numéros signalés"),
        ("⏱️", n("reportsLast24h"), "signalements (24 h)"),
        ("✉️", n("pendingJoinRequests"), "demandes en attente"),
        ("📈", n("totalReports"), "total signalements"),
        ("📥", n("importedNumbers"), "numéros importés"),
        ("🏷️", n("importedPrefixes"), "préfixes suivis"),
        (
            "👍",
            n("feedbackSpam") + n("feedbackLegit"),
            "retours reçus",
        ),
    ];
    let mut kpi_html = String::new();
    for (i, (ic, v, label)) in kpis.iter().enumerate() {
        let d = 0.03 * i as f32;
        kpi_html.push_str(&format!(
            "<div class=\"kpi anim\" style=\"animation-delay:{d}s\"><div class=\"ic\">{ic}</div>\
             <b>{v}</b><span>{label}</span></div>"
        ));
    }

    // Barres : top opérateurs (magnitude, mono-teinte accent).
    let mut ops_html = String::new();
    if let Some(arr) = s.get("topOperators").and_then(|v| v.as_array()) {
        let max = arr
            .iter()
            .filter_map(|o| o.get("count").and_then(|v| v.as_i64()))
            .max()
            .unwrap_or(1)
            .max(1);
        for (i, o) in arr.iter().enumerate() {
            let name = o
                .get("name")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| {
                    o.get("mnemo")
                        .and_then(|v| v.as_str())
                        .unwrap_or("?")
                        .to_string()
                });
            let c = o.get("count").and_then(|v| v.as_i64()).unwrap_or(0);
            let pct = (c * 100 / max).clamp(3, 100);
            let d = 0.05 * i as f32;
            ops_html.push_str(&format!(
                "<div class=\"row anim\" style=\"animation-delay:{d}s\">\
                   <span class=\"rl\">{name}</span>\
                   <div class=\"track\"><div class=\"bar\" style=\"width:{pct}%\"></div></div>\
                   <span class=\"rv\">{c}</span></div>",
                name = escape_html(&name),
            ));
        }
    }
    if ops_html.is_empty() {
        ops_html = "<p class=\"muted\">Aucun signalement pour l'instant.</p>".into();
    }

    // Campagnes actives : badges avec pulse, sévérité selon le volume.
    let mut camp_html = String::new();
    if let Some(arr) = s.get("activeCampaigns").and_then(|v| v.as_array()) {
        for (i, c) in arr.iter().enumerate() {
            let p = c.get("prefix").and_then(|v| v.as_str()).unwrap_or("");
            let cnt = c.get("count").and_then(|v| v.as_i64()).unwrap_or(0);
            let sev = if cnt >= 8 { "hi" } else { "mid" };
            let d = 0.05 * i as f32;
            camp_html.push_str(&format!(
                "<div class=\"camp {sev} anim\" style=\"animation-delay:{d}s\">\
                   <span class=\"pd\"></span><b>{p}xx…</b><span>{cnt} numéros / 24 h</span></div>",
                p = escape_html(p),
            ));
        }
    }
    if camp_html.is_empty() {
        camp_html = "<p class=\"muted\">Aucune campagne active. 🎉</p>".into();
    }

    // Signalements récents.
    let mut recent = String::new();
    if let Some(arr) = s.get("recentReports").and_then(|v| v.as_array()) {
        for r in arr {
            let num = r.get("number").and_then(|v| v.as_str()).unwrap_or("");
            let c = r.get("reportCount").and_then(|v| v.as_i64()).unwrap_or(0);
            let last = r.get("lastReport").and_then(|v| v.as_str()).unwrap_or("");
            recent.push_str(&format!(
                "<tr><td class=\"mono\">{}</td><td><span class=\"pill\">{}</span></td>\
                 <td class=\"muted\">{}</td></tr>",
                escape_html(num),
                c,
                escape_html(last)
            ));
        }
    }
    if recent.is_empty() {
        recent = "<tr><td colspan=3 class=\"muted\">—</td></tr>".into();
    }

    format!(
        r#"<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Admin — Anti-Spam</title><style>{base}
.top{{display:flex;align-items:center;justify-content:space-between;padding:28px 0 8px;flex-wrap:wrap;gap:12px}}
.top h1{{font-size:1.6rem;letter-spacing:-.02em}}
.live{{display:inline-flex;align-items:center;gap:8px;color:var(--muted);font-size:.9rem}}
.live .dot{{width:9px;height:9px;border-radius:50%;background:var(--good);animation:pulse 2s infinite}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin:16px 0 8px}}
.kpi{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:18px;box-shadow:var(--shadow);transition:transform .15s}}
.kpi:hover{{transform:translateY(-2px)}}
.kpi .ic{{font-size:1.3rem}}.kpi b{{display:block;font-size:1.9rem;font-weight:800;letter-spacing:-.02em;margin-top:4px}}
.kpi span{{color:var(--muted);font-size:.85rem}}
.panel{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:22px;box-shadow:var(--shadow);margin-top:18px}}
h2{{font-size:1.05rem;margin-bottom:14px;display:flex;align-items:center;gap:8px}}
.muted{{color:var(--muted)}}
.row{{display:flex;align-items:center;gap:12px;margin:9px 0}}
.rl{{width:34%;font-size:.9rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.rv{{width:44px;text-align:right;font-variant-numeric:tabular-nums;color:var(--muted);font-size:.9rem}}
.track{{flex:1;height:12px;background:var(--surface2);border-radius:999px;overflow:hidden}}
.bar{{height:100%;background:var(--grad);border-radius:999px;transform-origin:left;
  animation:grow .9s cubic-bezier(.2,.7,.3,1) both}}
.camps{{display:flex;flex-wrap:wrap;gap:10px}}
.camp{{display:inline-flex;align-items:center;gap:9px;padding:10px 14px;border-radius:var(--r-sm);
  border:1px solid var(--border);background:var(--surface2)}}
.camp b{{font-variant-numeric:tabular-nums}}.camp span{{color:var(--muted);font-size:.85rem}}
.camp .pd{{width:9px;height:9px;border-radius:50%;background:var(--warn);animation:pulse 1.6s infinite}}
.camp.hi{{border-color:var(--danger)}}.camp.hi .pd{{background:var(--danger)}}
table{{width:100%;border-collapse:collapse}}
th,td{{text-align:left;padding:9px 8px;border-bottom:1px solid var(--border);font-size:.9rem}}
th{{color:var(--faint);font-weight:600;font-size:.78rem;text-transform:uppercase;letter-spacing:.04em}}
.mono{{font-variant-numeric:tabular-nums}}
.pill{{background:var(--surface2);border-radius:999px;padding:2px 10px;font-size:.82rem;font-variant-numeric:tabular-nums}}
.bar-actions{{display:flex;align-items:center;gap:14px;margin-top:22px;flex-wrap:wrap}}
.btn{{display:inline-flex;align-items:center;gap:8px;font:inherit;font-weight:600;padding:11px 18px;
  border:1px solid var(--border);border-radius:12px;background:var(--surface);color:var(--fg);cursor:pointer}}
.btn.primary{{background:var(--grad);color:#fff;border:none}}
</style></head><body><div class="wrap">
<div class="top anim"><h1>📊 Dashboard</h1>
  <span class="live"><span class="dot"></span> données en direct</span></div>

<div class="grid">{kpis}</div>

<div class="panel anim" style="animation-delay:.1s">
  <h2>⚡ Campagnes actives <span class="muted" style="font-weight:400;font-size:.85rem">— pics de signalements sur une plage (24 h)</span></h2>
  <div class="camps">{camps}</div>
</div>

<div class="panel anim" style="animation-delay:.15s">
  <h2>📞 Opérateurs qui concentrent le spam</h2>
  {ops}
</div>

<div class="panel anim" style="animation-delay:.2s">
  <h2>🕑 Signalements récents</h2>
  <table><tr><th>Numéro</th><th>Signalé</th><th>Dernier</th></tr>{recent}</table>
</div>

<div class="bar-actions">
  <a class="btn primary" href="/admin">↻ Rafraîchir</a>
  <span class="muted">Feedback : {fbs} spam · {fbo} légitime</span>
  <a class="btn" href="/">← Site public</a>
  <a class="btn" href="/admin/logout">⎋ Se déconnecter</a>
</div>
</div></body></html>"#,
        base = BASE_CSS,
        kpis = kpi_html,
        camps = camp_html,
        ops = ops_html,
        recent = recent,
        fbs = n("feedbackSpam"),
        fbo = n("feedbackLegit"),
    )
}
