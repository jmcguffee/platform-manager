"use strict";
// pmgr dashboard. `pmgr ui` embeds the report in this page as JSON.
// Every value from the report is set with textContent, never as HTML,
// because findings quote logs, commit messages and API errors.

const SEV = ["critical", "error", "warning", "info"];
const SEV_LABEL = { critical: "Critical", error: "Error", warning: "Warning", info: "Suggestion" };
const VIEWS = ["overview", "actions", "oncall", "access", "security", "workloads", "utilization", "pipelines", "workflows", "argo", "sources"];
const AREAS = { oncall: ["oncall"], access: ["auth", "cluster"], security: ["security"], workloads: ["workload"], utilization: ["utilization"], pipelines: ["pipeline"], workflows: ["workflow"], argo: ["argo"] };
const SERVICE = { rds: "RDS", redshift: "Redshift", elasticache: "ElastiCache", msk: "MSK", eks: "EKS" };

const AWS_STATE = {
  ok: ["ok", "Signed in"],
  expiring: ["warn", "Ending soon"],
  expired: ["bad", "Session expired"],
  no_access: ["bad", "Role not granted"],
  wrong_role: ["warn", "Wrong role"],
  unreachable: ["bad", "Can't reach AWS"],
  no_profile: ["bad", "Profile missing"],
  no_cli: ["bad", "AWS CLI missing"],
};
const K8S_STATE = {
  ok: ["ok", "Reachable"],
  limited: ["warn", "Read-only access"],
  gone: ["warn", "Cluster deleted"],
  not_active: ["warn", "Not active"],
  unreachable: ["bad", "Can't reach API"],
  unauthorized: ["bad", "Credentials rejected"],
  forbidden: ["bad", "Access denied"],
  no_context: ["bad", "No kubeconfig context"],
  skipped: ["off", "Not checked"],
};

const app = { report: null, sev: new Set(SEV), q: "", everyone: false, diag: {}, live: false, token: "", syncing: false, syncError: "" };

// ---------- syncing (only when `pmgr ui` serves the page) ----------
// The server answers one connection at a time and is briefly closed between them, so a refused
// connection is retried a few times before it counts as "not running".
async function api(path, method = "GET", body = null) {
  for (let attempt = 0; ; attempt += 1) {
    let r;
    try {
      const headers = { "X-Pmgr-Token": app.token };
      if (body) headers["Content-Type"] = "application/json";
      r = await fetch(path, { method, headers, cache: "no-store", body: body ? JSON.stringify(body) : undefined });
    } catch (e) {
      if (attempt >= 8) throw new Error("pmgr ui isn't running anymore. Start it again in your terminal.");
      await new Promise((done) => setTimeout(done, 150 * (attempt + 1)));
      continue;
    }
    if (!r.ok) throw new Error((await r.text()).trim() || `HTTP ${r.status}`);
    return r.json();
  }
}

async function sync() {
  if (app.syncing || !app.live) return;
  app.syncing = true;
  app.syncStarted = Date.now();
  app.syncError = "";
  renderSync();
  try {
    await api("/api/sync", "POST");
    const started = Date.now();
    for (;;) {
      await new Promise((done) => setTimeout(done, 2000));
      const s = await api("/api/state");
      if (!s.running) {
        if (s.error) throw new Error(s.error);
        // Redraw in place with the new report: the view, filters and scroll stay put.
        app.report = await api("/api/report");
        app.syncing = false;
        const y = window.scrollY;
        render();
        window.scrollTo(0, y);
        return;
      }
      if (Date.now() - started > 10 * 60 * 1000) throw new Error("The sync is taking more than 10 minutes.");
    }
  } catch (e) {
    app.syncing = false;
    app.syncError = e.message;
    renderSync();
  }
}

function renderSync() {
  const slot = document.getElementById("again");
  if (!slot) return;
  if (!app.live) {
    slot.replaceChildren("Run ", h("code", {}, "pmgr ui"), " to refresh");
    return;
  }
  const secs = app.syncing ? Math.round((Date.now() - app.syncStarted) / 1000) : 0;
  const button = h("button", { type: "button", class: app.syncing ? "" : "primary", disabled: app.syncing, title: "Sync now (r)" },
    app.syncing ? [h("span", { class: "spin", "aria-hidden": "true" }), `Syncing… ${secs}s`] : "Sync now");
  button.addEventListener("click", sync);
  slot.replaceChildren(button);
  const banner = document.getElementById("sync-error");
  if (banner) banner.remove();
  if (app.syncError) {
    document.getElementById("main").prepend(h("p", { class: "banner", id: "sync-error", role: "alert" }, `Sync didn't finish: ${app.syncError}`));
  }
}

// ---------- tiny DOM helper ----------
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k === "class") el.className = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

function plural(n, one, many) { return `${n} ${n === 1 ? one : many}`; }

function copyButton(text) {
  const b = h("button", { class: "copy", type: "button", "aria-label": `Copy ${text}` }, "Copy");
  b.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(text);
      b.textContent = "Copied";
      b.classList.add("done");
      setTimeout(() => { b.textContent = "Copy"; b.classList.remove("done"); }, 1500);
    } catch { b.textContent = "Select and copy"; }
  });
  return b;
}

// Backticked spans are code. Ones that look like commands (they have a space) get a copy button.
function richText(text, copyable = true) {
  return text.split(/(`[^`]+`)/).filter(Boolean).map((part) => {
    if (part.startsWith("`") && part.endsWith("`")) {
      const code = part.slice(1, -1);
      if (copyable && code.includes(" ")) return h("span", { class: "cmd" }, h("code", {}, code), copyButton(code));
      return h("code", {}, code);
    }
    return part;
  });
}

// ---------- data ----------
function findings() { return (app.report && app.report.findings) || []; }
function inView(view) { return findings().filter((f) => AREAS[view].includes(f.area)); }
function counts(list) {
  const c = { critical: 0, error: 0, warning: 0, info: 0 };
  for (const f of list) c[f.severity] += 1;
  return c;
}
function bySeverity(a, b) { return SEV.indexOf(a.severity) - SEV.indexOf(b.severity); }
function hasErrors(list) { return list.some((f) => f.severity === "error" || f.severity === "critical"); }

// ---------- pieces ----------
function linkLabel(f) {
  if (f.check.startsWith("auth.") && f.link.includes("portal.azure.com")) return "Open Azure PIM activation";
  if (f.check === "github.saml") return "Authorize SSO for this org";
  if (f.area === "pipeline") return "Open the failing run";
  return f.link;
}

// ---------- Argo CD port-forwards ----------
// Starts (or reuses) `kubectl port-forward svc/argocd-server` for a cluster on the pmgr ui server, then
// opens Argo CD. The tab opens on the click itself, so pop-up blockers don't stop it.
function argoButton(cluster) {
  if (!app.live) return null;
  app.pf = app.pf || {};
  const state = app.pf[cluster] || {};
  const wrap = h("span", { class: "pf" });
  const b = h("button", { type: "button", class: "ghost diag-btn", disabled: state.loading }, state.loading ? "Opening…" : "Open Argo CD");
  b.addEventListener("click", async () => {
    const tab = window.open("about:blank", "_blank");
    app.pf[cluster] = { loading: true };
    wrap.replaceWith(argoButton(cluster));
    try {
      const r = await api("/api/portforward", "POST", { cluster });
      if (r.error) throw new Error(r.error);
      app.pf[cluster] = { url: r.url };
      if (tab) tab.location.href = r.url;
    } catch (e) {
      if (tab) tab.close();
      app.pf[cluster] = { error: e.message };
    }
    document.querySelectorAll(`[data-pf="${CSS.escape(cluster)}"]`).forEach((el) => el.replaceChildren(argoButton(cluster)));
  });
  wrap.append(b);
  if (state.url) wrap.append(" ", h("a", { href: state.url, target: "_blank", rel: "noopener noreferrer" }, `${state.url} ↗`));
  if (state.error) wrap.append(" ", h("span", { class: "pf-error" }, state.error));
  return wrap;
}
function argoSlot(cluster) { return h("span", { "data-pf": cluster }, argoButton(cluster)); }

// One row per environment: whether its tunnel is running, the local port it's on (or will use next),
// and buttons to create it, open Argo CD, copy the login password and stop it. The password is read
// from AWS Secrets Manager and copied to the clipboard by pmgr ui; it never reaches this page.
app.tunnelBusy = {};
app.tunnelNote = {};
function refreshTunnels() {
  if (!app.live) return;
  api("/api/portforward")
    .then((r) => { app.tunnels = r; app.tunnelError = ""; })
    .catch((e) => { app.tunnelError = e.message; })
    .finally(drawTunnels);
}
function drawTunnels() {
  const el = document.getElementById("tunnels");
  if (el) el.replaceChildren(...tunnelTable().filter(Boolean));
}
async function tunnelAction(name, action) {
  app.tunnelBusy[name] = action;
  app.tunnelNote[name] = null;
  drawTunnels();
  try {
    const path = { start: "/api/portforward", stop: "/api/portforward/stop", login: "/api/argo-login" }[action];
    const r = await api(path, "POST", { cluster: name });
    if (r.error) throw new Error(r.error);
    if (action === "login") app.tunnelNote[name] = { ok: `Password for ${r.username} copied. It clears from the clipboard in ${r.clears_in}s.` };
    if (action === "start") app.tunnelNote[name] = { ok: r.reused ? "Already running." : `Tunnel up on port ${r.port}.` };
    if (action === "stop") app.tunnels = r;
    app.pf = {};
  } catch (e) {
    app.tunnelNote[name] = { error: e.message };
  }
  app.tunnelBusy[name] = null;
  if (action === "stop") drawTunnels(); else refreshTunnels();
}
function tunnelTable() {
  const status = Object.fromEntries((app.tunnels || []).map((t) => [t.name, t]));
  const rows = (app.report.clusters || []).map((c) => {
    const t = status[c.name];
    const busy = app.tunnelBusy[c.name];
    const note = app.tunnelNote[c.name];
    const reachable = c.kubernetes === "ok";
    const btn = (label, action, cls = "ghost diag-btn") => {
      const b = h("button", { type: "button", class: cls, disabled: !!busy }, busy === action ? `${label}…` : label);
      b.addEventListener("click", () => tunnelAction(c.name, action));
      return b;
    };
    const port = !t ? h("span", { class: "muted" }, app.live ? "…" : "–")
      : t.alive ? h("a", { href: t.url, target: "_blank", rel: "noopener noreferrer" }, `localhost:${t.port}`)
      : h("span", { title: t.fixed ? "argocd_port in your config" : "Last port used, else 8080 + the cluster's position. If it's taken, a free port is picked." },
          String(t.port), h("span", { class: "muted" }, t.fixed ? " fixed" : " auto"));
    const actions = !app.live ? h("span", { class: "muted" }, "in pmgr ui")
      : !t ? null
      : t.alive ? h("span", { class: "pf" },
          h("a", { class: "button-link", href: t.url, target: "_blank", rel: "noopener noreferrer" }, "Open Argo CD"),
          t.login ? btn("Copy password", "login") : null,
          btn("Stop", "stop"))
      : h("span", { class: "pf" }, btn("Create tunnel", "start", reachable ? "primary btn-sm" : "ghost diag-btn"), t.login ? btn("Copy password", "login") : null);
    return h("tr", { class: t && t.alive ? "row-now" : "" },
      h("td", {}, h("b", {}, c.name), h("div", { class: "muted small" }, c.context)),
      h("td", {}, reachable ? h("span", { class: "chip-s ok" }, "reachable") : h("span", { class: "chip-s off", title: "At the last sync. Renewed your session since? Create tunnel tries anyway." }, (K8S_STATE[c.kubernetes] || ["", c.kubernetes])[1])),
      h("td", {}, !t ? "" : t.alive ? h("span", { class: "chip-s ok" }, "running") : h("span", { class: "chip-s off" }, "off")),
      h("td", { class: "n" }, port),
      h("td", {}, !t ? "" : t.login ? (t.username || "from secret") : h("span", { class: "muted" }, "add argocd_secret")),
      h("td", {}, actions,
        note && note.ok ? h("div", { class: "pf-ok" }, note.ok) : null,
        note && note.error ? h("div", { class: "pf-error" }, note.error) : null));
  });
  return [
    app.tunnelError ? h("p", { class: "pf-error" }, app.tunnelError) : null,
    table([["Environment"], ["Cluster"], ["Tunnel"], ["Local port", true], ["Login"], [""]], rows),
  ];
}

// ---------- diagnose ----------
// Runs the read-only commands you'd run by hand for this finding (describe, events, logs, the failing
// job's log) on the pmgr ui server, and shows the output under the finding.
function diagPanel(f) {
  const state = app.diag[f.id];
  if (!state) return null;
  if (state.loading) return h("div", { class: "diag" }, h("p", { class: "muted" }, h("span", { class: "spin", "aria-hidden": "true" }), "Diagnosing: gathering describe output, events and logs…"));
  if (state.error) return h("div", { class: "diag" }, h("p", { class: "banner" }, `Diagnose didn't finish: ${state.error}`));
  if (!state.sections.length) return h("div", { class: "diag" }, h("p", { class: "muted" }, "Nothing more to look up for this finding."));
  return h("div", { class: "diag" }, state.sections.map((x, i) =>
    h("details", { class: `diag-sec${x.ok ? "" : " failed"}`, open: i < 3 || !x.ok },
      h("summary", {}, x.title, x.ok ? null : h("span", { class: "chip-s bad" }, "command failed")),
      x.command ? h("p", { class: "diag-cmd" }, h("code", {}, x.command), copyButton(x.command)) : null,
      h("pre", {}, x.output))));
}

async function runDiagnose(f, slot) {
  app.diag[f.id] = { loading: true };
  slot.replaceChildren(diagPanel(f));
  try {
    const sections = await api("/api/diagnose", "POST", { id: f.id });
    app.diag[f.id] = { sections };
  } catch (e) {
    app.diag[f.id] = { error: e.message };
  }
  slot.replaceChildren(diagPanel(f));
}

function diagButton(f, slot) {
  if (!f.diag || !f.id) return null;
  if (!app.live) return h("span", { class: "muted diag-hint", title: "Diagnose runs on the pmgr ui server" }, "Diagnose is available in pmgr ui");
  const state = app.diag[f.id];
  const b = h("button", { type: "button", class: "ghost diag-btn", disabled: state && state.loading }, state && state.sections ? "Diagnose again" : "Diagnose");
  b.addEventListener("click", () => runDiagnose(f, slot));
  return b;
}

function findingRow(f) {
  const slot = h("div", { class: "diag-slot" }, diagPanel(f));
  return h(
    "li",
    { class: `finding ${f.severity}` },
    h("div", { class: "f-head" },
      h("span", { class: "sev" }, SEV_LABEL[f.severity]),
      h("span", { class: "where" }, f.resource),
      f.savings_usd_month ? h("span", { class: "save", title: "At on-demand list price" },
        `${f.savings_note === "up to" ? "up to " : ""}${usd(f.savings_usd_month)}/mo`) : null),
    h("p", { class: "what" }, richText(f.message, false)),
    f.fix ? h("p", { class: "fix" }, richText(f.fix)) : null,
    (f.link || f.diag) ? h("p", { class: "ref" },
      diagButton(f, slot),
      f.link ? h("a", { href: f.link, target: "_blank", rel: "noopener noreferrer" }, `${linkLabel(f)} ↗`) : null) : null,
    slot,
  );
}

function findingList(list, limit) {
  const shown = limit ? list.slice(0, limit) : list;
  return h("ul", { class: "findings" }, shown.map(findingRow));
}

function tally(list) {
  const c = counts(list);
  const bad = c.critical + c.error;
  const parts = [];
  if (bad) parts.push(h("span", { class: "e" }, plural(bad, "error", "errors")));
  if (c.warning) parts.push(h("span", { class: "w" }, plural(c.warning, "warning", "warnings")));
  if (c.info) parts.push(plural(c.info, "suggestion", "suggestions"));
  if (!parts.length) parts.push("No findings");
  return h("span", { class: "tally" }, parts.flatMap((p, i) => (i ? [", ", p] : [p])));
}

function link(kind, label, detail) {
  return h("div", { class: `link ${kind}`, role: "listitem" }, h("b", {}, label), detail ? h("span", {}, detail) : null);
}

function workloadLink(cluster) {
  if (cluster.kubernetes !== "ok") return ["off", "Not checked"];
  const list = findings().filter((f) => f.area === "workload" && f.resource.startsWith(`${cluster.name}/`));
  const c = counts(list);
  if (c.critical + c.error) return ["bad", plural(c.critical + c.error, "problem", "problems")];
  if (c.warning) return ["warn", plural(c.warning, "warning", "warnings")];
  const unseen = (app.report.unseen || []).some((u) => u.startsWith(`${cluster.name}: couldn't read`));
  return unseen ? ["warn", "Partly readable"] : ["ok", "Healthy"];
}

function argoLink(cluster) {
  if (cluster.kubernetes !== "ok") return ["off", "Not checked"];
  const list = findings().filter((f) => f.area === "argo" && f.resource.startsWith(`${cluster.name}/`));
  const c = counts(list);
  if (c.critical + c.error) return ["bad", plural(c.critical + c.error, "app failing", "apps failing")];
  if (c.warning) return ["warn", plural(c.warning, "app drifting", "apps drifting")];
  const unseen = (app.report.unseen || []).some((u) => u.startsWith(`${cluster.name}: Argo CD`));
  return unseen ? ["off", "Can't read Applications"] : ["ok", "Healthy"];
}

function chains() {
  const r = app.report;
  const rows = [];
  for (const c of r.clusters || []) {
    const [ak, alabel] = AWS_STATE[c.aws] || ["bad", c.aws];
    const [kk, klabel] = K8S_STATE[c.kubernetes] || ["bad", c.kubernetes];
    const [wk, wdetail] = workloadLink(c);
    const [gk, gdetail] = argoLink(c);
    rows.push(
      h(
        "div",
        { class: "chain" },
        h("div", { class: "chain-name" }, c.name, c.current ? h("span", { class: "here" }, " (current)") : null, h("small", {}, c.context),
          c.kubernetes === "ok" && app.live ? h("div", { class: "chain-actions" }, argoSlot(c.name)) : null),
        h(
          "div",
          { class: "links", role: "list", "aria-label": `Access chain for ${c.name}` },
          link(ak, "AWS session", alabel),
          h("span", { class: `joint ${ak === "ok" ? "" : "broken"}`, "aria-hidden": "true" }),
          link(kk, "Kubernetes", klabel),
          h("span", { class: `joint ${kk === "ok" ? "" : "broken"}`, "aria-hidden": "true" }),
          link(wk, "Workloads", wdetail),
          h("span", { class: `joint ${kk === "ok" ? "" : "broken"}`, "aria-hidden": "true" }),
          link(gk, "Argo CD", gdetail),
        ),
      ),
    );
  }
  for (const a of r.accounts || []) {
    const [ak, alabel] = AWS_STATE[a.aws] || ["bad", a.aws];
    rows.push(
      h(
        "div",
        { class: "chain" },
        h("div", { class: "chain-name" }, a.name, h("small", {}, a.account ? `Account ${a.account}` : `Profile ${a.profile}`)),
        h("div", { class: "links single", role: "list" }, link(ak, "AWS session", alabel)),
      ),
    );
  }
  if (!rows.length) return h("p", { class: "empty" }, "No clusters or accounts are configured. Add them to your config file, then run pmgr ui.");
  return h("div", { class: "chains" }, rows);
}

function usageBars(rows, max) {
  const top = Math.max(1, max || Math.max(...rows.map((r) => r[1])));
  return h(
    "div",
    { class: "usage" },
    rows.map(([name, mins]) =>
      h(
        "div",
        { class: "use" },
        h("span", { class: "name", title: name }, name),
        h("span", { class: "track", "aria-hidden": "true" }, h("span", { class: "fill", style: `width:${Math.max(1, (mins / top) * 100)}%` })),
        h("span", { class: "mins" }, `${Math.round(mins).toLocaleString("en-US")} min`),
      ),
    ),
  );
}

function filters(onChange, placeholder = "Filter by repo, file or text") {
  const search = h("input", { type: "search", placeholder, "aria-label": "Filter findings" });
  search.value = app.q;
  search.addEventListener("input", () => { app.q = search.value; onChange(); });
  const chips = SEV.map((s) => {
    const b = h("button", { class: "chip", type: "button", "aria-pressed": String(app.sev.has(s)) }, SEV_LABEL[s]);
    b.addEventListener("click", () => {
      if (app.sev.has(s)) app.sev.delete(s);
      else app.sev.add(s);
      b.setAttribute("aria-pressed", String(app.sev.has(s)));
      onChange();
    });
    return b;
  });
  return h("div", { class: "toolbar" }, search, chips);
}

function passes(f) {
  if (!app.sev.has(f.severity)) return false;
  if (!app.q) return true;
  const q = app.q.toLowerCase();
  return [f.resource, f.message, f.fix].some((t) => (t || "").toLowerCase().includes(q));
}

function grouped(list, keyOf, openWhen) {
  const groups = new Map();
  for (const f of list) {
    const k = keyOf(f);
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(f);
  }
  return [...groups.entries()].map(([name, items]) =>
    h(
      "details",
      { class: "group", open: openWhen(items) },
      h("summary", {}, h("span", { class: "group-name" }, name), tally(items)),
      findingList(items.sort(bySeverity)),
    ),
  );
}

function unseenNote() {
  const unseen = (app.report && app.report.unseen) || [];
  if (!unseen.length) return null;
  return h(
    "div",
    { class: "unseen" },
    "Couldn't read these, so they have no findings. That isn't the same as having no problems.",
    h("ul", {}, unseen.map((u) => h("li", {}, u))),
  );
}

// ---------- metrics helpers ----------
function metrics(kind) { return ((app.report && app.report.metrics) || []).filter((m) => m.kind === kind); }
function sources() { return (app.report && app.report.sources) || []; }
function dur(s) {
  if (s == null) return "–";
  if (s < 90) return `${Math.round(s)}s`;
  if (s < 5400) return `${Math.round(s / 60)}m`;
  return `${(s / 3600).toFixed(1)}h`;
}
function pctText(x) { return x == null ? "–" : `${Math.round(x * 100)}%`; }
function ago(iso) {
  if (!iso) return "–";
  const m = (Date.now() - Date.parse(iso)) / 60000;
  if (m < 60) return `${Math.max(1, Math.round(m))}m ago`;
  if (m < 48 * 60) return `${Math.round(m / 60)}h ago`;
  return `${Math.round(m / 1440)}d ago`;
}
function usd(n) { return n == null ? "–" : `$${Math.round(n).toLocaleString("en-US")}`; }
function savingsTotal(list) { return list.reduce((a, f) => a + (f.savings_usd_month || 0), 0); }
// CI cost per 30 days for private repos, at the configured rate.
function ciCost() {
  const rate = (app.report.settings && app.report.settings.ci_usd_per_minute) || 0.008;
  const days = (app.report.settings && app.report.settings.lookback_days) || 14;
  const priv = new Set(sources().filter((s) => s.type === "repo" && s.private).map((s) => s.name));
  return metrics("workflow").filter((w) => priv.has(w.repo)).reduce((a, w) => a + w.minutes, 0) * rate * (30 / days);
}
function spendTracked() { return ((app.report && app.report.metrics) || []).reduce((a, m) => a + (m.monthly_usd || 0), 0) + ciCost(); }
function num(n) { return n == null ? "–" : Math.round(n).toLocaleString("en-US"); }
// A success rate gets a color only when it's worth a look.
function rateCell(x) {
  const cls = x == null ? "" : x < 0.7 ? "bad" : x < 0.9 ? "warn" : "";
  return h("td", { class: `n ${cls}` }, pctText(x));
}
function statusChip(last) {
  if (!last) return "–";
  const c = last.conclusion || last.status;
  const kind = c === "success" ? "ok" : ["failure", "timed_out", "startup_failure"].includes(c) ? "bad" : "off";
  const label = { success: "Passed", failure: "Failed", timed_out: "Timed out", startup_failure: "Didn't start", cancelled: "Canceled", skipped: "Skipped", in_progress: "Running", queued: "Queued" }[c] || c;
  const chip = h("span", { class: `chip-s ${kind}` }, label);
  return last.url ? h("a", { href: last.url, target: "_blank", rel: "noopener noreferrer", class: "plain" }, chip, ` ${ago(last.at)}`) : [chip, ` ${ago(last.at)}`];
}
// Sort value for a cell: data-sort if set, else a number read from the text ($, %, 6m, 1.2h), else the text.
function cellValue(td, numeric) {
  if (!td) return "";
  if (td.dataset.sort != null) return Number(td.dataset.sort);
  const t = td.textContent.trim();
  if (!numeric) return t.toLowerCase();
  if (t === "–" || t === "") return -Infinity;
  const d = t.match(/^([\d.]+)\s*(s|m|h|d)\b/);
  if (d) return Number(d[1]) * { s: 1, m: 60, h: 3600, d: 86400 }[d[2]];
  const n = Number(t.replace(/[$,%]|\/mo/g, "").split(" ")[0]);
  return Number.isNaN(n) ? -Infinity : n;
}
function table(headers, rows) {
  const tbody = h("tbody", {}, rows);
  const ths = headers.map(([label, numeric], i) => {
    const th = h("th", { class: `${numeric ? "n" : ""} ${label ? "sortable" : ""}`, scope: "col", tabindex: label ? "0" : null }, label);
    if (!label) return th;
    const sortBy = () => {
      const dir = th.getAttribute("aria-sort") === "descending" ? "ascending" : "descending";
      for (const other of ths) other.removeAttribute("aria-sort");
      th.setAttribute("aria-sort", dir);
      const sign = dir === "ascending" ? 1 : -1;
      [...tbody.rows].sort((a, b) => {
        const x = cellValue(a.cells[i], numeric), y = cellValue(b.cells[i], numeric);
        return (x > y ? 1 : x < y ? -1 : 0) * sign;
      }).forEach((r) => tbody.append(r));
    };
    th.addEventListener("click", sortBy);
    th.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); sortBy(); } });
    return th;
  });
  return h("div", { class: "table-wrap" }, h("table", { class: "data" }, h("thead", {}, h("tr", {}, ths)), tbody));
}
// A small inline bar for a 0–100 value.
function bar(v, high) {
  if (v == null) return null;
  const tone = high != null && v >= high ? "bad" : high != null && v >= high * 0.85 ? "warn" : "";
  return h("span", { class: `bar ${tone}`, "aria-hidden": "true" }, h("i", { style: `width:${Math.max(2, Math.min(100, v))}%` }));
}
function stats(items) {
  return h("dl", { class: "stats" }, items.map(([label, value, tone, href]) => h("div", { class: tone || "" },
    href ? h("a", { href }, h("dt", {}, label), h("dd", {}, value)) : [h("dt", {}, label), h("dd", {}, value)])));
}
function panel(title, href, body, note) {
  return h("section", { class: "panel" },
    h("div", { class: "panel-head" }, h("h3", {}, title), note ? h("span", { class: "tally" }, note) : null, href ? h("a", { href }, "Open") : null),
    h("div", { class: "panel-body" }, body));
}
function lede(text, tone, sub) {
  return h("div", { class: "lede" }, h("h2", { class: `verdict${tone ? ` ${tone}` : ""}` }, text), sub ? h("p", { class: "verdict-sub" }, sub) : null);
}
function sourceProblems(type) {
  const bad = sources().filter((s) => s.type === type && !s.ok);
  if (!bad.length) return null;
  return h("div", { class: "callout" },
    h("p", { class: "callout-title" }, `Couldn't read ${plural(bad.length, type === "repo" ? "repo" : type, type === "repo" ? "repos" : `${type}s`)}`),
    h("ul", {}, bad.map((s) => h("li", {}, h("b", {}, s.name), `: ${s.detail}. `, s.fix ? richText(s.fix) : null))));
}

// ---------- views ----------
function overview() {
  const all = findings();
  const c = counts(all);
  const bad = c.critical + c.error;
  const verdict = bad ? `${plural(bad, "problem needs", "problems need")} you.` : c.warning ? "Nothing is broken." : "Everything checks out.";
  const sub = bad ? `Plus ${plural(c.warning, "warning", "warnings")} and ${plural(c.info, "suggestion", "suggestions")}.`
    : c.warning ? `${plural(c.warning, "thing", "things")} could be better.` : c.info ? `${plural(c.info, "suggestion", "suggestions")} if you have time.` : "";
  const urgent = all.filter((f) => f.severity !== "info").sort(bySeverity);
  const saving = savingsTotal(all);
  const savers = all.filter((f) => f.savings_usd_month > 0).sort((a, b) => b.savings_usd_month - a.savings_usd_month);
  const dd = sources().some((x) => x.type === "datadog");
  const now = shiftsNow();
  const wfs = metrics("workflow");
  const worst = wfs.filter((w) => w.success_rate != null && w.runs >= 3).sort((a, b) => a.success_rate - b.success_rate).slice(0, 5);
  const busiest = [...wfs].sort((a, b) => b.minutes - a.minutes).slice(0, 5);
  const unread = sources().filter((x) => !x.ok).length;

  const right = [];
  if (dd && metrics("shift").length) {
    const mine = now.filter(isMine);
    right.push(panel("On call now", "#oncall", (mine.length ? mine : now).length
      ? h("dl", { class: "kv" }, (mine.length ? mine : now).map((x) => [h("dt", {}, h("b", {}, x.name), h("span", { class: "muted" }, ` ${x.schedule}`)), h("dd", { class: "muted" }, `until ${when(x.end)}`)]))
      : h("p", { class: "empty" }, "Nobody on call right now.")));
  }
  if (savers.length) right.push(panel("Top savings", "#actions", h("dl", { class: "kv" }, savers.slice(0, 5).map((f) => [h("dt", { title: f.resource }, f.resource.split("/").slice(1).join("/")), h("dd", { class: "save" }, `${usd(f.savings_usd_month)}/mo`)])), `${usd(saving)}/mo`));
  if (worst.length) right.push(panel("Least reliable pipelines", "#pipelines", h("dl", { class: "kv" }, worst.map((w) => [h("dt", { title: `${w.repo} › ${w.workflow}` }, `${w.repo} › ${w.workflow}`), h("dd", { class: w.success_rate < 0.7 ? "bad" : w.success_rate < 0.9 ? "warn" : "" }, pctText(w.success_rate))]))));
  if (busiest.length) right.push(panel("Where CI time goes", "#pipelines", h("dl", { class: "kv" }, busiest.map((w) => [h("dt", { title: `${w.repo} › ${w.workflow}` }, `${w.repo} › ${w.workflow}`), h("dd", {}, `${num(w.minutes)} min`)])), `${usd(ciCost())} / 30 days`));
  if (unread) right.push(panel("Couldn't read", "#sources", h("p", { class: "muted" }, `${plural(unread, "source", "sources")} couldn't be read, so they have no findings. See why in Sources.`)));

  return [
    lede(verdict, bad ? "bad" : "", sub),
    stats([["Fix now", num(bad), bad ? "bad" : "", "#actions"], ["This week", num(c.warning), c.warning ? "warn" : "", "#actions"],
           ["Potential savings", `${usd(saving)}/mo`, saving ? "save" : "", "#actions"], ["Spend tracked", `${usd(spendTracked())}/mo`, "", "#utilization"],
           ["CI success", pctText(ciSuccess()), "", "#pipelines"],
           ...(dd ? [["On call now", (now.filter(isMine)[0] || now[0] || { name: "–" }).name, "", "#oncall"]] : [])]),
    h("div", { class: "board" },
      h("div", {},
        panel("Needs you", "#actions", urgent.length ? findingList(urgent, 6) : h("p", { class: "empty" }, "No errors or warnings."),
          urgent.length > 6 ? `${urgent.length - 6} more` : null),
        h("h2", {}, "Access"), chains()),
      h("div", {}, right)),
  ];
}

function ciSuccess() {
  const wfs = metrics("workflow").filter((w) => w.success_rate != null);
  const runs = wfs.reduce((a, w) => a + w.runs, 0);
  return runs ? wfs.reduce((a, w) => a + w.success_rate * w.runs, 0) / runs : null;
}

function actionGroups() {
  const all = findings();
  const savers = all.filter((f) => f.savings_usd_month > 0).sort((a, b) => b.savings_usd_month - a.savings_usd_month);
  const saverSet = new Set(savers);
  return [
    { id: "now", title: "Fix now", note: "Broken or about to break.", items: all.filter((f) => (f.severity === "critical" || f.severity === "error") && !saverSet.has(f)) },
    { id: "save", title: "Save money", note: "Largest monthly savings first, at on-demand list price (your discounts would lower them).", items: savers },
    { id: "week", title: "This week", note: "Risks and gaps worth fixing soon.", items: all.filter((f) => f.severity === "warning" && !saverSet.has(f)) },
    { id: "hygiene", title: "Hygiene", note: "Small improvements.", items: all.filter((f) => f.severity === "info" && !saverSet.has(f)) },
  ];
}

function markdown(groups) {
  const lines = [`# Platform action items, ${new Date(app.report.generated_at).toLocaleDateString("en-US", { month: "long", day: "numeric", year: "numeric" })}`];
  for (const g of groups) {
    if (!g.items.length) continue;
    lines.push("", `## ${g.title}${g.id === "save" ? ` (${usd(savingsTotal(g.items))}/month)` : ""}`, "");
    for (const f of g.items) {
      lines.push(`- [ ] **${f.resource}**: ${f.message}${f.savings_usd_month ? ` (save about ${usd(f.savings_usd_month)}/month)` : ""}`);
      if (f.fix) lines.push(`  - Fix: ${f.fix}`);
      if (f.link) lines.push(`  - ${f.link}`);
    }
  }
  return lines.join("\n") + "\n";
}

function actions() {
  const groups = actionGroups();
  const [now, save, week] = groups;
  const copy = h("button", { type: "button" }, "Copy as Markdown");
  copy.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(markdown(groups)); copy.textContent = "Copied"; }
    catch { copy.textContent = "Couldn't copy"; }
    setTimeout(() => { copy.textContent = "Copy as Markdown"; }, 1500);
  });
  const verdict = now.items.length ? `${plural(now.items.length, "thing needs", "things need")} fixing now.`
    : save.items.length ? `You could save about ${usd(savingsTotal(save.items))} a month.` : week.items.length ? "Nothing urgent." : "Nothing to do.";
  return [
    h("h2", { class: `verdict${now.items.length ? " bad" : ""}` }, verdict),
    h("p", { class: "verdict-sub" }, "Every finding as a to-do, in the order worth doing them. Copy the list into a ticket or a message."),
    stats([["Fix now", num(now.items.length), now.items.length ? "bad" : ""], ["Save money", `${usd(savingsTotal(save.items))}/mo`, save.items.length ? "save" : ""],
           ["This week", num(week.items.length), week.items.length ? "warn" : ""], ["Hygiene", num(groups[3].items.length)]]),
    h("div", { class: "toolbar" }, copy),
    groups.map((g) => g.items.length
      ? h("details", { class: "group", open: g.id !== "hygiene" },
          h("summary", {}, h("span", { class: "group-name" }, g.title),
            h("span", { class: "tally" }, g.id === "save" ? `${plural(g.items.length, "item", "items")}, ${usd(savingsTotal(g.items))}/month` : plural(g.items.length, "item", "items"))),
          h("p", { class: "section-note group-note" }, g.note), findingList(g.items))
      : null),
  ];
}

// ---------- who's on call ----------
function when(iso) {
  return new Date(iso).toLocaleString("en-US", { weekday: "short", month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}
// From datadog.people_teams (their members) plus datadog.people.
function myPeople() {
  const row = metrics("oncall_people")[0];
  return row ? row.emails : (app.report.settings && app.report.settings.oncall_people) || [];
}
function peopleLabel() {
  const row = metrics("oncall_people")[0];
  const teams = row ? row.teams.filter((x) => x.found) : [];
  const extra = row ? row.emails.length - teams.reduce((a, x) => a + x.members, 0) : myPeople().length;
  const parts = teams.map((x) => `${x.name} (${plural(x.members, "person", "people")})`);
  if (extra > 0) parts.push(plural(extra, "other person", "other people"));
  return parts.length ? parts.join(" + ") : plural(myPeople().length, "person", "people");
}
function isMine(shift) { const mine = myPeople(); return !mine.length || mine.includes((shift.email || "").toLowerCase()); }
function shiftsNow() {
  const t = Date.now();
  return metrics("shift").filter((x) => Date.parse(x.start) <= t && Date.parse(x.end) > t);
}

function whoIsOnCall() {
  const all = metrics("shift");
  if (!all.length) return null;
  const mine = myPeople();
  const t = Date.now();
  const days = (app.report.settings && app.report.settings.oncall_days) || 7;
  const schedules = [...new Set(all.map((x) => x.schedule))];
  const now = shiftsNow();
  const cards = schedules.map((sch) => {
    const cur = now.filter((x) => x.schedule === sch);
    return h("div", { class: "oncall-card" },
      h("small", {}, sch),
      cur.length ? cur.map((x) => h("p", { class: `who${isMine(x) && mine.length ? " mine" : ""}` }, x.name, h("span", { class: "muted" }, ` until ${when(x.end)}`)))
        : h("p", { class: "who none" }, "Nobody on call right now"));
  });
  const week = all.filter((x) => Date.parse(x.end) > t).filter((x) => app.everyone || isMine(x)).sort((a, b) => Date.parse(a.start) - Date.parse(b.start));
  const toggle = mine.length ? h("button", { type: "button" }, app.everyone ? "Show only my people" : "Show everyone") : null;
  if (toggle) toggle.addEventListener("click", () => { app.everyone = !app.everyone; render(); });
  return [
    h("h2", {}, "Who's on call"),
    h("div", { class: "oncall-now" }, cards),
    h("div", { class: "toolbar week-head" },
      h("span", { class: "group-name" }, `Next ${days} days`),
      mine.length ? h("span", { class: "tally" }, app.everyone ? "everyone" : peopleLabel()) : null, toggle),
    week.length
      ? table([["Who"], ["Schedule"], ["From"], ["To"], [""]], week.map((x) => {
          const on = Date.parse(x.start) <= t && Date.parse(x.end) > t;
          return h("tr", { class: on ? "row-now" : "" },
            h("td", {}, h("b", {}, x.name), x.email ? h("small", { class: "muted" }, ` ${x.email}`) : null),
            h("td", {}, x.schedule), h("td", {}, when(x.start)), h("td", {}, when(x.end)),
            h("td", {}, on ? h("span", { class: "chip-s ok" }, "On call now") : ""));
        }))
      : h("p", { class: "empty" }, mine.length && !app.everyone ? `None of your people are on call in the next ${days} days.` : `No shifts in the next ${days} days.`),
  ];
}

function oncall() {
  const src = sources().find((x) => x.type === "datadog");
  if (!src) {
    return [h("h2", { class: "verdict" }, "Datadog isn't set up."),
      h("p", { class: "verdict-sub" }, "Add a datadog section to ~/.config/platform-manager/config.yaml with your site, install Pup (brew install datadog-labs/pack/pup), run pup auth login, then sync.")];
  }
  const pages = metrics("page").filter((x) => !["resolved", "closed"].includes(x.status));
  const unacked = pages.filter((x) => x.status !== "acknowledged");
  const incidents = metrics("incident").filter((x) => ["active", "stable"].includes(x.state));
  const alerting = metrics("monitor").filter((x) => x.status === "alert");
  const warns = metrics("monitor").filter((x) => x.status === "warn" || x.status === "no data");
  const auth = findings().find((f) => f.check === "datadog.auth" || f.check === "datadog.no_cli" || f.check === "datadog.unreachable");
  const linkTo = (url, text) => h("a", { href: url, target: "_blank", rel: "noopener noreferrer" }, text);
  const out = [
    h("h2", { class: `verdict${unacked.length || alerting.length || auth ? " bad" : ""}` },
      auth ? "Pup can't read Datadog." : unacked.length ? `${plural(unacked.length, "page needs", "pages need")} acknowledging.`
        : alerting.length ? `${plural(alerting.length, "monitor is", "monitors are")} alerting.` : incidents.length ? "Pages are handled." : "All quiet."),
    h("p", { class: "verdict-sub" }, `Datadog on ${src.name}: open pages, active incidents and alerting monitors, read-only through Pup.`),
  ];
  if (auth) {
    out.push(h("div", { class: "callout" }, h("p", { class: "callout-title" }, auth.message), h("p", {}, richText(auth.fix))));
    return out;
  }
  out.push(stats([["Unacknowledged pages", num(unacked.length), unacked.length ? "bad" : ""], ["Open pages", num(pages.length), pages.length ? "warn" : ""],
    ["Active incidents", num(incidents.filter((x) => x.state === "active").length), incidents.some((x) => x.state === "active") ? "bad" : ""],
    ["Alerting monitors", num(alerting.length), alerting.length ? "bad" : ""], ["Warning or no data", num(warns.length), warns.length ? "warn" : ""]]));
  out.push(sourceProblems("datadog"));
  out.push(whoIsOnCall());
  const ago2 = (min) => (min == null ? "–" : min < 60 ? `${min}m` : min < 2880 ? `${Math.floor(min / 60)}h` : `${Math.floor(min / 1440)}d`);
  out.push(h("h2", {}, "Pages"), pages.length
    ? table([["Page"], ["Status"], ["Urgency"], ["Team"], ["Open for", 1]], pages.map((x) => h("tr", { class: x.status === "acknowledged" ? "" : "row-bad" },
        h("td", {}, linkTo(x.url, x.title)), h("td", {}, h("span", { class: `chip-s ${x.status === "acknowledged" ? "off" : "bad"}` }, x.status || "open")),
        h("td", {}, x.urgency || "–"), h("td", {}, x.team || "–"), h("td", { class: "n" }, ago2(x.opened_min)))))
    : h("p", { class: "empty" }, "No open pages."));
  out.push(h("h2", {}, "Incidents"), incidents.length
    ? table([["Incident"], ["Severity"], ["State"], ["Customers"], ["Open for", 1]], incidents.map((x) => h("tr", { class: x.state === "active" ? "row-bad" : "" },
        h("td", {}, linkTo(x.url, `${x.number ? `#${x.number} ` : ""}${x.title}`)), h("td", {}, x.severity), h("td", {}, x.state),
        h("td", {}, x.customer_impacted ? "Affected" : "–"), h("td", { class: "n" }, ago2(x.opened_min)))))
    : h("p", { class: "empty" }, "No active or stable incidents."));
  const mons = [...alerting, ...warns];
  out.push(h("h2", {}, "Monitors"), mons.length
    ? table([["Monitor"], ["Status"], ["Priority", 1], ["Since", 1]], mons.map((x) => h("tr", { class: x.status === "alert" ? "row-bad" : "" },
        h("td", {}, linkTo(x.url, x.name)), h("td", {}, h("span", { class: `chip-s ${x.status === "alert" ? "bad" : "off"}` }, x.status)),
        h("td", { class: "n" }, x.priority ? `P${x.priority}` : "–"), h("td", { class: "n" }, ago2(x.triggered_min)))))
    : h("p", { class: "empty" }, "No monitors alerting, warning or missing data."));
  return out;
}

function security() {
  const rows = metrics("exposure");
  const list = inView("security");
  const checked = sources().filter((x) => x.type === "security");
  if (!checked.length) {
    return [lede("No accounts checked.", "", "The security check runs on every AWS account with a working session. Sign in (Access view), then sync.")];
  }
  const flagged = rows.filter((x) => !x.allowed);
  const c = counts(list);
  const envs = [...new Set(rows.map((x) => x.env || "untagged"))];
  const container = h("div");
  const draw = () => {
    const shown = list.filter(passes);
    container.replaceChildren(...(shown.length
      ? grouped(shown, (f) => f.resource.split("/").slice(0, 2).join(" › "), () => true)
      : [h("p", { class: "empty" }, list.length ? "No findings match these filters." : "No exposure findings.")]));
  };
  draw();
  return [
    lede(c.critical + c.error ? `${plural(c.critical + c.error, "exposure needs", "exposures need")} closing.` : flagged.length || c.warning ? "Nothing is wide open." : "Only the public load balancer faces the internet.",
      c.critical + c.error ? "bad" : "",
      "Private VPCs everywhere; 0.0.0.0/0 belongs only on the production internet-facing load balancer, on web ports."),
    stats([["Reachable from the internet", num(rows.length)], ["Allowed", num(rows.length - flagged.length)],
           ["Flagged", num(flagged.length), flagged.length ? "bad" : ""], ["Errors", num(c.critical + c.error), c.critical + c.error ? "bad" : ""],
           ["Warnings", num(c.warning), c.warning ? "warn" : ""], ["Environments seen", envs.length ? envs.join(", ") : "–"]]),
    sourceProblems("security"),
    h("h2", {}, "Internet-reachable", h("span", { class: "tally" }, `${plural(rows.length, "resource", "resources")} across ${plural(checked.length, "account", "accounts")}`)),
    rows.length
      ? table([["Resource"], ["Type"], ["Environment"], ["Open to"], ["Account"], ["Status"]],
          [...rows].sort((a, b) => a.allowed - b.allowed).map((x) => h("tr", { class: x.allowed ? "" : "row-bad" },
            h("td", {}, h("b", { class: "mono" }, x.id), x.name && x.name !== x.id ? h("small", { class: "muted" }, ` ${x.name}`) : null),
            h("td", {}, x.type), h("td", {}, x.env || h("span", { class: "muted" }, "untagged")), h("td", {}, x.detail),
            h("td", {}, `${x.account} (${x.region})`),
            h("td", {}, h("span", { class: `chip-s ${x.allowed ? "ok" : "bad"}` }, x.allowed ? "Allowed" : "Flagged")))))
      : h("p", { class: "empty" }, "Nothing is reachable from the internet in the accounts checked."),
    h("h2", {}, "Findings"),
    filters(draw, "Filter by account, group or resource"),
    container,
  ];
}

function access() {
  const list = inView("access").sort(bySeverity);
  return [
    h("h2", { class: "verdict" }, hasErrors(list) ? "Some access is broken." : "Access is working."),
    h("p", { class: "verdict-sub" }, "Each row follows the path a command takes: your AWS session, then the cluster's API, then what runs on it."),
    chains(),
    h("h2", {}, "Findings"),
    list.length ? findingList(list) : h("p", { class: "empty" }, "No access problems."),
  ];
}

function workloads() {
  const reachable = (app.report.clusters || []).filter((c) => c.kubernetes === "ok");
  if (!reachable.length) {
    return [
      h("h2", { class: "verdict" }, "No cluster to read."),
      h("p", { class: "verdict-sub" }, "pmgr reads workloads and events from clusters it can reach, and none are reachable right now. The Access view shows what's in the way."),
    ];
  }
  const container = h("div");
  const draw = () => {
    const list = inView("workloads").filter(passes);
    // Group by cluster and namespace (nodes group under the cluster).
    const key = (f) => {
      const [cluster, ns] = f.resource.split("/");
      return ns === "node" ? `${cluster} › nodes` : `${cluster} › ${ns}`;
    };
    container.replaceChildren(
      ...(list.length ? grouped(list, key, (items) => items.some((f) => f.severity !== "info")) : [h("p", { class: "empty" }, "No workload problems match these filters.")]),
    );
  };
  draw();
  const all = inView("workloads");
  return [
    h("h2", { class: `verdict${hasErrors(all) ? " bad" : ""}` }, hasErrors(all) ? "Some workloads are failing." : all.length ? "Workloads are running." : "Workloads are healthy."),
    h("p", { class: "verdict-sub" }, `Pods, controllers, nodes, volumes and jobs on ${reachable.map((c) => c.name).join(", ")}, plus Warning events from the last hour that status alone doesn't explain.`),
    filters(draw, "Filter by namespace, workload or text"),
    container,
    unseenNote(),
  ];
}

function utilization() {
  const all = inView("utilization");
  const container = h("div");
  const draw = () => {
    const list = all.filter(passes);
    // "account/region/service/resource" (or "cluster/eks/what"): group by account, region and service.
    const key = (f) => {
      const parts = f.resource.split("/");
      const [where, region, service] = SERVICE[parts[1]] ? [parts[0], "", parts[1]] : parts;
      return `${where}${region ? ` (${region})` : ""} › ${SERVICE[service] || service}`;
    };
    container.replaceChildren(
      ...(list.length ? grouped(list, key, () => true) : [h("p", { class: "empty" }, all.length ? "No findings match these filters." : "Nothing is notably over- or under-used.")]),
    );
  };
  draw();
  const svcTables = [];
  const rds = metrics("rds");
  if (rds.length) svcTables.push(h("h2", {}, "RDS"), table(
    [["Instance"], ["Account"], ["Class"], ["Engine"], ["CPU avg", 1], ["CPU p95", 1], ["CPU max", 1], ["Connections", 1], ["Free storage", 1], ["$/month", 1]],
    rds.map((m) => h("tr", {}, h("td", {}, h("b", {}, m.name), m.multi_az ? h("small", { class: "muted" }, " Multi-AZ") : null), h("td", {}, m.region ? `${m.account} (${m.region})` : m.account),
      h("td", {}, m.class), h("td", {}, m.engine), pcell(m.cpu_avg), pcell(m.cpu_p95, 80), pcell(m.cpu_max), h("td", { class: "n" }, num(m.connections_max)),
      h("td", { class: `n ${m.free_storage_pct != null && m.free_storage_pct < 15 ? "warn" : ""}` }, m.free_storage_pct == null ? "–" : `${m.free_storage_pct}%`),
      h("td", { class: "n" }, usd(m.monthly_usd))))));
  const cache = metrics("elasticache");
  if (cache.length) svcTables.push(h("h2", {}, "ElastiCache"), table(
    [["Cluster"], ["Account"], ["Nodes", 1], ["Node type"], ["CPU avg", 1], ["CPU p95", 1], ["Memory max", 1], ["Evictions", 1], ["$/month", 1]],
    cache.map((m) => h("tr", {}, h("td", {}, h("b", {}, m.name)), h("td", {}, m.region ? `${m.account} (${m.region})` : m.account), h("td", { class: "n" }, num(m.nodes)), h("td", {}, m.class),
      pcell(m.cpu_avg), pcell(m.cpu_p95, 80), pcell(m.memory_max, 80), h("td", { class: `n ${m.evictions ? "warn" : ""}` }, num(m.evictions)), h("td", { class: "n" }, usd(m.monthly_usd))))));
  const rs = metrics("redshift");
  if (rs.length) svcTables.push(h("h2", {}, "Redshift"), table(
    [["Cluster"], ["Account"], ["Nodes", 1], ["Node type"], ["CPU avg", 1], ["CPU p95", 1], ["Disk used", 1], ["$/month", 1]],
    rs.map((m) => h("tr", {}, h("td", {}, h("b", {}, m.name)), h("td", {}, m.region ? `${m.account} (${m.region})` : m.account), h("td", { class: "n" }, num(m.nodes)), h("td", {}, m.class),
      pcell(m.cpu_avg), pcell(m.cpu_p95, 80), pcell(m.disk_used_max, 80), h("td", { class: "n" }, usd(m.monthly_usd))))));
  const msk = metrics("msk");
  if (msk.length) svcTables.push(h("h2", {}, "MSK"), table(
    [["Cluster"], ["Account"], ["Brokers", 1], ["Broker type"], ["CPU avg", 1], ["CPU p95", 1], ["Disk used", 1], ["$/month", 1]],
    msk.map((m) => h("tr", {}, h("td", {}, h("b", {}, m.name)), h("td", {}, m.region ? `${m.account} (${m.region})` : m.account), h("td", { class: "n" }, num(m.nodes)), h("td", {}, m.class),
      pcell(m.cpu_avg), pcell(m.cpu_p95, 60), pcell(m.disk_used_max, 75), h("td", { class: "n" }, usd(m.monthly_usd))))));
  const eks = metrics("eks");
  if (eks.length) svcTables.push(h("h2", {}, "EKS"), table(
    [["Cluster"], ["Version"], ["Nodes", 1], ["Node types"], ["Requests CPU", 1], ["Requests mem", 1], ["Usage CPU", 1], ["Usage mem", 1], ["$/month", 1]],
    eks.map((m) => h("tr", {}, h("td", {}, h("b", {}, m.name)), h("td", {}, m.version || "–"), h("td", { class: "n" }, num(m.nodes)),
      h("td", {}, m.node_types.map((t) => `${t.count} × ${t.type}${t.spot ? " (spot)" : ""}`).join(", ")),
      pcell(m.requests_cpu_pct, 90, 40), pcell(m.requests_mem_pct, 90, 40), pcell(m.usage_cpu_pct), pcell(m.usage_mem_pct),
      h("td", { class: "n" }, m.monthly_usd != null ? usd(m.monthly_usd) : "–")))));
  const monthly = ((app.report && app.report.metrics) || []).filter((m) => m.kind !== "workflow").reduce((a, m) => a + (m.monthly_usd || 0), 0);
  const savingAll = savingsTotal(all);
  const hot = all.filter((f) => f.severity !== "info" && !f.check.endsWith(".idle")).length;
  const idle = all.filter((f) => f.check.endsWith(".idle")).length;
  const roomy = all.filter((f) => f.severity === "info").length;
  const parts = [];
  if (hot) parts.push(plural(hot, "resource is running hot", "resources are running hot"));
  if (idle) parts.push(plural(idle, "looks idle", "look idle"));
  if (roomy) parts.push(plural(roomy, "could be smaller", "could be smaller"));
  const days = app.report.settings && app.report.settings.utilization_days;
  return [
    h("h2", { class: `verdict${hasErrors(all) ? " bad" : ""}` }, parts.length ? `${parts[0][0].toUpperCase()}${parts[0].slice(1)}.` : "Capacity looks right."),
    h("p", { class: "verdict-sub" }, (parts.length > 1 ? `Also, ${parts.slice(1).join(" and ")}. ` : "")
      + `RDS, Redshift, ElastiCache and MSK are judged on ${days || 14} days of CloudWatch metrics; EKS on requests, capacity and current usage.`),
    stats([["Monthly cost", `${usd(monthly)}/mo`], ["Potential savings", `${usd(savingAll)}/mo`, savingAll ? "save" : ""],
           ["Running hot", num(hot), hot ? "warn" : ""], ["Idle", num(idle), idle ? "warn" : ""], ["Could be smaller", num(roomy)]]),
    h("p", { class: "section-note" }, "Costs are on-demand list prices for compute (instances, nodes, brokers), not storage or data transfer."),
    svcTables,
    h("h2", {}, "Findings"),
    filters(draw, "Filter by account, service or name"),
    container,
    unseenNote(),
  ];
}

// A percent cell, colored when it's high (or, with a low mark, low).
function pcell(v, high, low) {
  const cls = v == null ? "" : high != null && v >= high ? "warn" : low != null && v < low ? "muted" : "";
  return h("td", { class: `n ${cls}`, "data-sort": v == null ? -1 : v }, v == null ? "–" : `${v}%`, bar(v, high));
}

function pipelines() {
  const wfs = metrics("workflow");
  const list = inView("pipelines");
  const days = app.report.settings ? app.report.settings.lookback_days : 14;
  const repos = app.report.settings && app.report.settings.repos.length ? app.report.settings.repos.map((r) => r.name) : [...new Set(wfs.map((w) => w.repo))];
  if (!repos.length) {
    return [h("h2", { class: "verdict" }, "No repos configured."), h("p", { class: "verdict-sub" }, "List your repos under github.repos in ~/.config/platform-manager/config.yaml, then sync.")];
  }
  const runs = wfs.reduce((a, w) => a + w.runs, 0);
  const counted = wfs.filter((w) => w.success_rate != null);
  const overall = counted.length ? counted.reduce((a, w) => a + w.success_rate * w.runs, 0) / counted.reduce((a, w) => a + w.runs, 0) : null;
  const minutes = wfs.reduce((a, w) => a + w.minutes, 0);
  const broken = wfs.filter((w) => w.broken).length;
  return [
    h("h2", { class: `verdict${broken ? " bad" : ""}` }, broken ? `${plural(broken, "workflow is", "workflows are")} failing on the default branch.` : wfs.length ? "Pipelines are passing." : "No pipeline data yet."),
    h("p", { class: "verdict-sub" }, `Every workflow's last ${days} days. Success counts completed runs on all branches; "default" is the default branch only. Minutes are run time, close to billed minutes.`),
    stats([["Workflows", num(wfs.length)], ["Runs", num(runs)], ["Success", pctText(overall), overall != null && overall < 0.9 ? "warn" : ""],
           ["CI minutes", num(minutes)], ["CI cost / 30 days", usd(ciCost())], ["Failing now", num(broken), broken ? "bad" : ""]]),
    sourceProblems("repo"),
    repos.map((repo) => {
      const rows = wfs.filter((w) => w.repo === repo).sort((a, b) => b.minutes - a.minutes);
      const src = sources().find((s) => s.type === "repo" && s.name === repo);
      const mine = list.filter((f) => f.resource.startsWith(`${repo}:`));
      return h("section", { class: "repo" },
        h("h2", {}, repo, h("span", { class: "tally" }, src ? ` ${src.detail}` : "")),
        rows.length
          ? table([["Workflow"], ["Runs", 1], ["Success", 1], ["Default", 1], ["p50", 1], ["p95", 1], ["Queue p95", 1], ["Minutes", 1], ["Last run"]],
              rows.map((w) => h("tr", { class: w.broken ? "row-bad" : "" },
                h("td", {}, h("span", { class: "wf" }, w.workflow), w.reruns ? h("small", { class: "muted" }, ` ${w.reruns} reruns`) : null),
                h("td", { class: "n" }, num(w.runs)), rateCell(w.success_rate), rateCell(w.main_success_rate),
                h("td", { class: "n" }, dur(w.duration_p50_s)), h("td", { class: "n" }, dur(w.duration_p95_s)),
                h("td", { class: `n ${w.queue_p95_s >= 300 ? "warn" : ""}` }, dur(w.queue_p95_s)),
                h("td", { class: "n" }, num(w.minutes)), h("td", {}, statusChip(w.last)))))
          : h("p", { class: "empty" }, src && !src.ok ? `Not read: ${src.detail}.` : `No runs in the last ${days} days.`),
        mine.length ? findingList(mine.sort(bySeverity)) : null);
    }),
  ];
}

function sourcesView() {
  const all = sources();
  const bad = all.filter((s) => !s.ok);
  const label = { cluster: "Cluster", account: "AWS account", repo: "Repo", datadog: "Datadog", security: "Security check" };
  return [
    h("h2", { class: `verdict${bad.length ? " bad" : ""}` }, bad.length ? `pmgr couldn't read ${plural(bad.length, "source", "sources")}.` : "pmgr could read everything."),
    h("p", { class: "verdict-sub" }, "What each check tried to read and what happened. When something is missing from another view, the reason is here."),
    all.length
      ? table([["Source"], ["Name"], ["Status"], ["What happened"]],
          [...all].sort((a, b) => a.ok - b.ok).map((s) => h("tr", { class: s.ok ? "" : "row-bad" },
            h("td", {}, label[s.type] || s.type), h("td", {}, h("b", {}, s.name)),
            h("td", {}, h("span", { class: `chip-s ${s.ok ? "ok" : "bad"}` }, s.ok ? "Read" : "Not read")),
            h("td", {}, s.detail, s.fix ? h("div", { class: "fix-line" }, richText(s.fix)) : null))))
      : h("p", { class: "empty" }, "Nothing has been checked yet."),
  ];
}

function workflows() {
  const container = h("div");
  const draw = () => {
    const list = inView("workflows").filter(passes);
    container.replaceChildren(
      ...(list.length
        ? grouped(list, (f) => f.resource.split(":")[0], (items) => items.some((f) => f.severity !== "info"))
        : [h("p", { class: "empty" }, "No findings match these filters.")]),
    );
  };
  draw();
  return [
    (() => {
      const all = inView("workflows");
      const repos = new Set(all.map((f) => f.resource.split(":")[0])).size;
      const c = counts(all);
      return h("h2", { class: `verdict${c.critical + c.error ? " bad" : ""}` },
        all.length ? `${plural(c.critical + c.error + c.warning, "gap", "gaps")} to fix across ${plural(repos, "repo", "repos")}.` : "No workflow gaps.");
    })(),
    h("p", { class: "verdict-sub" }, "What your workflow files allow: unpinned actions, broad tokens, long-lived keys, missing checks and wasted minutes."),
    filters(draw),
    container,
  ];
}

function argo() {
  const list = inView("argo");
  const reachable = (app.report.clusters || []).filter((c) => c.kubernetes === "ok");
  return [
    reachable.length
      ? [h("h2", { class: "verdict" }, hasErrors(list) ? "Some apps are failing." : "Argo CD apps are healthy."),
         h("p", { class: "verdict-sub" }, "Failed syncs, degraded apps, stuck operations, render errors, and apps that won't converge.")]
      : [h("h2", { class: "verdict" }, "No Argo CD to read."),
         h("p", { class: "verdict-sub" }, "pmgr reads Argo CD Applications from clusters it can reach, and none were reachable at the last sync. The Access view shows what's in the way.")],
    (app.report.clusters || []).length === 0 ? null : h("section", { class: "panel" },
      h("div", { class: "panel-head" }, h("h3", {}, "Environments"),
        h("span", { class: "tally" }, app.live ? "Tunnels are kubectl port-forwards on this machine, read-only to the cluster" : "Tunnels work in pmgr ui")),
      h("div", { id: "tunnels" }, (setTimeout(refreshTunnels, 0), tunnelTable()))),
    reachable.length ? [
      h("h2", {}, "Applications"),
      list.length
        ? grouped(list, (f) => f.resource.split("/")[0], () => true)
        : h("p", { class: "empty" }, `No Argo CD problems on ${reachable.map((c) => c.name).join(", ")}.`),
      unseenNote()] : null,
  ];
}

const RENDER = { overview, actions, oncall, access, security, workloads, utilization, pipelines, workflows, argo, sources: sourcesView };

// ---------- shell ----------
const NAV = [
  ["Today", [["overview", "Overview"], ["actions", "Action items"], ["oncall", "On-call"]]],
  ["Infrastructure", [["access", "Access"], ["security", "Security"], ["workloads", "Workloads"], ["utilization", "Utilization"], ["argo", "Argo CD"]]],
  ["Delivery", [["pipelines", "Pipelines"], ["workflows", "Workflow gaps"]]],
  ["System", [["sources", "Sources"]]],
];
const TITLES = Object.fromEntries(NAV.flatMap(([, items]) => items));

function currentView() {
  const v = location.hash.replace(/^#/, "");
  return VIEWS.includes(v) ? v : "overview";
}

function navBadge(v) {
  if (!app.report) return null;
  let n = 0;
  let tone = "warn";
  if (v === "actions") {
    const g = actionGroups();
    n = g[0].items.length + g[2].items.length;
    if (g[0].items.length) tone = "bad";
  } else if (v === "sources") {
    n = sources().filter((x) => !x.ok).length;
  } else if (AREAS[v]) {
    const c = counts(inView(v));
    n = c.critical + c.error + c.warning;
    if (c.critical + c.error) tone = "bad";
  }
  return n ? h("span", { class: `badge ${tone}` }, String(n)) : null;
}

function renderNav(view) {
  document.getElementById("nav").replaceChildren(...NAV.map(([group, items]) =>
    h("div", { class: "nav-group" }, h("span", {}, group),
      items.map(([v, label]) => {
        const a = h("a", { href: `#${v}`, "aria-current": v === view ? "page" : null }, label, navBadge(v));
        a.addEventListener("click", () => { app.q = ""; });   // a fresh view starts unfiltered
        return a;
      }))));
}

function renderChecked() {
  const el = document.getElementById("checked");
  if (!app.report) { el.textContent = ""; return; }
  const at = new Date(app.report.generated_at);
  el.textContent = `Synced ${ago(app.report.generated_at).replace(" ago", "")} ago`.replace("Synced 1m ago", "Synced just now");
  el.title = at.toLocaleString("en-US", { dateStyle: "long", timeStyle: "short" });
}

function render() {
  const view = currentView();
  renderNav(view);
  document.getElementById("title").textContent = TITLES[view] || "Overview";
  document.title = `${TITLES[view] || "Overview"} · pmgr`;
  renderChecked();
  const main = document.getElementById("main");
  if (!app.report) {
    main.replaceChildren(h("p", { class: "empty" }, "This page has no report in it. Run pmgr ui to make one."));
    return;
  }
  main.replaceChildren(...[RENDER[view]()].flat(3).filter(Boolean));
  renderSync();
}

// ---------- search everything ----------
function searchIndex() {
  const items = [];
  const areaView = Object.fromEntries(Object.entries(AREAS).flatMap(([v, areas]) => areas.map((a) => [a, v])));
  for (const x of sources()) items.push({ kind: { repo: "Repo", cluster: "Cluster", account: "AWS account", datadog: "Datadog" }[x.type] || x.type, label: `${x.name}  ${x.detail}`, view: x.type === "repo" ? "pipelines" : x.type === "datadog" ? "oncall" : "access", q: x.name });
  for (const w of metrics("workflow")) items.push({ kind: "Workflow", label: `${w.repo} › ${w.workflow}`, view: "pipelines", q: w.repo });
  for (const k of ["rds", "elasticache", "redshift", "msk", "eks"]) for (const m of metrics(k)) items.push({ kind: SERVICE[k], label: `${m.name}  ${m.class || m.version || ""}`, view: "utilization", q: m.name });
  for (const sch of new Set(metrics("shift").map((x) => x.schedule))) items.push({ kind: "Schedule", label: sch, view: "oncall", q: "" });
  for (const who of new Set(metrics("shift").map((x) => `${x.name}|${x.email}`))) items.push({ kind: "Person", label: who.replace("|", "  "), view: "oncall", q: "" });
  for (const f of [...findings()].sort(bySeverity)) items.push({ kind: SEV_LABEL[f.severity], label: `${f.resource}: ${f.message}`, view: areaView[f.area] || "actions", q: f.resource });
  return items;
}

function setupSearch() {
  const input = document.getElementById("search");
  const box = document.getElementById("results");
  let hits = [];
  let at = 0;
  const go = (hit) => {
    app.q = hit.q || "";
    box.hidden = true;
    input.value = "";
    input.blur();
    if (location.hash === `#${hit.view}`) render();
    else location.hash = hit.view;
  };
  const draw = () => {
    const q = input.value.trim().toLowerCase();
    if (!q || !app.report) { box.hidden = true; return; }
    const words = q.split(/\s+/);
    hits = searchIndex().filter((x) => words.every((w) => `${x.kind} ${x.label}`.toLowerCase().includes(w))).slice(0, 12);
    at = Math.min(at, Math.max(0, hits.length - 1));
    box.replaceChildren(...(hits.length ? hits.map((x, i) => {
      const a = h("a", { href: `#${x.view}`, role: "option", class: i === at ? "on" : "" }, h("span", { class: "kind" }, x.kind), h("span", { class: "label" }, x.label));
      a.addEventListener("click", (e) => { e.preventDefault(); go(x); });
      return a;
    }) : [h("p", { class: "empty", style: "padding:8px 10px;margin:0" }, "Nothing matches.")]));
    box.hidden = false;
  };
  input.addEventListener("input", () => { at = 0; draw(); });
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { at = Math.min(at + 1, hits.length - 1); draw(); e.preventDefault(); }
    else if (e.key === "ArrowUp") { at = Math.max(at - 1, 0); draw(); e.preventDefault(); }
    else if (e.key === "Enter" && hits[at]) { go(hits[at]); }
    else if (e.key === "Escape") { input.value = ""; box.hidden = true; input.blur(); }
  });
  input.addEventListener("blur", () => setTimeout(() => { box.hidden = true; }, 150));
}

// ---------- theme and keys ----------
function setupTheme() {
  const select = document.getElementById("theme");
  let saved = "system";
  try { saved = localStorage.getItem("pmgr-theme") || "system"; } catch { /* storage blocked */ }
  const apply = (v) => {
    if (v === "system") delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = v;
  };
  select.value = saved;
  apply(saved);
  select.addEventListener("change", () => {
    apply(select.value);
    try { localStorage.setItem("pmgr-theme", select.value); } catch { /* storage blocked */ }
  });
}

function setupKeys() {
  const help = document.getElementById("help");
  document.getElementById("help-close").addEventListener("click", () => { help.hidden = true; });
  const order = NAV.flatMap(([, items]) => items.map(([v]) => v));
  document.addEventListener("keydown", (e) => {
    const typing = e.target instanceof Element && e.target.matches("input, select, textarea");
    if (e.key === "Escape") { help.hidden = true; return; }
    if (typing || e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key === "/") { e.preventDefault(); document.getElementById("search").focus(); }
    else if (e.key === "r") sync();
    else if (e.key === "?") help.hidden = !help.hidden;
    else if (/^[1-9]$/.test(e.key) && order[Number(e.key) - 1]) location.hash = order[Number(e.key) - 1];
  });
}

function start() {
  const embedded = document.getElementById("pmgr-data");
  if (embedded) app.report = JSON.parse(embedded.textContent);
  if (document.getElementById("pmgr-live")) {
    app.live = true;
    app.token = new URLSearchParams(location.search).get("t") || "";
  }
  setupTheme();
  setupSearch();
  setupKeys();
  window.addEventListener("hashchange", () => {
    render();
    window.scrollTo(0, 0);
    document.getElementById("main").focus({ preventScroll: true });
  });
  // Keep "Synced … ago" and the sync timer current.
  setInterval(() => { renderChecked(); if (app.syncing) renderSync(); }, 1000);
  render();
}

start();
