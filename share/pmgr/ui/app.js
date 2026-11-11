"use strict";
// pmgr dashboard. `pmgr ui` embeds the report in this page as JSON.
// Every value from the report is set with textContent, never as HTML,
// because findings quote logs, commit messages and API errors.

const SEV = ["critical", "error", "warning", "info"];
const SEV_LABEL = { critical: "Critical", error: "Error", warning: "Warning", info: "Suggestion" };
const VIEWS = ["overview", "actions", "oncall", "access", "workloads", "utilization", "pipelines", "workflows", "argo", "sources"];
const AREAS = { oncall: ["oncall"], access: ["auth", "cluster"], workloads: ["workload"], utilization: ["utilization"], pipelines: ["pipeline"], workflows: ["workflow"], argo: ["argo"] };
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

const app = { report: null, sev: new Set(SEV), q: "", everyone: false, live: false, token: "", syncing: false, syncError: "" };

// ---------- syncing (only when `pmgr ui` serves the page) ----------
// The server answers one connection at a time and is briefly closed between them, so a refused
// connection is retried a few times before it counts as "not running".
async function api(path, method = "GET") {
  for (let attempt = 0; ; attempt += 1) {
    let r;
    try {
      r = await fetch(path, { method, headers: { "X-Pmgr-Token": app.token }, cache: "no-store" });
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
  app.syncing = true;
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
  const slot = document.querySelector(".again");
  if (!slot || !app.live) return;
  const button = h("button", { type: "button", class: "sync", disabled: app.syncing }, app.syncing ? "Syncing…" : "Sync now");
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
  for (const kid of kids.flat()) {
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

function findingRow(f) {
  return h(
    "li",
    { class: `finding ${f.severity}` },
    h("span", { class: "edge", "aria-hidden": "true" }),
    h(
      "div",
      {},
      f.savings_usd_month ? h("p", { class: "save" }, `${f.savings_note === "up to" ? "Save up to" : "Save about"} ${usd(f.savings_usd_month)}/month`, h("span", { class: "muted" }, " at list price")) : null,
      h("p", { class: "what" }, h("span", { class: "sev" }, SEV_LABEL[f.severity]), h("span", { class: "where" }, f.resource), ": ", richText(f.message, false)),
      f.fix ? h("p", { class: "fix" }, richText(f.fix)) : null,
      f.link ? h("p", { class: "ref" }, h("a", { href: f.link, target: "_blank", rel: "noopener noreferrer" }, linkLabel(f))) : null,
    ),
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
        h("div", { class: "chain-name" }, c.name, c.current ? h("span", { class: "here" }, " (current)") : null, h("small", {}, c.context)),
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
function table(headers, rows) {
  return h("div", { class: "table-wrap" }, h("table", { class: "data" },
    h("thead", {}, h("tr", {}, headers.map(([label, numeric]) => h("th", { class: numeric ? "n" : "" }, label)))),
    h("tbody", {}, rows)));
}
function stats(items) {
  return h("dl", { class: "stats" }, items.map(([label, value, tone]) => h("div", { class: tone || "" }, h("dt", {}, label), h("dd", {}, value))));
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
  let verdict;
  let sub;
  let cls = "verdict";
  if (bad) {
    verdict = `${plural(bad, "problem needs", "problems need")} you.`;
    cls += " bad";
    sub = `Start with these. There are also ${plural(c.warning, "warning", "warnings")} and ${plural(c.info, "suggestion", "suggestions")}.`;
  } else if (c.warning) {
    verdict = "Nothing is broken.";
    sub = `${plural(c.warning, "thing", "things")} could be better, plus ${plural(c.info, "suggestion", "suggestions")}.`;
  } else {
    verdict = "Everything checks out.";
    sub = c.info ? `${plural(c.info, "suggestion", "suggestions")} if you have time.` : "No findings in this check.";
  }
  const urgent = all.filter((f) => f.severity !== "info").sort(bySeverity);
  const usage = Object.entries(app.report.usage_minutes || {})
    .flatMap(([repo, rows]) => Object.entries(rows).map(([name, mins]) => [`${repo} › ${name}`, mins]))
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6);
  const days = app.report.settings ? app.report.settings.lookback_days : null;
  const saving = savingsTotal(all);
  return [
    h("h1", { class: cls }, verdict),
    h("p", { class: "verdict-sub" }, sub),
    stats([["Fix now", num(bad), bad ? "bad" : ""], ["This week", num(c.warning), c.warning ? "warn" : ""],
           ["Potential savings", `${usd(saving)}/mo`, saving ? "save" : ""], ["Spend tracked", `${usd(spendTracked())}/mo`],
           ["CI success", pctText(ciSuccess())],
           ...(sources().some((x) => x.type === "datadog")
             ? [["Open pages", num(metrics("page").filter((x) => !["resolved", "closed"].includes(x.status)).length)],
                ...(metrics("shift").length ? [["On call now", (shiftsNow().filter(isMine)[0] || shiftsNow()[0] || { name: "Nobody" }).name]] : [])] : [])]),
    saving || bad ? h("p", { class: "more" }, h("a", { href: "#actions" }, "See every action item")) : null,
    h("h2", {}, "Access"),
    chains(),
    h("h2", {}, urgent.length ? "What to fix first" : "Findings"),
    urgent.length ? findingList(urgent, 8) : h("p", { class: "empty" }, "No errors or warnings."),
    urgent.length > 8 ? h("p", { class: "more" }, `${urgent.length - 8} more in the other views.`) : null,
    usage.length
      ? [
          h("h2", {}, "Where CI time goes"),
          h("p", { class: "section-note" }, `Approximate runner minutes${days ? ` over the last ${days} days` : ""}, largest first.`),
          usageBars(usage),
        ]
      : null,
    unseenNote(),
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
    h("h1", { class: `verdict${now.items.length ? " bad" : ""}` }, verdict),
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
function myPeople() { return (app.report.settings && app.report.settings.oncall_people) || []; }
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
      mine.length ? h("span", { class: "tally" }, app.everyone ? "everyone" : `your ${plural(mine.length, "person", "people")} only`) : null, toggle),
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
    return [h("h1", { class: "verdict" }, "Datadog isn't set up."),
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
    h("h1", { class: `verdict${unacked.length || alerting.length || auth ? " bad" : ""}` },
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

function access() {
  const list = inView("access").sort(bySeverity);
  return [
    h("h1", { class: "verdict" }, hasErrors(list) ? "Some access is broken." : "Access is working."),
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
      h("h1", { class: "verdict" }, "No cluster to read."),
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
    h("h1", { class: `verdict${hasErrors(all) ? " bad" : ""}` }, hasErrors(all) ? "Some workloads are failing." : all.length ? "Workloads are running." : "Workloads are healthy."),
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
    // "account/service/resource": group by account and service.
    const key = (f) => {
      const [where, service] = f.resource.split("/");
      return `${where} › ${SERVICE[service] || service}`;
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
    rds.map((m) => h("tr", {}, h("td", {}, h("b", {}, m.name), m.multi_az ? h("small", { class: "muted" }, " Multi-AZ") : null), h("td", {}, m.account),
      h("td", {}, m.class), h("td", {}, m.engine), pcell(m.cpu_avg), pcell(m.cpu_p95, 80), pcell(m.cpu_max), h("td", { class: "n" }, num(m.connections_max)),
      h("td", { class: `n ${m.free_storage_pct != null && m.free_storage_pct < 15 ? "warn" : ""}` }, m.free_storage_pct == null ? "–" : `${m.free_storage_pct}%`),
      h("td", { class: "n" }, usd(m.monthly_usd))))));
  const cache = metrics("elasticache");
  if (cache.length) svcTables.push(h("h2", {}, "ElastiCache"), table(
    [["Cluster"], ["Account"], ["Nodes", 1], ["Node type"], ["CPU avg", 1], ["CPU p95", 1], ["Memory max", 1], ["Evictions", 1], ["$/month", 1]],
    cache.map((m) => h("tr", {}, h("td", {}, h("b", {}, m.name)), h("td", {}, m.account), h("td", { class: "n" }, num(m.nodes)), h("td", {}, m.class),
      pcell(m.cpu_avg), pcell(m.cpu_p95, 80), pcell(m.memory_max, 80), h("td", { class: `n ${m.evictions ? "warn" : ""}` }, num(m.evictions)), h("td", { class: "n" }, usd(m.monthly_usd))))));
  const rs = metrics("redshift");
  if (rs.length) svcTables.push(h("h2", {}, "Redshift"), table(
    [["Cluster"], ["Account"], ["Nodes", 1], ["Node type"], ["CPU avg", 1], ["CPU p95", 1], ["Disk used", 1], ["$/month", 1]],
    rs.map((m) => h("tr", {}, h("td", {}, h("b", {}, m.name)), h("td", {}, m.account), h("td", { class: "n" }, num(m.nodes)), h("td", {}, m.class),
      pcell(m.cpu_avg), pcell(m.cpu_p95, 80), pcell(m.disk_used_max, 80), h("td", { class: "n" }, usd(m.monthly_usd))))));
  const msk = metrics("msk");
  if (msk.length) svcTables.push(h("h2", {}, "MSK"), table(
    [["Cluster"], ["Account"], ["Brokers", 1], ["Broker type"], ["CPU avg", 1], ["CPU p95", 1], ["Disk used", 1], ["$/month", 1]],
    msk.map((m) => h("tr", {}, h("td", {}, h("b", {}, m.name)), h("td", {}, m.account), h("td", { class: "n" }, num(m.nodes)), h("td", {}, m.class),
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
    h("h1", { class: `verdict${hasErrors(all) ? " bad" : ""}` }, parts.length ? `${parts[0][0].toUpperCase()}${parts[0].slice(1)}.` : "Capacity looks right."),
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
  return h("td", { class: `n ${cls}` }, v == null ? "–" : `${v}%`);
}

function pipelines() {
  const wfs = metrics("workflow");
  const list = inView("pipelines");
  const days = app.report.settings ? app.report.settings.lookback_days : 14;
  const repos = app.report.settings && app.report.settings.repos.length ? app.report.settings.repos.map((r) => r.name) : [...new Set(wfs.map((w) => w.repo))];
  if (!repos.length) {
    return [h("h1", { class: "verdict" }, "No repos configured."), h("p", { class: "verdict-sub" }, "List your repos under github.repos in ~/.config/platform-manager/config.yaml, then sync.")];
  }
  const runs = wfs.reduce((a, w) => a + w.runs, 0);
  const counted = wfs.filter((w) => w.success_rate != null);
  const overall = counted.length ? counted.reduce((a, w) => a + w.success_rate * w.runs, 0) / counted.reduce((a, w) => a + w.runs, 0) : null;
  const minutes = wfs.reduce((a, w) => a + w.minutes, 0);
  const broken = wfs.filter((w) => w.broken).length;
  return [
    h("h1", { class: `verdict${broken ? " bad" : ""}` }, broken ? `${plural(broken, "workflow is", "workflows are")} failing on the default branch.` : wfs.length ? "Pipelines are passing." : "No pipeline data yet."),
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
  const label = { cluster: "Cluster", account: "AWS account", repo: "Repo", datadog: "Datadog" };
  return [
    h("h1", { class: `verdict${bad.length ? " bad" : ""}` }, bad.length ? `pmgr couldn't read ${plural(bad.length, "source", "sources")}.` : "pmgr could read everything."),
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
    h("h1", { class: "verdict" }, "Workflow gaps"),
    h("p", { class: "verdict-sub" }, "What your workflow files allow: unpinned actions, broad tokens, long-lived keys, missing checks and wasted minutes."),
    filters(draw),
    container,
  ];
}

function argo() {
  const list = inView("argo");
  const reachable = (app.report.clusters || []).filter((c) => c.kubernetes === "ok");
  if (!reachable.length) {
    return [
      h("h1", { class: "verdict" }, "No Argo CD to read."),
      h("p", { class: "verdict-sub" }, "pmgr reads Argo CD Applications from clusters it can reach, and none are reachable right now. The Access view shows what's in the way."),
    ];
  }
  return [
    h("h1", { class: "verdict" }, hasErrors(list) ? "Some apps are failing." : "Argo CD apps are healthy."),
    h("p", { class: "verdict-sub" }, "Failed syncs, degraded apps, stuck operations, render errors, and apps that won't converge."),
    list.length
      ? grouped(list, (f) => f.resource.split("/")[0], () => true)
      : h("p", { class: "empty" }, `No Argo CD problems on ${reachable.map((c) => c.name).join(", ")}.`),
    unseenNote(),
  ];
}

const RENDER = { overview, actions, oncall, access, workloads, utilization, pipelines, workflows, argo, sources: sourcesView };

// ---------- shell ----------
function currentView() {
  const v = location.hash.replace(/^#/, "");
  return VIEWS.includes(v) ? v : "overview";
}

function render() {
  const view = currentView();
  for (const a of document.querySelectorAll(".views a")) {
    const v = a.dataset.view;
    a.removeAttribute("aria-current");
    if (v === view) a.setAttribute("aria-current", "page");
    const old = a.querySelector(".count");
    if (old) old.remove();
    if (app.report && v === "actions") {
      const g = actionGroups();
      const n = g[0].items.length + g[1].items.length + g[2].items.length;
      if (n) a.append(h("span", { class: "count" }, String(n)));
    }
    if (app.report && v === "sources") {
      const n = sources().filter((x) => !x.ok).length;
      if (n) a.append(h("span", { class: "count" }, String(n)));
    }
    if (app.report && AREAS[v]) {
      const c = counts(inView(v));
      const n = c.critical + c.error + c.warning;
      if (n) a.append(h("span", { class: "count" }, String(n)));
    }
  }
  document.getElementById("checked").textContent = app.report
    ? `Checked ${new Date(app.report.generated_at).toLocaleString("en-US", { month: "long", day: "numeric", hour: "numeric", minute: "2-digit" })}.`
    : "";
  const main = document.getElementById("main");
  if (!app.report) {
    main.replaceChildren(h("p", { class: "empty" }, "This page has no report in it. Run pmgr ui to make one."));
    return;
  }
  main.replaceChildren(...[RENDER[view]()].flat(3).filter(Boolean));
  renderSync();
}

function start() {
  const embedded = document.getElementById("pmgr-data");
  if (embedded) app.report = JSON.parse(embedded.textContent);
  if (document.getElementById("pmgr-live")) {
    app.live = true;
    app.token = new URLSearchParams(location.search).get("t") || "";
  }
  window.addEventListener("hashchange", () => {
    render();
    window.scrollTo(0, 0);
    document.getElementById("main").focus({ preventScroll: true });
  });
  render();
}

start();
