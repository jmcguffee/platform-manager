"use strict";
// pmgr dashboard. `pmgr ui` embeds the report in this page as JSON.
// Every value from the report is set with textContent, never as HTML,
// because findings quote logs, commit messages and API errors.

const SEV = ["critical", "error", "warning", "info"];
const SEV_LABEL = { critical: "Critical", error: "Error", warning: "Warning", info: "Suggestion" };
const VIEWS = ["overview", "access", "workloads", "pipelines", "workflows", "argo"];
const AREAS = { access: ["auth", "cluster"], workloads: ["workload"], pipelines: ["pipeline"], workflows: ["workflow"], argo: ["argo"] };

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

const app = { report: null, sev: new Set(SEV), q: "" };

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
  return [
    h("h1", { class: cls }, verdict),
    h("p", { class: "verdict-sub" }, sub),
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

function pipelines() {
  const list = inView("pipelines");
  const usage = app.report.usage_minutes || {};
  const repos = app.report.settings ? app.report.settings.repos.map((r) => r.name) : Object.keys(usage);
  const max = Math.max(1, ...Object.values(usage).flatMap((rows) => Object.values(rows)));
  const days = app.report.settings ? app.report.settings.lookback_days : 14;
  return [
    h("h1", { class: "verdict" }, list.some((f) => f.check === "pipeline.broken") ? "A pipeline is failing." : "Pipelines are passing."),
    h("p", { class: "verdict-sub" }, `What runs did over the last ${days} days: broken workflows, failure rates, flaky reruns, queue time and slow runs.`),
    repos.map((repo) => {
      const mine = list.filter((f) => f.resource.startsWith(`${repo}:`));
      const rows = Object.entries(usage[repo] || {}).sort((a, b) => b[1] - a[1]);
      return h(
        "details",
        { class: "group", open: true },
        h("summary", {}, h("span", { class: "group-name" }, repo), tally(mine)),
        h(
          "div",
          { class: "group-body" },
          rows.length ? usageBars(rows, max) : h("p", { class: "empty" }, "No runs in this window, or runs couldn't be read."),
          mine.length ? findingList(mine.sort(bySeverity)) : null,
        ),
      );
    }),
    unseenNote(),
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

const RENDER = { overview, access, workloads, pipelines, workflows, argo };

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
}

function start() {
  const embedded = document.getElementById("pmgr-data");
  if (embedded) app.report = JSON.parse(embedded.textContent);
  window.addEventListener("hashchange", () => {
    render();
    window.scrollTo(0, 0);
    document.getElementById("main").focus({ preventScroll: true });
  });
  render();
}

start();
