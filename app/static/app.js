"use strict";

// Agent Trust Gateway dashboard. Plain JS, no framework.
// Issued tokens are kept in memory only (never persisted) so they can be used in the simulator.

const UA_PRESETS = {
  agent: "ShoppingAssistant/1.0 (+https://agents.example/shopping-assistant)",
  browser: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
  scraper: "python-requests/2.31.0",
};
const CLASS_LABELS = {
  human: "Human",
  authorised_agent: "Authorised agent",
  suspicious: "Suspicious",
  unverified: "Unverified",
};

const state = {
  events: [],
  selectedEventId: null,
  eventFilter: "",
  credFilter: "",
  issuedTokens: [], // {id, token, label}
  lastEventIds: new Set(),
  merchants: [],
};

// ---------- helpers ----------
const $ = (sel, root = document) => root.querySelector(sel);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = data.error || {};
    const detail = Array.isArray(err.details) ? err.details.map((d) => `${d.loc.slice(-1)[0]}: ${d.msg}`).join("; ") : "";
    throw new Error(`${err.message || res.statusText}${detail ? ` (${detail})` : ""}`);
  }
  return data;
}

function toast(msg, isError = false) {
  const el = $("#toast");
  el.textContent = msg;
  el.className = `toast${isError ? " error" : ""}`;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.add("hidden"), 3200);
}

const chip = (decision) => `<span class="chip chip-${esc(decision)}">${esc(decision)}</span>`;
const scoreColor = (s) => (s >= 70 ? "var(--block)" : s >= 40 ? "var(--review)" : "var(--allow)");
const scoreBar = (s) =>
  `<div class="scorebar"><div class="bar"><div class="fill" style="width:${s}%;background:${scoreColor(s)}"></div></div><span class="num">${s}</span></div>`;

function timeAgo(iso) {
  const secs = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (secs < 5) return "just now";
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return new Date(iso).toLocaleDateString();
}
function timeUntil(iso) {
  const secs = Math.round((new Date(iso).getTime() - Date.now()) / 1000);
  if (secs <= 0) return timeAgo(iso);
  if (secs < 60) return `in ${secs}s`;
  if (secs < 3600) return `in ${Math.floor(secs / 60)}m ${secs % 60}s`;
  return `in ${Math.floor(secs / 3600)}h`;
}
const shortId = (id) => (id ? esc(id) : '<span class="muted">—</span>');

function factorList(factors, base, total) {
  const rows = [`<li><span class="pts base">${base}</span><span>Neutral starting score</span></li>`];
  for (const f of factors) {
    const cls = f.points > 0 ? "pos" : "neg";
    const sign = f.points > 0 ? "+" : "";
    rows.push(`<li><span class="pts ${cls}">${sign}${f.points}</span><span>${esc(f.description)} <code>${esc(f.code)}</code></span></li>`);
  }
  const raw = base + factors.reduce((a, f) => a + f.points, 0);
  const clampNote = raw !== total ? ` <span class="muted small">(clamped from ${raw})</span>` : "";
  rows.push(`<li class="total"><span class="pts">${total}</span><span>Final risk score${clampNote}</span></li>`);
  return `<ul class="factors">${rows.join("")}</ul>`;
}

function renderResult(el, r, extra = "") {
  el.classList.remove("hidden");
  el.innerHTML = `
    <div class="result-head">
      ${chip(r.decision)}
      <span class="big" style="color:${scoreColor(r.risk_score)}">${r.risk_score}</span><span class="muted small">/ 100</span>
      <span class="chip chip-neutral">${esc(CLASS_LABELS[r.classification] || r.classification)}</span>
      <a class="link small" href="#" data-event="${esc(r.event_id)}">View event →</a>
    </div>
    ${extra}
    <dl class="kv">
      <dt>Identity</dt><dd>${esc(r.identity_status)}</dd>
      <dt>Authorisation</dt><dd>${esc(r.authorisation_status)}</dd>
      <dt>Credential</dt><dd>${esc(r.credential_status)}${r.credential_id ? ` · <span class="mono">${esc(r.credential_id)}</span>` : ""}</dd>
    </dl>
    <div style="margin-top:8px">${factorList(r.risk_factors, r.base_score, r.risk_score)}</div>`;
  el.querySelector("[data-event]").addEventListener("click", (e) => {
    e.preventDefault();
    selectEvent(r.event_id);
  });
}

// ---------- data loading ----------
async function loadSummary() {
  const s = await api("/api/dashboard/summary");
  document.querySelectorAll("#cards [data-k]").forEach((el) => {
    el.textContent = s[el.dataset.k] ?? "–";
  });
}

async function loadEvents() {
  const q = state.eventFilter ? `&decision=${state.eventFilter}` : "";
  state.events = await api(`/api/events?limit=60${q}`);
  const body = $("#event-body");
  if (!state.events.length) {
    body.innerHTML = `<tr class="empty-row"><td colspan="6">No events yet. Run a scenario above.</td></tr>`;
    return;
  }
  const fresh = state.lastEventIds.size > 0;
  body.innerHTML = state.events
    .map((e) => {
      const source = e.scenario ? esc(e.scenario.replace(/_/g, " ")) : esc(e.agent_id || e.ip_address);
      const isNew = fresh && !state.lastEventIds.has(e.id);
      return `<tr data-id="${esc(e.id)}" class="${e.id === state.selectedEventId ? "selected" : ""} ${isNew ? "flash" : ""}">
        <td class="muted" title="${esc(new Date(e.created_at).toLocaleString())}">${timeAgo(e.created_at)}</td>
        <td>${source}</td>
        <td>${esc(e.action)}</td>
        <td>${esc(CLASS_LABELS[e.classification] || e.classification)}</td>
        <td>${scoreBar(e.risk_score)}</td>
        <td>${chip(e.decision)}</td>
      </tr>`;
    })
    .join("");
  state.lastEventIds = new Set(state.events.map((e) => e.id));
}

async function loadCredentials() {
  const q = state.credFilter ? `?status=${state.credFilter}` : "";
  const creds = await api(`/api/credentials${q}`);
  const body = $("#cred-body");
  if (!creds.length) {
    body.innerHTML = `<tr class="empty-row"><td colspan="7">No credentials match.</td></tr>`;
    return;
  }
  body.innerHTML = creds
    .slice(0, 25)
    .map(
      (c) => `<tr>
        <td class="mono">${esc(c.id)}</td>
        <td>${esc(c.user_id)}</td>
        <td>${esc(c.agent_id)}</td>
        <td>${c.scopes.map((s) => `<span class="chip chip-neutral">${esc(s)}</span>`).join(" ")}</td>
        <td><span class="chip chip-${esc(c.status)}">${esc(c.status)}</span></td>
        <td class="muted" title="${esc(new Date(c.expires_at).toLocaleString())}">${c.status === "revoked" ? "revoked " + timeAgo(c.revoked_at) : timeUntil(c.expires_at)}</td>
        <td>${c.status === "active" ? `<button class="btn btn-sm btn-danger" data-revoke="${esc(c.id)}">Revoke</button>` : ""}</td>
      </tr>`
    )
    .join("");
}

async function loadRegistry() {
  const [users, merchants, agents, health] = await Promise.all([
    api("/api/users"), api("/api/merchants"), api("/api/agents"), api("/health"),
  ]);
  state.merchants = merchants;
  const fill = (sel, items) => {
    const prev = sel.value;
    sel.innerHTML = items.map((i) => `<option value="${esc(i.id)}">${esc(i.name)} (${esc(i.id)})</option>`).join("");
    if (items.some((i) => i.id === prev)) sel.value = prev;
  };
  fill($("#user-select"), users);
  fill($("#merchant-select"), merchants);
  fill($("#agent-select"), agents);
  if (merchants[0]) $("#merchant-name").textContent = merchants[0].name;
  $("#key-id").textContent = `key ${health.signing_key_id}`;
}

async function refresh() {
  try {
    await Promise.all([loadSummary(), loadEvents(), loadCredentials()]);
  } catch (err) {
    console.error(err);
  }
}

// ---------- event detail ----------
function gauge(score) {
  const r = 34, c = 2 * Math.PI * r, off = c * (1 - score / 100);
  return `<svg class="gauge" viewBox="0 0 84 84" role="img" aria-label="Risk score ${score}">
    <circle cx="42" cy="42" r="${r}" fill="none" stroke="var(--surface-2)" stroke-width="8"/>
    <circle cx="42" cy="42" r="${r}" fill="none" stroke="${scoreColor(score)}" stroke-width="8" stroke-linecap="round"
      stroke-dasharray="${c}" stroke-dashoffset="${off}" transform="rotate(-90 42 42)"/>
    <text x="42" y="47" text-anchor="middle" font-size="20" font-weight="700" fill="var(--text)">${score}</text>
  </svg>`;
}

async function selectEvent(id) {
  state.selectedEventId = id;
  document.querySelectorAll("#event-body tr").forEach((tr) => tr.classList.toggle("selected", tr.dataset.id === id));
  let e = state.events.find((x) => x.id === id);
  if (!e) e = await api(`/api/events/${encodeURIComponent(id)}`);
  const meta = e.request_metadata ? `<h4>Metadata</h4><pre class="token">${esc(JSON.stringify(e.request_metadata, null, 2))}</pre>` : "";
  $("#detail").innerHTML = `
    <div class="card-head"><h3>Event detail</h3>${chip(e.decision)}</div>
    <div class="gauge-wrap">
      ${gauge(e.risk_score)}
      <div>
        <div><strong>${esc(CLASS_LABELS[e.classification] || e.classification)}</strong></div>
        <div class="muted small">Thresholds: allow &lt; 40 · review 40–69 · block ≥ 70</div>
        <div class="muted small mono">${esc(e.id)}</div>
      </div>
    </div>
    <h4>Why</h4>
    ${factorList(e.risk_factors, e.base_score, e.risk_score)}
    <h4>Checks</h4>
    <dl class="kv">
      <dt>Identity</dt><dd>${esc(e.identity_status)}</dd>
      <dt>Authorisation</dt><dd>${esc(e.authorisation_status)}</dd>
      <dt>Credential</dt><dd>${esc(e.credential_status)}</dd>
    </dl>
    <h4>Request</h4>
    <dl class="kv">
      <dt>Time</dt><dd>${esc(new Date(e.created_at).toLocaleString())}</dd>
      <dt>Action</dt><dd>${esc(e.action)}</dd>
      <dt>Merchant</dt><dd>${shortId(e.merchant_id)}</dd>
      <dt>User</dt><dd>${shortId(e.user_id)}</dd>
      <dt>Agent</dt><dd>${shortId(e.agent_id)}</dd>
      <dt>Credential ID</dt><dd class="mono">${shortId(e.credential_id)}</dd>
      <dt>IP</dt><dd>${esc(e.ip_address)}</dd>
      <dt>User-agent</dt><dd class="small">${esc(e.user_agent) || '<span class="muted">—</span>'}</dd>
      <dt>Declared agent</dt><dd>${e.declared_agent ? "yes" : "no"}</dd>
    </dl>
    ${meta}`;
  if (window.innerWidth < 1000) $("#detail").scrollIntoView({ behavior: "smooth", block: "start" });
}

// ---------- scenarios ----------
async function loadScenarios() {
  const list = await api("/api/demo/scenarios");
  $("#scenarios").innerHTML = list
    .map(
      (s, i) => `<button class="scenario" data-key="${esc(s.key)}">
        <span class="scenario-top"><strong>${i + 1}. ${esc(s.title)}</strong>${chip(s.expected)}</span>
        <span class="desc">${esc(s.description)}</span>
      </button>`
    )
    .join("");
}

async function runScenario(btn) {
  btn.disabled = true;
  try {
    const r = await api(`/api/demo/scenarios/${btn.dataset.key}`, { method: "POST" });
    const seq =
      r.requests_sent > 1
        ? `<div class="muted small">${r.requests_sent} requests: decision per request</div><div class="sequence">${r.decisions
            .map((d) => `<span class="seq-${d}" title="${d}"></span>`)
            .join("")}</div>`
        : "";
    const title = `<div class="small" style="margin-bottom:6px"><strong>${esc(r.scenario.title)}</strong> <span class="muted">· ${esc(r.scenario.description)}</span></div>`;
    renderResult($("#scenario-result"), r.final, title + seq);
    await refresh();
  } catch (err) {
    toast(err.message, true);
  } finally {
    btn.disabled = false;
  }
}

// ---------- authorisation ----------
function rememberToken(issued, label) {
  state.issuedTokens.unshift({ id: issued.credential.id, token: issued.token, label });
  const sel = $("#sim-cred-select");
  const opt = document.createElement("option");
  opt.value = issued.credential.id;
  opt.textContent = `${issued.credential.id} · ${label}`;
  sel.insertBefore(opt, sel.options[1] || null);
  sel.value = issued.credential.id;
  applyCredentialSelection();
}

async function submitAuthorisation(e) {
  e.preventDefault();
  const fd = new FormData(e.target);
  const body = {
    user_id: fd.get("user_id"),
    merchant_id: fd.get("merchant_id"),
    agent_id: fd.get("agent_id"),
    scopes: fd.getAll("scopes"),
    ttl_seconds: Number(fd.get("ttl_seconds")),
  };
  if (!body.scopes.length) return toast("Pick at least one scope", true);
  try {
    const res = await api("/api/authorisations", { method: "POST", body });
    const { issued } = res;
    const c = issued.credential;
    const el = $("#issued");
    el.classList.remove("hidden");
    el.innerHTML = `
      <div class="row" style="justify-content:space-between"><strong>Credential issued</strong><span class="chip chip-active">active</span></div>
      <dl class="kv">
        <dt>Credential ID</dt><dd class="mono">${esc(c.id)}</dd>
        <dt>User → Merchant</dt><dd>${esc(c.user_id)} → ${esc(c.merchant_id)}</dd>
        <dt>Agent</dt><dd>${esc(c.agent_id)}</dd>
        <dt>Scope</dt><dd>${c.scopes.map(esc).join(", ")}</dd>
        <dt>Issued</dt><dd>${esc(new Date(c.issued_at).toLocaleTimeString())}</dd>
        <dt>Expires</dt><dd>${esc(new Date(c.expires_at).toLocaleTimeString())} (${timeUntil(c.expires_at)})</dd>
        <dt>Signed by</dt><dd>Ed25519 key <span class="mono">${esc(c.key_id)}</span></dd>
      </dl>
      <div class="token" title="Signed token, shown once and not stored by the server">${esc(issued.token)}</div>
      <div class="row">
        <button type="button" class="btn btn-sm" id="copy-token">Copy token</button>
        <span class="muted small">Loaded into the simulator →</span>
      </div>`;
    $("#copy-token").addEventListener("click", () => navigator.clipboard.writeText(issued.token).then(() => toast("Token copied")));
    rememberToken(issued, `${c.agent_id} [${c.scopes.join(",")}]`);
    $("#sim-user").value = c.user_id;
    $("#sim-agent").value = c.agent_id;
    toast("Agent authorised, credential issued");
    await refresh();
  } catch (err) {
    toast(err.message, true);
  }
}

async function createUser() {
  const name = $("#new-user-name").value.trim();
  const email = $("#new-user-email").value.trim();
  if (!name) return toast("Name is required", true);
  try {
    const u = await api("/api/users", { method: "POST", body: { name, email: email || null } });
    await loadRegistry();
    $("#user-select").value = u.id;
    $("#new-user").classList.add("hidden");
    $("#new-user-name").value = $("#new-user-email").value = "";
    toast(`User ${u.name} created`);
    loadSummary();
  } catch (err) {
    toast(err.message, true);
  }
}

// ---------- simulator ----------
function applyCredentialSelection() {
  const id = $("#sim-cred-select").value;
  const t = state.issuedTokens.find((x) => x.id === id);
  $("#sim-token").value = t ? t.token : "";
}

function applyUaPreset() {
  const preset = $("#ua-preset").value;
  $("#sim-ua").value = UA_PRESETS[preset];
  $("#sim-declared").checked = preset === "agent";
}

async function submitSimulation(e) {
  e.preventDefault();
  const fd = new FormData(e.target);
  const merchant = $("#merchant-select").value || (state.merchants[0] && state.merchants[0].id);
  const body = {
    credential: fd.get("credential") || null,
    merchant_id: merchant,
    user_id: fd.get("user_id") || null,
    agent_id: fd.get("agent_id") || null,
    action: fd.get("action"),
    ip_address: fd.get("ip_address"),
    user_agent: fd.get("user_agent") || "",
    declared_agent: $("#sim-declared").checked,
    metadata: { source: "dashboard-simulator" },
  };
  const repeat = Math.min(50, Math.max(1, Number($("#sim-repeat").value) || 1));
  try {
    const decisions = [];
    let last;
    for (let i = 0; i < repeat; i++) {
      last = await api("/api/gateway/evaluate", { method: "POST", body });
      decisions.push(last.decision);
    }
    const seq = repeat > 1 ? `<div class="sequence">${decisions.map((d) => `<span class="seq-${d}" title="${d}"></span>`).join("")}</div>` : "";
    renderResult($("#sim-result"), last, seq);
    await refresh();
  } catch (err) {
    toast(err.message, true);
  }
}

// ---------- wiring ----------
function wireSegmented(id, key, loader) {
  $(id).addEventListener("click", (e) => {
    const b = e.target.closest("button");
    if (!b) return;
    $(id).querySelectorAll("button").forEach((x) => x.classList.toggle("active", x === b));
    state[key] = b.dataset.v;
    loader();
  });
}

function init() {
  $("#scenarios").addEventListener("click", (e) => {
    const b = e.target.closest(".scenario");
    if (b) runScenario(b);
  });
  $("#auth-form").addEventListener("submit", submitAuthorisation);
  $("#sim-form").addEventListener("submit", submitSimulation);
  $("#sim-cred-select").addEventListener("change", applyCredentialSelection);
  $("#ua-preset").addEventListener("change", applyUaPreset);
  $("#new-user-btn").addEventListener("click", () => $("#new-user").classList.toggle("hidden"));
  $("#create-user-btn").addEventListener("click", createUser);
  $("#event-body").addEventListener("click", (e) => {
    const tr = e.target.closest("tr[data-id]");
    if (tr) selectEvent(tr.dataset.id);
  });
  $("#cred-body").addEventListener("click", async (e) => {
    const b = e.target.closest("[data-revoke]");
    if (!b) return;
    try {
      await api(`/api/credentials/${encodeURIComponent(b.dataset.revoke)}/revoke`, { method: "POST", body: { reason: "Revoked from merchant dashboard" } });
      toast(`Revoked ${b.dataset.revoke}`);
      await refresh();
    } catch (err) {
      toast(err.message, true);
    }
  });
  wireSegmented("#event-filter", "eventFilter", loadEvents);
  wireSegmented("#cred-filter", "credFilter", loadCredentials);

  applyUaPreset();
  $("#sim-user").value = "usr_alex_tan";
  $("#sim-agent").value = "agt_shopping_assistant";

  Promise.all([loadRegistry(), loadScenarios(), refresh()]).catch((err) => toast(err.message, true));
  setInterval(refresh, 5000);
}

document.addEventListener("DOMContentLoaded", init);
