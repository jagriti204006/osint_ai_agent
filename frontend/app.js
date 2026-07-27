"use strict";

/* IOC Reputation Lookup — client.
 *
 * Every value that reaches the DOM goes through textContent or a whitelisted
 * attribute setter. There is no innerHTML in this file, so hostile data from an
 * upstream API cannot become markup even if the backend sanitiser were bypassed.
 */

const VERDICTS = { malicious: "MALICIOUS", suspicious: "SUSPICIOUS", clean: "CLEAN", no_data: "NO DATA" };

const SAMPLES = [
  { v: "8.8.8.8", n: "IP" },
  { v: "google.com", n: "Domain" },
  { v: "44d88612fea8a8f36de82e1278abb02f", n: "Hash · EICAR" },
  { v: "svchost.exe", n: "Process · bare name" },
  { v: "C:\\Users\\Public\\svchost.exe", n: "Process · masquerade" },
];

const $ = (id) => document.getElementById(id);
const state = { recent: [], busy: false, defanged: false };

/* ---------- tiny DOM helpers (no innerHTML) ---------- */

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = String(text);
  return n;
}

function kvRow(k, v) {
  const row = el("div", "kv-row");
  row.append(el("span", "k", k), el("span", "v", v));
  return row;
}

/* Only ever produce an anchor for http(s). Mirrors the backend allowlist so a
 * bad link can never become a javascript: URL even if it slipped through. */
function safeAnchor(href, label) {
  if (typeof href !== "string") return null;
  let u;
  try { u = new URL(href, window.location.origin); } catch { return null; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return null;
  const a = el("a", "source-link", label);
  a.setAttribute("href", u.href);
  a.setAttribute("target", "_blank");
  a.setAttribute("rel", "noopener noreferrer");
  return a;
}

function toast(msg, bad) {
  const t = el("div", bad ? "toast bad" : "toast", msg);
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 2600);
}

/* Clipboard failures are surfaced, never swallowed — an analyst who thinks
 * they copied an IOC and did not has lost evidence. */
async function copy(text, what) {
  try {
    if (!navigator.clipboard) throw new Error("Clipboard API unavailable");
    await navigator.clipboard.writeText(text);
    toast(what + " copied");
  } catch (err) {
    toast("Copy failed: " + (err && err.message ? err.message : "blocked by browser"), true);
  }
}

/* ---------- radar contacts ---------- */

const SVG_NS = "http://www.w3.org/2000/svg";
const CONTACT_MS = 3000;

/* Ping a contact at a random bearing and range inside the scope. Elements carry
 * classes rather than inline styles so the strict CSP (style-src 'self', no
 * unsafe-inline) still holds. */
function pingContact() {
  const scope = $("radar-contacts");
  if (!scope) return;
  const angle = Math.random() * Math.PI * 2;
  const range = 90 + Math.random() * 380;
  const cx = 500 + Math.cos(angle) * range;
  const cy = 500 + Math.sin(angle) * range;

  const group = document.createElementNS(SVG_NS, "g");
  const ring = document.createElementNS(SVG_NS, "circle");
  ring.setAttribute("class", "contact-ring");
  ring.setAttribute("cx", cx);
  ring.setAttribute("cy", cy);
  ring.setAttribute("r", "4");
  const dot = document.createElementNS(SVG_NS, "circle");
  dot.setAttribute("class", "contact-dot");
  dot.setAttribute("cx", cx);
  dot.setAttribute("cy", cy);
  dot.setAttribute("r", "3.4");

  group.append(ring, dot);
  scope.append(group);
  // Drop the node once its animation has run, so the layer never accumulates.
  setTimeout(() => group.remove(), CONTACT_MS + 200);
}

function startContacts() {
  const reduce = window.matchMedia
    && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reduce) return;
  pingContact();
  setInterval(pingContact, CONTACT_MS);
}

/* ---------- type detection (hint only; server is authoritative) ---------- */

function detectType(v) {
  const s = (v || "").trim();
  if (!s) return null;
  if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(s)) return "hash";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return "ip";
  if (s.includes("@") && !s.includes("/")) return "email";
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s) || s.includes("/")) return "url";
  if (/\.(exe|dll|sys|scr|ps1|bat|cmd|vbs|js|jar|com)$/i.test(s) || s.includes("\\")) return "process";
  if (s.includes(".")) return "domain";
  return null;
}

const TYPE_LABELS = {
  auto: "Auto-detect", hash: "Hash", domain: "Domain", ip: "IP Address",
  url: "URL", email: "Email Sender", process: "Process Name",
};

/* ---------- detail row tone ---------- */

function tone(label, value) {
  const v = String(value).toLowerCase();
  if (label === "Domain age (days)" || label === "Sender domain age (days)") {
    const days = parseInt(v, 10);
    if (!isNaN(days)) {
      if (days <= 30) return "alert";
      if (days <= 90) return "warn";
      return "ok";
    }
    return "";
  }
  if (label === "Masquerading verdict") return v.startsWith("yes") ? "alert" : v.startsWith("no") ? "ok" : "";
  if (label === "Observed path" || label === "Suspicious directory") return "alert";
  if (label === "Impersonates" || label === "Resembles") return "alert";
  if (label === "Tor exit node") return v === "yes" ? "alert" : "";
  if (label === "Internet scanner") return v === "yes" ? "warn" : "";
  if (label === "GreyNoise class") return v === "malicious" ? "alert" : v === "benign" ? "ok" : "";
  if (label === "IDN warning") return "alert";
  if (label === "SPF" || label === "DMARC") {
    if (v.startsWith("absent")) return "alert";
    if (v.includes("p=none") || v.includes("neutral") || v.includes("allow all")) return "alert";
    if (v.includes("soft fail")) return "warn";
    if (v.startsWith("present")) return "ok";
    return "";
  }
  if (label === "DKIM") return v.startsWith("published") ? "ok" : "warn";
  if (label === "MX records") return v === "none" ? "alert" : "";
  if (label === "Spoofing risk") return "alert";
  if (label === "LOLBAS abuse functions" || label === "GTFOBins entry") return "warn";
  if (label === "MHR detection rate") return parseInt(v, 10) > 0 ? "alert" : "";
  return "";
}

function flagsFor(result) {
  const out = [];
  const ts = result.type_specific || {};
  const age = parseInt(ts["Domain age (days)"], 10);
  if (!isNaN(age) && age <= 30) out.push(["alert", "Registered " + age + " days ago"]);
  if (String(ts["Masquerading verdict"] || "").toLowerCase().startsWith("yes")) out.push(["alert", "Masquerading"]);
  if (String(ts["Tor exit node"] || "").toLowerCase() === "yes") out.push(["alert", "Tor exit"]);
  if (ts["IDN warning"]) out.push(["alert", "IDN homograph risk"]);
  if (String(ts["Internet scanner"] || "").toLowerCase() === "yes") out.push(["warn", "Mass internet scanner"]);
  if (ts["LOLBAS abuse functions"]) out.push(["warn", "LOLBAS binary"]);
  if (ts["GTFOBins entry"]) out.push(["warn", "GTFOBins binary"]);
  if (String(ts["SPF"] || "").startsWith("absent")) out.push(["alert", "No SPF"]);
  if (String(ts["DMARC"] || "").startsWith("absent")) out.push(["alert", "No DMARC"]);
  if (String(ts["DMARC"] || "").includes("p=none")) out.push(["warn", "DMARC not enforced"]);
  if (String(ts["MX records"] || "") === "none") out.push(["alert", "No MX — cannot receive mail"]);
  if (String(ts["MX records"] || "").startsWith("null MX")) out.push(["alert", "Null MX — sender is forged"]);
  if (String(ts["DKIM"] || "").startsWith("inconclusive")) out.push(["mute", "DKIM inconclusive"]);
  if (result.verdict === "no_data") out.push(["mute", "Unknown — not clean"]);
  return out;
}

/* ---------- rendering ---------- */

const cards = new Map();

function skeletonCard(name) {
  const card = el("div", "source-card");
  const top = el("div", "source-top");
  top.append(el("span", "source-name", name));
  card.append(top);
  const skel = el("div", "skel");
  ["w1", "w2", "w3", "w4"].forEach((w) => skel.append(el("div", "shimmer " + w)));
  skel.append(el("span", "querying", "Querying…"));
  card.append(skel);
  return card;
}

function fillCard(card, s) {
  card.replaceChildren();
  const top = el("div", "source-top");
  top.append(el("span", "source-name", s.name));
  if (s.status === "ok" && s.verdict) {
    top.append(el("span", "tag sm " + s.verdict, VERDICTS[s.verdict]));
  }
  card.append(top);

  if (s.status === "ok") {
    if (s.score) card.append(el("span", "source-score", s.score));
    const kv = el("div", "kv");
    Object.entries(s.fields || {}).forEach(([k, v]) => kv.append(kvRow(k.replace(/_/g, " "), v)));
    card.append(kv);
    const a = safeAnchor(s.link, "Full report ↗");
    if (a) card.append(a);
    return;
  }

  const box = el("div", "fault");
  const label = s.status === "rate_limited" ? "Rate limited"
    : s.status === "disabled" ? "Not configured" : "Source unreachable";
  box.append(el("span", "label", label));
  box.append(el("span", "text", s.error || ""));
  box.append(el("span", "note", "No verdict returned — treat this source as unknown, not clean."));
  card.append(box);
}

function renderStart(info) {
  cards.clear();
  const results = $("results");
  results.replaceChildren();
  results.hidden = false;
  $("empty-state").hidden = true;

  const head = el("section", "verdict-head");
  head.id = "verdict-head";
  const top = el("div", "verdict-top");
  const left = el("div", "verdict-left");
  left.append(el("div", "section-label", TYPE_LABELS[info.type] || "Indicator"));
  const row = el("div", "ioc-row");
  row.append(el("span", "ioc-value", info.ioc));
  row.id = "ioc-row";
  left.append(row);
  top.append(left);
  const tagSlot = el("div", "tag-slot");
  tagSlot.id = "tag-slot";
  top.append(tagSlot);
  head.append(top);
  head.append(el("p", "summary", "Querying " + info.sources.length + " sources…"));
  results.append(head);

  const sec = el("section");
  const sh = el("div", "sec-head");
  sh.append(el("h2", null, "Source breakdown"));
  const count = el("span", "count", "0 / " + info.sources.length + " sources resolved");
  count.id = "resolved-count";
  sh.append(count);
  sec.append(sh);
  const grid = el("div", "source-grid");
  grid.id = "source-grid";
  info.sources.forEach((name) => {
    const c = skeletonCard(name);
    cards.set(name, c);
    grid.append(c);
  });
  sec.append(grid);
  results.append(sec);
}

function renderSource(s) {
  const card = cards.get(s.name);
  if (card) fillCard(card, s);
  const done = [...cards.values()].filter((c) => !c.querySelector(".skel")).length;
  const counter = $("resolved-count");
  if (counter) counter.textContent = done + " / " + cards.size + " sources resolved";
}

function renderDone(r) {
  const slot = $("tag-slot");
  if (slot) {
    slot.replaceChildren();
    slot.append(el("span", "tag " + r.verdict, VERDICTS[r.verdict]));
  }

  const head = $("verdict-head");
  const summary = head && head.querySelector(".summary");
  if (summary) summary.textContent = r.summary;

  const row = $("ioc-row");
  if (row && row.children.length === 1) {
    const copyBtn = el("button", "mini-btn", "Copy");
    copyBtn.type = "button";
    copyBtn.addEventListener("click", () => copy(r.ioc, "Indicator"));
    const defangBtn = el("button", "mini-btn warn", "Copy defanged");
    defangBtn.type = "button";
    defangBtn.addEventListener("click", () => copy(r.defanged || r.ioc, "Defanged indicator"));
    row.append(copyBtn, defangBtn);
  }

  if (head) {
    const meta = el("div", "meta-row");
    const conf = el("div", "conf-block");
    const ch = el("div", "conf-head");
    ch.append(el("span", null, "Confidence"), el("span", null, r.confidence + " / 100"));
    conf.append(ch);
    const track = el("div", "conf-track");
    const fill = el("div", "conf-fill " + r.verdict);
    // width is the one dynamic style; the value is an integer clamped server-side
    // and re-clamped here, so it cannot carry a CSS payload.
    const pct = Math.max(0, Math.min(100, parseInt(r.confidence, 10) || 0));
    fill.style.setProperty("width", pct + "%");
    track.append(fill);
    conf.append(track);
    meta.append(conf);
    head.append(meta);
  }

  const results = $("results");

  const ts = r.type_specific || {};
  if (Object.keys(ts).length) {
    const sec = el("section");
    const sh = el("div", "sec-head");
    sh.append(el("h2", null, (TYPE_LABELS[r.type] || "Indicator") + " detail"));
    sec.append(sh);
    const panel = el("div", "panel");
    const flags = flagsFor(r);
    if (flags.length) {
      const fr = el("div", "flags");
      flags.forEach(([t, label]) => fr.append(el("span", "flag " + t, label)));
      panel.append(fr);
    }
    const grid = el("div", "detail-grid");
    Object.entries(ts).forEach(([k, v]) => {
      const dr = el("div", "detail-row");
      dr.append(el("span", "k", k));
      const val = el("span", "v " + tone(k, v), v);
      dr.append(val);
      grid.append(dr);
    });
    panel.append(grid);
    sec.append(panel);
    results.append(sec);
  }

  if ((r.attack_techniques || []).length) {
    const sec = el("section");
    const sh = el("div", "sec-head");
    sh.append(el("h2", null, "MITRE ATT&CK"));
    sec.append(sh);
    const wrap = el("div", "attack");
    r.attack_techniques.forEach((t) => {
      const chip = el("span", "tech");
      chip.append(el("span", "id", t.id), el("span", "n", t.name));
      wrap.append(chip);
    });
    sec.append(wrap);
    results.append(sec);
  }

}

/* ---------- SSE over fetch (keeps the IOC out of the URL and logs) ---------- */

function busyNotice() {
  toast("A lookup is already running — wait for it to finish.", true);
}

async function run(value, type) {
  if (state.busy) { busyNotice(); return; }
  state.busy = true;
  $("find-btn").disabled = true;
  clearError();

  try {
    let resp;
    try {
      resp = await fetch("/api/lookup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ioc: value, type: type || "auto" }),
      });
    } catch {
      showError("Cannot reach the backend. Is the server running on port 8000?");
      return;
    }

    if (!resp.ok || !resp.body) {
      showError("Backend returned HTTP " + resp.status + ".");
      return;
    }

    addRecent(value);
    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
      const { done, value: chunk } = await reader.read();
      if (done) break;
      buffer += decoder.decode(chunk, { stream: true });
      const parts = buffer.split("\n\n");
      buffer = parts.pop() || "";
      for (const part of parts) {
        let event = "message";
        const dataLines = [];
        part.split("\n").forEach((line) => {
          if (line.startsWith("event: ")) event = line.slice(7).trim();
          else if (line.startsWith("data: ")) dataLines.push(line.slice(6));
        });
        if (!dataLines.length) continue;
        let payload;
        try { payload = JSON.parse(dataLines.join("\n")); } catch { continue; }
        if (event === "start") renderStart(payload);
        else if (event === "source") renderSource(payload);
        else if (event === "done") renderDone(payload);
        else if (event === "error") showError(payload.message);
      }
    }
  } finally {
    // Must run even if rendering throws, or the UI locks out every later
    // search behind a stuck busy flag.
    state.busy = false;
    $("find-btn").disabled = false;
  }
}

/* Clear the result area and fall back to the empty state.
 * A rejected input must not leave the previous lookup on screen, or the error
 * reads as though it belongs to that result. */
function clearResults() {
  const results = $("results");
  results.replaceChildren();
  results.hidden = true;
  $("empty-state").hidden = false;
  cards.clear();
}

/* Hide the error AND drop its text. Leaving stale text in a hidden box means
 * any later reveal shows a message about a search already moved on from. */
function clearError() {
  const box = $("error-box");
  box.replaceChildren();
  box.hidden = true;
}

function showError(msg) {
  clearResults();
  const box = $("error-box");
  box.replaceChildren(el("span", null, msg));
  box.hidden = false;
}

function addRecent(v) {
  state.recent = [v].concat(state.recent.filter((x) => x !== v)).slice(0, 5);
  const row = $("recent-row");
  row.replaceChildren(el("span", "section-label", "Recent"));
  state.recent.forEach((item) => {
    const label = item.length > 30 ? item.slice(0, 14) + "…" + item.slice(-8) : item;
    const chip = el("button", "recent-chip", label);
    chip.type = "button";
    chip.title = item;
    chip.addEventListener("click", () => run(item, "auto"));
    row.append(chip);
  });
  row.hidden = false;
}

/* ---------- wiring ---------- */

function updateInferNote() {
  const v = $("ioc-input").value.trim();
  const note = $("infer-note");
  const sel = $("ioc-type");
  if (!v) { note.hidden = true; return; }
  if (sel.value !== "auto") {
    note.textContent = "Type locked to " + TYPE_LABELS[sel.value] + " — switch to Auto-detect to infer.";
  } else {
    const d = detectType(v);
    note.textContent = d
      ? "Auto-detected as " + TYPE_LABELS[d] + " — override with the selector if wrong."
      : "Shape not recognised — pick a type from the selector.";
  }
  note.hidden = false;
}

document.addEventListener("DOMContentLoaded", () => {
  startContacts();
  $("ioc-input").addEventListener("input", updateInferNote);
  $("ioc-type").addEventListener("change", updateInferNote);

  $("lookup-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const input = $("ioc-input");
    const value = input.value.trim();
    if (!value) { showError("Enter an indicator to look up."); return; }
    // Check before clearing the input: a swallowed click that also wipes what
    // you typed is the worst of both.
    if (state.busy) { busyNotice(); return; }
    const type = $("ioc-type").value;
    input.value = "";                    // cleared, per spec
    $("infer-note").hidden = true;
    run(value, type);
  });

  const samples = $("samples");
  SAMPLES.forEach((s) => {
    const b = el("button", "sample");
    b.type = "button";
    b.append(el("span", "v", s.v), el("span", "n", s.n));
    b.addEventListener("click", () => run(s.v, "auto"));
    samples.append(b);
  });

  fetch("/api/health")
    .then((r) => r.json())
    .then((h) => {
      const wrap = $("source-chips");
      wrap.replaceChildren();
      h.sources.forEach((s) => {
        const chip = el("span", "src-chip" + (s.enabled ? "" : " off"),
          s.name + (s.enabled ? "" : " · no key"));
        wrap.append(chip);
      });
    })
    .catch(() => {});
});
