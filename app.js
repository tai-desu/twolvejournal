/* ============================================================
   TWØLVE — life wheel journal
   All data is encrypted with your password (AES-GCM via WebCrypto)
   and stored in this browser's localStorage only.
   ============================================================ */
"use strict";

/* ---------------- default areas (from the 12-life-areas wheel) -------- */
const DEFAULT_AREAS = [
  { name: "Health",       cats: ["Mental Health", "Fitness", "Nutrition", "Sleep", "Hygiene"] },
  { name: "Appearance",   cats: ["Body Image", "Skincare", "Hair", "Fashion", "Self-Care"] },
  { name: "Love",         cats: ["Self-Love", "Romantic Relationship", "Partnership", "Dating Life", "Intimacy"] },
  { name: "Family",       cats: ["Bonding Time", "Support System", "Responsibilities", "Traditions", "Stability"] },
  { name: "Friends",      cats: ["Social Circle", "Social Support", "Social Events", "Shared Experiences", "Cultural Exchange"] },
  { name: "Career",       cats: ["Skill Development", "Learning", "Networking", "Work-Life Balance", "Formal Education"] },
  { name: "Money",        cats: ["Income", "Savings", "Investing", "Financial Planning", "Financial Independence"] },
  { name: "Self-Growth",  cats: ["Purpose", "Goal Setting", "Habits & Routines", "Passions", "Self-Reflection"] },
  { name: "Spirituality", cats: ["Mindfulness", "Inner Peace", "Personal Beliefs", "Compassion", "Connection with Nature"] },
  { name: "Recreation",   cats: ["Hobbies", "Entertainment", "Pleasure", "Sport", "Travel"] },
  { name: "Environment",  cats: ["Organization", "Cleanliness", "Comfort", "Maintenance", "Aesthetics"] },
  { name: "Community",    cats: ["Connections", "Helping Others", "Volunteering", "Local Events", "Social Responsibility"] },
];

const VAULT_KEY = "twolve.vault";
const $  = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];

/* ================= crypto ================= */
const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function deriveKey(password, salt) {
  const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 310000, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
}
async function encryptVault(key, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(obj)));
  return { iv: b64(iv), data: b64(data) };
}
async function decryptVault(key, vault) {
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(vault.iv) }, key, unb64(vault.data));
  return JSON.parse(dec.decode(plain));
}

/* ================= state ================= */
let KEY = null;        // in-memory crypto key while unlocked
let SALT = null;
let DB = null;         // { areas, entries, goals, evaluations }
let activeArea = 0;
let activeEvalId = null;
let SB = null;         // supabase client (cloud mode only)
const cloudMode = () =>
  typeof SUPABASE_URL !== "undefined" && SUPABASE_URL && SUPABASE_ANON_KEY;

function setSync(msg, ok) {
  const el = $("#sync-status");
  if (!el) return;
  el.textContent = msg;
  el.classList.toggle("err", ok === false);
}

function freshDB() {
  return {
    areas: DEFAULT_AREAS.map((a) => ({ name: a.name, cats: [...a.cats] })),
    entries: [],       // {id, date, areaIdx, feelings, struggles, reflection, ts}
    goals: [],         // {id, areaIdx, text, target, done}
    evaluations: [],   // {id, date, label, scores:{ "areaIdx|cat": n }}
  };
}
async function persist() {
  const payload = await encryptVault(KEY, DB);
  const rec = { salt: b64(SALT), ...payload, updated_at: new Date().toISOString() };
  localStorage.setItem(VAULT_KEY, JSON.stringify(rec));
  if (cloudMode() && SB) {
    try {
      const { data: { user } } = await SB.auth.getUser();
      if (!user) throw 0;
      const { error } = await SB.from("vaults").upsert({
        user_id: user.id, salt: rec.salt, iv: rec.iv, data: rec.data, updated_at: rec.updated_at,
      });
      if (error) throw error;
      setSync("synced ✓", true);
    } catch {
      setSync("offline · saved on this device", false);
    }
  }
}
const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
const todayISO = () => new Date().toISOString().slice(0, 10);
const fmtDate = (iso) => new Date(iso + "T12:00:00").toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });

/* ================= auth flow ================= */
const vaultRaw = localStorage.getItem(VAULT_KEY);
if (cloudMode() && window.supabase) {
  SB = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
  $("#auth-cloud").classList.remove("hidden");
  $("#auth-sub").textContent = "Sign in — your journal syncs across devices.";
} else if (vaultRaw) {
  if (cloudMode()) $("#auth-sub").textContent = "Sync unavailable right now — unlocking local copy.";
  $("#auth-login").classList.remove("hidden");
} else {
  $("#auth-setup").classList.remove("hidden");
  $("#auth-sub").textContent = "Set up your private life-wheel journal.";
}

/* ---- cloud: sign in / sign up ---- */
async function cloudOpenVault(pass) {
  // newest of remote and local cache wins
  let remote = null;
  try {
    const { data: rows } = await SB.from("vaults").select("*").limit(1);
    remote = rows && rows[0] ? rows[0] : null;
  } catch { /* offline — fall back to local cache */ }
  const local = JSON.parse(localStorage.getItem(VAULT_KEY) || "null");
  let vault = remote;
  if (remote && local) vault = new Date(local.updated_at || 0) > new Date(remote.updated_at || 0) ? local : remote;
  else vault = remote || local;

  if (!vault) {                       // brand-new account: create an empty journal
    SALT = crypto.getRandomValues(new Uint8Array(16));
    KEY = await deriveKey(pass, SALT);
    DB = freshDB();
    await persist();
  } else {
    SALT = unb64(vault.salt);
    KEY = await deriveKey(pass, SALT);
    DB = await decryptVault(KEY, vault);   // throws if password can't open the vault
    localStorage.setItem(VAULT_KEY, JSON.stringify({
      salt: vault.salt, iv: vault.iv, data: vault.data, updated_at: vault.updated_at || new Date().toISOString(),
    }));
    if (vault === local) await persist();  // local was newer — push it up
    else setSync("synced ✓", true);
  }
}
async function cloudSignIn() {
  authErr("");
  const email = $("#cloud-email").value.trim(), pass = $("#cloud-pass").value;
  if (!email || !pass) return authErr("Email and password, please.");
  try {
    const { error } = await SB.auth.signInWithPassword({ email, password: pass });
    if (error) return authErr(error.message);
    await cloudOpenVault(pass);
    $("#cloud-pass").value = "";
    enterQuote();
  } catch {
    authErr("Signed in, but couldn't decrypt your journal with this password.");
  }
}
async function cloudSignUp() {
  authErr("");
  const email = $("#cloud-email").value.trim(), pass = $("#cloud-pass").value;
  if (!email || !pass) return authErr("Email and password, please.");
  if (pass.length < 6) return authErr("Use at least 6 characters.");
  const { data, error } = await SB.auth.signUp({ email, password: pass });
  if (error) return authErr(error.message);
  if (!data.session) return authErr("Account created — check your email to confirm, then sign in.");
  try {
    await cloudOpenVault(pass);
    $("#cloud-pass").value = "";
    enterQuote();
  } catch { authErr("Couldn't set up your journal. Try signing in."); }
}
if (cloudMode()) {
  $("#btn-cloud-in").addEventListener("click", cloudSignIn);
  $("#btn-cloud-up").addEventListener("click", cloudSignUp);
  $("#cloud-pass").addEventListener("keydown", (e) => e.key === "Enter" && cloudSignIn());
}

$("#btn-setup").addEventListener("click", async () => {
  const p1 = $("#setup-pass-1").value, p2 = $("#setup-pass-2").value;
  if (p1.length < 6) return authErr("Use at least 6 characters.");
  if (p1 !== p2) return authErr("Passwords don't match.");
  SALT = crypto.getRandomValues(new Uint8Array(16));
  KEY = await deriveKey(p1, SALT);
  DB = freshDB();
  await persist();
  enterQuote();
});

$("#btn-login").addEventListener("click", unlock);
$("#login-pass").addEventListener("keydown", (e) => e.key === "Enter" && unlock());

async function unlock() {
  try {
    const vault = JSON.parse(localStorage.getItem(VAULT_KEY));
    SALT = unb64(vault.salt);
    KEY = await deriveKey($("#login-pass").value, SALT);
    DB = await decryptVault(KEY, vault);
    $("#login-pass").value = "";
    enterQuote();
  } catch { authErr("Wrong password."); }
}
function authErr(msg) { $("#auth-error").textContent = msg; }

$("#btn-lock").addEventListener("click", relock);

/* ================= quote screen ================= */
const pad0 = (n) => String(n).padStart(2, "0").replace(/0/g, "Ø");
function greeting() {
  const h = new Date().getHours();
  const part = h < 5 ? "Still up" : h < 12 ? "Good morning" : h < 18 ? "Good afternoon" : "Good evening";
  const name = typeof USER_NAME !== "undefined" && USER_NAME ? USER_NAME : "";
  return name ? `${part}, <b>${name}</b>.` : `${part}.`;
}
function showQuote() {
  $("#quote-greet").innerHTML = greeting();
  const i = Math.floor(Math.random() * QUOTES.length);
  const q = QUOTES[i];
  $("#quote-index").textContent = `${pad0(i + 1)} / ${pad0(QUOTES.length)}`;
  $("#quote-text").textContent = q.text;
  $("#quote-author").textContent = q.by;
}
function enterQuote() {
  $("#view-auth").classList.add("hidden");
  $("#auth-error").textContent = "";
  showQuote();
  $("#view-quote").classList.remove("hidden");
}
$("#btn-another-quote").addEventListener("click", showQuote);
$("#btn-enter").addEventListener("click", () => {
  $("#view-quote").classList.add("hidden");
  $("#app").classList.remove("hidden");
  bootApp();
});

/* ================= top navigation ================= */
$$(".tab").forEach((t) =>
  t.addEventListener("click", () => {
    $$(".tab").forEach((x) => x.classList.toggle("active", x === t));
    ["journal", "book", "evaluation", "settings"].forEach((v) =>
      $("#view-" + v).classList.toggle("hidden", t.dataset.view !== v));
    if (t.dataset.view === "book") { bookArea = activeArea; bookPage = 0; renderBook(); }
    if (t.dataset.view === "evaluation") renderEval();
    if (t.dataset.view === "settings") renderSettings();
  })
);

/* ================= wheel sound library ================= */
let AC = null, soundOn = true;
function _ctx() {
  AC = AC || new (window.AudioContext || window.webkitAudioContext)();
  if (AC.state === "suspended") AC.resume();
  return AC;
}
/* noise burst: d=duration s, f=filter freq, q, g=gain, at=delay */
function _n(t, { d = 0.06, f = 1000, q = 1.2, g = 0.4, type = "bandpass", at = 0 } = {}) {
  const A = _ctx();
  const len = Math.max(1, Math.floor(A.sampleRate * d));
  const buf = A.createBuffer(1, len, A.sampleRate);
  const ch = buf.getChannelData(0);
  for (let i = 0; i < len; i++) ch[i] = (Math.random() * 2 - 1) * Math.pow(1 - i / len, 3);
  const s = A.createBufferSource(); s.buffer = buf;
  const flt = A.createBiquadFilter(); flt.type = type; flt.frequency.value = f; flt.Q.value = q;
  const gn = A.createGain(); gn.gain.value = g;
  s.connect(flt); flt.connect(gn); gn.connect(A.destination);
  s.start(t + at);
}
/* pitched hit: w=waveform, f0→f1 sweep, d=duration, g=gain, lp=lowpass, at=delay */
function _o(t, { w = "sine", f0 = 170, f1 = 60, d = 0.15, g = 0.5, lp = 0, at = 0 } = {}) {
  const A = _ctx();
  const o = A.createOscillator(), gn = A.createGain();
  o.type = w;
  o.frequency.setValueAtTime(f0, t + at);
  o.frequency.exponentialRampToValueAtTime(Math.max(f1, 1), t + at + d * 0.75);
  gn.gain.setValueAtTime(g, t + at);
  gn.gain.exponentialRampToValueAtTime(0.001, t + at + d);
  let node = o;
  if (lp) { const flt = A.createBiquadFilter(); flt.type = "lowpass"; flt.frequency.value = lp; o.connect(flt); node = flt; }
  node.connect(gn); gn.connect(A.destination);
  o.start(t + at); o.stop(t + at + d + 0.05);
}

const SOUND_LIB = [
  { id: "mahoraga", name: "Ø1 · Mahoraga", desc: "heavy thump, ratchet clack, axle creak — the original", fn(t) {
      _o(t, { f0: 170, f1: 58, d: 0.16, g: 0.55 });
      _n(t, { d: 0.06, f: 900, q: 1.4, g: 0.4 });
      _o(t, { w: "sawtooth", f0: 52, f1: 38, d: 0.26, g: 0.13, lp: 260 });
  }},
  { id: "ratchet", name: "Ø2 · Ratchet Gear", desc: "three rapid wooden clicks, like teeth passing a pawl", fn(t) {
      _n(t, { d: 0.035, f: 1300, q: 2, g: 0.35 });
      _n(t, { d: 0.035, f: 1150, q: 2, g: 0.4, at: 0.055 });
      _n(t, { d: 0.045, f: 950, q: 2, g: 0.45, at: 0.115 });
      _o(t, { f0: 130, f1: 70, d: 0.1, g: 0.3, at: 0.115 });
  }},
  { id: "oldaxle", name: "Ø3 · Old Axle", desc: "long dry creak with a soft knock underneath", fn(t) {
      _o(t, { w: "sawtooth", f0: 62, f1: 34, d: 0.45, g: 0.17, lp: 300 });
      _o(t, { w: "sawtooth", f0: 95, f1: 50, d: 0.35, g: 0.07, lp: 500, at: 0.06 });
      _o(t, { f0: 120, f1: 68, d: 0.12, g: 0.3 });
  }},
  { id: "dryclack", name: "Ø4 · Dry Clack", desc: "one crisp knock, nothing else — minimal", fn(t) {
      _n(t, { d: 0.05, f: 1000, q: 2.2, g: 0.5 });
      _o(t, { f0: 220, f1: 120, d: 0.06, g: 0.25 });
  }},
  { id: "temple", name: "Ø5 · Temple Block", desc: "round, hollow woodblock pock", fn(t) {
      _o(t, { f0: 480, f1: 290, d: 0.1, g: 0.42 });
      _o(t, { f0: 720, f1: 500, d: 0.05, g: 0.15 });
      _n(t, { d: 0.03, f: 1500, q: 1.5, g: 0.18 });
  }},
  { id: "taiko", name: "Ø6 · Deep Drum", desc: "low taiko boom with a skin slap", fn(t) {
      _o(t, { f0: 100, f1: 38, d: 0.38, g: 0.7 });
      _n(t, { d: 0.035, f: 2400, q: 0.8, g: 0.15 });
  }},
  { id: "waterwheel", name: "Ø7 · Water Wheel", desc: "wooden clack trailed by a soft water swish", fn(t) {
      _n(t, { d: 0.05, f: 850, q: 1.6, g: 0.38 });
      _o(t, { f0: 150, f1: 65, d: 0.12, g: 0.35 });
      _n(t, { d: 0.4, f: 3200, q: 0.4, g: 0.08, type: "highpass", at: 0.05 });
  }},
  { id: "clockwork", name: "Ø8 · Clockwork", desc: "tick–tock, two clicks a step apart", fn(t) {
      _n(t, { d: 0.03, f: 1900, q: 3, g: 0.32 });
      _n(t, { d: 0.04, f: 1050, q: 3, g: 0.38, at: 0.09 });
  }},
  { id: "bamboo", name: "Ø9 · Bamboo", desc: "hollow two-tone knock, like a shishi-odoshi", fn(t) {
      _o(t, { f0: 640, f1: 500, d: 0.06, g: 0.3 });
      _o(t, { f0: 340, f1: 250, d: 0.11, g: 0.38, at: 0.04 });
      _n(t, { d: 0.03, f: 1200, q: 1.5, g: 0.15 });
  }},
  { id: "whisper", name: "1Ø · Whisper", desc: "barely-there soft tick for quiet journaling", fn(t) {
      _n(t, { d: 0.04, f: 700, q: 1, g: 0.13 });
      _o(t, { f0: 160, f1: 90, d: 0.08, g: 0.09 });
  }},
];
const SOUND_MAP = Object.fromEntries(SOUND_LIB.map((s) => [s.id, s]));
const WHEEL_SOUND = "ratchet";   // ← the wheel's sound (ids: mahoraga, ratchet, oldaxle, dryclack, temple, taiko, waterwheel, clockwork, bamboo, whisper)
function playSound(id) {
  try { const s = SOUND_MAP[id] || SOUND_LIB[0]; s.fn(_ctx().currentTime); }
  catch { /* audio unavailable — turn silently */ }
}
function woodTurn() {
  if (!soundOn) return;
  playSound(WHEEL_SOUND);
}
document.addEventListener("pointerdown", () => { if (AC && AC.state === "suspended") AC.resume(); });
$("#btn-sound").addEventListener("click", () => {
  soundOn = !soundOn;
  $("#btn-sound").textContent = soundOn ? "♪ sound on" : "♪ sound off";
  $("#btn-sound").classList.toggle("off", !soundOn);
  if (soundOn) woodTurn();
});

/* ================= the wheel ================= */
const N = 12;
const STEP = 17; // degrees between numerals
function wheelGeom() {
  const mobile = matchMedia("(max-width:900px)").matches;
  return mobile ? { cx: -370, R: 480 } : { cx: -380, R: 730 };
}
function buildWheel() {
  const wrap = $("#wheel-items");
  wrap.innerHTML = "";
  DB.areas.forEach((a, i) => {
    const el = document.createElement("div");
    el.className = "w-item";
    el.innerHTML = `<span class="w-dot"></span>
      <span class="w-num">${String(i + 1).padStart(2, "0").replace(/0/g, "Ø")}</span>
      <span class="w-label"><b></b><span></span></span>`;
    el.addEventListener("click", () => setArea(i));
    wrap.appendChild(el);
  });
  layoutWheel();
}
function layoutWheel() {
  const { cx, R } = wheelGeom();
  $$(".w-item").forEach((el, i) => {
    let d = ((i - activeArea) % N + N) % N;      // 0..11
    if (d > N / 2) d -= N;                       // shortest way: -6..5
    el.style.left = cx + "px";
    el.style.transform = `rotate(${d * STEP}deg) translateX(${R}px) translateY(-50%)`;
    el.classList.toggle("active", d === 0);
    el.classList.toggle("far", Math.abs(d) > 2);
    const a = DB.areas[i];
    el.querySelector(".w-label b").textContent = a.name;
    el.querySelector(".w-label span").textContent = `${a.cats.length} categor${a.cats.length === 1 ? "y" : "ies"}`;
  });
}
function setArea(i) {
  const next = ((i % N) + N) % N;
  if (next !== activeArea) woodTurn();
  activeArea = next;
  layoutWheel();
  renderAreaPane();
}

/* scroll & touch to turn */
let wheelAcc = 0, wheelBusy = false;
$("#wheel-pane").addEventListener("wheel", (e) => {
  e.preventDefault();
  wheelAcc += e.deltaY;
  if (wheelBusy) return;
  if (Math.abs(wheelAcc) > 60) {
    setArea(activeArea + Math.sign(wheelAcc));
    wheelAcc = 0; wheelBusy = true;
    setTimeout(() => (wheelBusy = false), 380);
  }
}, { passive: false });

let touchY = null;
$("#wheel-pane").addEventListener("touchstart", (e) => (touchY = e.touches[0].clientY), { passive: true });
$("#wheel-pane").addEventListener("touchmove", (e) => {
  if (touchY == null) return;
  const dy = touchY - e.touches[0].clientY;
  if (Math.abs(dy) > 42) { setArea(activeArea + Math.sign(dy)); touchY = e.touches[0].clientY; }
}, { passive: true });
addEventListener("resize", () => DB && layoutWheel());

/* ================= journal pane ================= */
$$(".ptab").forEach((t) =>
  t.addEventListener("click", () => {
    $$(".ptab").forEach((x) => x.classList.toggle("active", x === t));
    ["write", "goals", "history"].forEach((p) =>
      $("#pane-" + p).classList.toggle("hidden", t.dataset.pane !== p));
  })
);

function goalsTab() {
  $$(".ptab").forEach((x) => x.classList.toggle("active", x.dataset.pane === "goals"));
  ["write", "goals", "history"].forEach((p) => $("#pane-" + p).classList.toggle("hidden", p !== "goals"));
}
function renderGoalPreview() {
  const wrap = $("#goal-preview");
  const goals = DB.goals.filter((g) => g.areaIdx === activeArea);
  const active = goals.filter((g) => !g.done);
  const done = goals.length - active.length;
  if (!goals.length) {
    wrap.innerHTML = `<button class="gp-empty" type="button">＋ set a goal for this area</button>`;
  } else {
    const chips = active.slice(0, 3).map((g) =>
      `<span class="gp-chip"><span class="gp-dot"></span>${esc(g.text)}${g.target ? `<em>${fmtDate(g.target)}</em>` : ""}</span>`).join("");
    const more = active.length > 3 ? `<span class="gp-more">+${active.length - 3} more</span>` : "";
    const allDone = active.length === 0 ? `<span class="gp-alldone">all goals done ✓</span>` : "";
    wrap.innerHTML = `<span class="gp-label">Goals</span>${chips}${more}${allDone}<span class="gp-prog">${done}/${goals.length} done</span>`;
  }
  wrap.onclick = goalsTab;
}
function renderAreaPane() {
  const a = DB.areas[activeArea];
  $("#area-title").textContent = `${String(activeArea + 1).padStart(2, "0")} — ${a.name}`;
  $("#area-cats").textContent = a.cats.join("  ·  ");
  renderGoalPreview();
  // prefill today's entry if it exists
  const d = $("#fld-date").value || todayISO();
  $("#fld-date").value = d;
  loadEntryInto(d);
  renderGoals();
  renderHistory();
}
function findEntry(date) {
  return DB.entries.find((e) => e.date === date && e.areaIdx === activeArea);
}
function loadEntryInto(date) {
  const e = findEntry(date);
  $("#fld-feelings").value = e ? e.feelings : "";
  $("#fld-struggles").value = e ? e.struggles : "";
  $("#fld-reflection").value = e ? e.reflection : "";
}
$("#fld-date").addEventListener("change", () => loadEntryInto($("#fld-date").value));

$("#btn-save-entry").addEventListener("click", async () => {
  const date = $("#fld-date").value || todayISO();
  let e = findEntry(date);
  if (!e) { e = { id: uid(), date, areaIdx: activeArea }; DB.entries.push(e); }
  e.feelings = $("#fld-feelings").value.trim();
  e.struggles = $("#fld-struggles").value.trim();
  e.reflection = $("#fld-reflection").value.trim();
  e.ts = Date.now();
  await persist();
  flash("#save-flash", "Saved ✓");
  renderHistory();
  renderBackupNote();
});
function flash(sel, msg) {
  $(sel).textContent = msg;
  setTimeout(() => ($(sel).textContent = ""), 1800);
}

/* goals */
$("#btn-add-goal").addEventListener("click", async () => {
  const text = $("#goal-text").value.trim();
  if (!text) return;
  DB.goals.push({ id: uid(), areaIdx: activeArea, text, target: $("#goal-date").value || "", done: false });
  $("#goal-text").value = ""; $("#goal-date").value = "";
  await persist(); renderGoals();
});
function renderGoals() {
  renderGoalPreview();
  const ul = $("#goal-list"); ul.innerHTML = "";
  const goals = DB.goals.filter((g) => g.areaIdx === activeArea);
  if (!goals.length) { ul.innerHTML = `<li class="empty">No goals for this area yet. Add one above.</li>`; return; }
  goals.forEach((g) => {
    const li = document.createElement("li");
    if (g.done) li.className = "done";
    li.innerHTML = `<input type="checkbox" ${g.done ? "checked" : ""} style="width:auto;margin:0">
      <span class="g-text">${esc(g.text)}</span>
      <span class="g-date">${g.target ? fmtDate(g.target) : ""}</span>
      <button class="g-x" title="Delete">✕</button>`;
    li.querySelector("input").addEventListener("change", async (e) => { g.done = e.target.checked; await persist(); renderGoals(); });
    li.querySelector(".g-x").addEventListener("click", async () => { DB.goals = DB.goals.filter((x) => x.id !== g.id); await persist(); renderGoals(); });
    ul.appendChild(li);
  });
}

/* history */
function renderHistory() {
  const ul = $("#entry-list"); ul.innerHTML = "";
  const list = DB.entries.filter((e) => e.areaIdx === activeArea).sort((a, b) => b.date.localeCompare(a.date));
  if (!list.length) { ul.innerHTML = `<li class="empty">Nothing written in this area yet.</li>`; return; }
  list.forEach((e) => {
    const li = document.createElement("li");
    const block = (t, v) => (v ? `<div class="e-block"><b>${t}</b><p>${esc(v)}</p></div>` : "");
    li.innerHTML = `<div class="e-date">${fmtDate(e.date)}</div>
      ${block("Feelings", e.feelings)}${block("Struggles", e.struggles)}${block("Reflection", e.reflection)}
      <button class="e-del">delete entry</button>`;
    li.querySelector(".e-del").addEventListener("click", async () => {
      if (!confirm("Delete this entry?")) return;
      DB.entries = DB.entries.filter((x) => x.id !== e.id);
      await persist(); renderHistory();
    });
    ul.appendChild(li);
  });
}
const esc = (s) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

/* ================= the book ================= */
let bookArea = 0, bookPage = 0, bookBusy = false;
const isMobileBook = () => matchMedia("(max-width:900px)").matches;
const reducedMotion = () => matchMedia("(prefers-reduced-motion: reduce)").matches;

function paperFlip() {
  if (!soundOn) return;
  try {
    const t = _ctx().currentTime;
    _n(t, { d: 0.16, f: 3600, type: "highpass", q: 0.4, g: 0.12 });
    _n(t, { d: 0.05, f: 1500, q: 1, g: 0.1, at: 0.06 });
  } catch { /* silent */ }
}

function bookPagesFor(ai) {
  const a = DB.areas[ai];
  const list = DB.entries.filter((e) => e.areaIdx === ai).sort((x, y) => x.date.localeCompare(y.date));
  const pages = [];
  const range = list.length ? `${fmtDate(list[0].date)} — ${fmtDate(list[list.length - 1].date)}` : "";
  pages.push(`<div class="p-cover">
      <div class="p-num">${String(ai + 1).padStart(2, "0").replace(/0/g, "Ø")}</div>
      <div class="p-title">${esc(a.name)}</div>
      <div class="p-meta">${list.length} entr${list.length === 1 ? "y" : "ies"}${range ? " · " + range : ""}</div>
    </div>`);
  if (!list.length) {
    pages.push(`<div class="p-empty">This chapter is still blank.<br>Write your first entry in the Journal.</div>`);
  }
  list.forEach((e, i) => {
    const block = (t, v) => (v ? `<div class="p-block"><b>${t}</b><p>${esc(v)}</p></div>` : "");
    pages.push(`<div class="p-entry">
        <div class="p-date">${fmtDate(e.date)}</div>
        ${block("Feelings", e.feelings)}${block("Struggles", e.struggles)}${block("Reflection", e.reflection)}
        <div class="p-no">${i + 1}</div>
      </div>`);
  });
  if (pages.length % 2) pages.push(`<div class="p-blank"></div>`);
  return pages;
}

function renderBook() {
  const tabs = $("#b-tabs");
  tabs.innerHTML = "";
  DB.areas.forEach((a, i) => {
    const b = document.createElement("button");
    b.className = "b-tab" + (i === bookArea ? " active" : "");
    b.title = a.name;
    b.textContent = String(i + 1).padStart(2, "0").replace(/0/g, "Ø");
    b.addEventListener("click", () => {
      if (i === bookArea) return;
      bookArea = i; bookPage = 0;
      paperFlip();
      renderBook();
    });
    tabs.appendChild(b);
  });
  renderSpread();
}
function renderSpread() {
  const pages = bookPagesFor(bookArea);
  const step = isMobileBook() ? 1 : 2;
  bookPage = Math.max(0, Math.min(bookPage, pages.length - 1));
  if (!isMobileBook() && bookPage % 2) bookPage--;
  $("#b-left").innerHTML = pages[bookPage] || "";
  $("#b-right").innerHTML = pages[bookPage + 1] || "";
  $("#b-prev").style.visibility = bookPage > 0 ? "visible" : "hidden";
  $("#b-next").style.visibility = bookPage + step < pages.length ? "visible" : "hidden";
}
function flipNext() {
  const pages = bookPagesFor(bookArea);
  const step = isMobileBook() ? 1 : 2;
  if (bookBusy || bookPage + step >= pages.length) return;
  paperFlip();
  if (isMobileBook() || reducedMotion()) { bookPage += step; renderSpread(); return; }
  bookBusy = true;
  const oldRight = pages[bookPage + 1] || "";
  const newLeft = pages[bookPage + 2] || "";
  const newRight = pages[bookPage + 3] || "";
  const f = document.createElement("div");
  f.className = "b-flipper from-right";
  f.innerHTML = `<div class="bf-face bf-front">${oldRight}</div><div class="bf-face bf-back">${newLeft}</div>`;
  $("#book").appendChild(f);
  $("#b-right").innerHTML = newRight;
  requestAnimationFrame(() => requestAnimationFrame(() => { f.style.transform = "rotateY(-180deg)"; }));
  setTimeout(() => {
    bookPage += 2;
    f.remove();
    bookBusy = false;
    renderSpread();
  }, 600);
}
function flipPrev() {
  if (bookBusy || bookPage <= 0) return;
  paperFlip();
  const pages = bookPagesFor(bookArea);
  if (isMobileBook() || reducedMotion()) { bookPage -= isMobileBook() ? 1 : 2; renderSpread(); return; }
  bookBusy = true;
  const oldLeft = pages[bookPage] || "";
  const newLeft = pages[bookPage - 2] || "";
  const newRight = pages[bookPage - 1] || "";
  const f = document.createElement("div");
  f.className = "b-flipper from-left";
  f.innerHTML = `<div class="bf-face bf-front">${oldLeft}</div><div class="bf-face bf-back">${newRight}</div>`;
  // back face of a left-side flip must be pre-mirrored so it reads correctly mid-turn
  f.querySelector(".bf-back").style.transform = "rotateY(-180deg)";
  $("#book").appendChild(f);
  $("#b-left").innerHTML = newLeft;
  requestAnimationFrame(() => requestAnimationFrame(() => { f.style.transform = "rotateY(180deg)"; }));
  setTimeout(() => {
    bookPage -= 2;
    f.remove();
    bookBusy = false;
    renderSpread();
  }, 600);
}
$("#b-next").addEventListener("click", flipNext);
$("#b-prev").addEventListener("click", flipPrev);
document.addEventListener("keydown", (e) => {
  if ($("#view-book").classList.contains("hidden") || $("#app").classList.contains("hidden")) return;
  if (e.key === "ArrowRight") flipNext();
  if (e.key === "ArrowLeft") flipPrev();
});

/* ================= evaluation ================= */
const catKey = (ai, cat) => ai + "|" + cat;
function quarterLabel(d = new Date()) {
  return `Q${Math.floor(d.getMonth() / 3) + 1} ${d.getFullYear()} · ${d.toLocaleDateString(undefined, { month: "short", day: "numeric" })}`;
}
$("#btn-new-eval").addEventListener("click", async () => {
  const ev = { id: uid(), date: todayISO(), label: quarterLabel(), scores: {} };
  DB.areas.forEach((a, ai) => a.cats.forEach((c) => (ev.scores[catKey(ai, c)] = 5)));
  DB.evaluations.push(ev);
  activeEvalId = ev.id;
  await persist(); renderEval();
});
$("#btn-del-eval").addEventListener("click", async () => {
  if (!activeEvalId || !confirm("Delete this evaluation?")) return;
  DB.evaluations = DB.evaluations.filter((e) => e.id !== activeEvalId);
  activeEvalId = DB.evaluations.length ? DB.evaluations[DB.evaluations.length - 1].id : null;
  await persist(); renderEval();
});
$("#eval-select").addEventListener("change", (e) => { activeEvalId = e.target.value; renderEval(); });

function renderEval() {
  const sel = $("#eval-select");
  sel.innerHTML = "";
  DB.evaluations.forEach((ev) => {
    const o = document.createElement("option");
    o.value = ev.id; o.textContent = ev.label;
    sel.appendChild(o);
  });
  if (!activeEvalId && DB.evaluations.length) activeEvalId = DB.evaluations[DB.evaluations.length - 1].id;
  if (activeEvalId) sel.value = activeEvalId;

  // due note
  const due = $("#eval-due");
  if (!DB.evaluations.length) due.textContent = "No evaluations yet — create your first one.";
  else {
    const last = DB.evaluations.reduce((m, e) => (e.date > m ? e.date : m), "0");
    const days = Math.floor((Date.now() - new Date(last)) / 86400000);
    due.textContent = days >= 90
      ? `Your last check-in was ${days} days ago — time for a new evaluation.`
      : `Last check-in ${days} day${days === 1 ? "" : "s"} ago · next one due in ${90 - days} days.`;
  }
  renderEvalForm();
  drawChart();
}

function currentEval() { return DB.evaluations.find((e) => e.id === activeEvalId) || null; }

function renderEvalForm() {
  const wrap = $("#eval-areas");
  wrap.innerHTML = "";
  const ev = currentEval();
  $("#eval-title").textContent = ev ? `Scores — ${ev.label}` : "Scores";
  if (!ev) { wrap.innerHTML = `<p class="empty">Create an evaluation to start scoring.</p>`; return; }
  DB.areas.forEach((a, ai) => {
    const box = document.createElement("div");
    box.className = "ev-area";
    const avg = areaAvg(ev, ai);
    box.innerHTML = `<div class="ev-area-head"><h3>${String(ai + 1).padStart(2, "0")} · ${esc(a.name)}</h3><span class="ev-avg">avg ${avg.toFixed(1)}</span></div><div class="ev-cats hidden"></div>`;
    const cats = box.querySelector(".ev-cats");
    a.cats.forEach((c) => {
      const k = catKey(ai, c);
      if (!(k in ev.scores)) ev.scores[k] = 5;
      const row = document.createElement("div");
      row.className = "ev-cat";
      row.innerHTML = `<label>${esc(c)}</label><input type="range" min="1" max="10" step="1" value="${ev.scores[k]}"><span class="ev-val">${ev.scores[k]}</span>`;
      const rng = row.querySelector("input");
      rng.addEventListener("input", () => { row.querySelector(".ev-val").textContent = rng.value; });
      rng.addEventListener("change", async () => {
        ev.scores[k] = +rng.value;
        box.querySelector(".ev-avg").textContent = "avg " + areaAvg(ev, ai).toFixed(1);
        await persist(); drawChart();
      });
      cats.appendChild(row);
    });
    box.querySelector(".ev-area-head").addEventListener("click", () => cats.classList.toggle("hidden"));
    if (ai === 0) cats.classList.remove("hidden");
    wrap.appendChild(box);
  });
}
function areaAvg(ev, ai) {
  const vals = DB.areas[ai].cats.map((c) => ev.scores[catKey(ai, c)] || 0).filter((v) => v > 0);
  return vals.length ? vals.reduce((s, v) => s + v, 0) / vals.length : 0;
}

/* ---- the wheel chart ---- */
function polar(cx, cy, r, deg) {
  const a = ((deg - 90) * Math.PI) / 180;
  return [cx + r * Math.cos(a), cy + r * Math.sin(a)];
}
function sector(cx, cy, r0, r1, a0, a1) {
  const [x0, y0] = polar(cx, cy, r1, a0), [x1, y1] = polar(cx, cy, r1, a1);
  const [x2, y2] = polar(cx, cy, r0, a1), [x3, y3] = polar(cx, cy, r0, a0);
  const large = a1 - a0 > 180 ? 1 : 0;
  return `M${x0},${y0} A${r1},${r1} 0 ${large} 1 ${x1},${y1} L${x2},${y2} A${r0},${r0} 0 ${large} 0 ${x3},${y3} Z`;
}
function drawChart() {
  const svg = $("#eval-chart");
  const C = 360, R0 = 44, R1 = 268, RLBL = 322, RRING = 288;
  const ev = currentEval();
  let out = `<defs>
    <radialGradient id="scoreGrad" gradientUnits="userSpaceOnUse" cx="${C}" cy="${C}" r="${R1}">
      <stop offset="0%"  stop-color="var(--score-lo)"/>
      <stop offset="16%" stop-color="var(--score-lo)"/>
      <stop offset="58%" stop-color="#8A48B8"/>
      <stop offset="100%" stop-color="var(--score-hi)"/>
    </radialGradient>
  </defs>`;

  // guide rings at scores 2,4,6,8,10
  for (let s = 2; s <= 10; s += 2) {
    const r = R0 + (s / 10) * (R1 - R0);
    out += `<circle cx="${C}" cy="${C}" r="${r}" fill="none" stroke="var(--line)" stroke-width="1"/>`;
  }
  out += `<circle cx="${C}" cy="${C}" r="${RRING}" fill="none" stroke="var(--ink)" stroke-opacity=".25" stroke-width="1"/>`;

  const span = 360 / N;
  DB.areas.forEach((a, ai) => {
    const A0 = ai * span;
    const catSpan = span / Math.max(a.cats.length, 1);

    // score wedges
    if (ev) a.cats.forEach((c, ci) => {
      const s = ev.scores[catKey(ai, c)] || 0;
      if (s <= 0) return;
      const r = R0 + (s / 10) * (R1 - R0);
      const g = 0.7; // gap degrees
      out += `<path d="${sector(C, C, R0, r, A0 + ci * catSpan + g, A0 + (ci + 1) * catSpan - g)}"
                fill="url(#scoreGrad)" fill-opacity=".92"/>`;
    });

    // category spoke lines
    a.cats.forEach((c, ci) => {
      const [x0, y0] = polar(C, C, R0, A0 + ci * catSpan);
      const [x1, y1] = polar(C, C, R1, A0 + ci * catSpan);
      out += `<line x1="${x0}" y1="${y0}" x2="${x1}" y2="${y1}" stroke="var(--line)" stroke-width="1"/>`;
    });
    // area boundary
    const [bx0, by0] = polar(C, C, R0, A0), [bx1, by1] = polar(C, C, RRING, A0);
    out += `<line x1="${bx0}" y1="${by0}" x2="${bx1}" y2="${by1}" stroke="var(--ink)" stroke-opacity=".3" stroke-width="1"/>`;

    // area number near hub
    const [nx, ny] = polar(C, C, R0 - 18, A0 + span / 2);
    out += `<text x="${nx}" y="${ny}" text-anchor="middle" dominant-baseline="middle"
             font-family="Space Grotesk" font-size="13" fill="var(--mid)">${ai + 1}</text>`;

    // area label, rotated to follow the wheel
    const mid = A0 + span / 2;
    const [lx, ly] = polar(C, C, RLBL, mid);
    const rot = mid > 90 && mid < 270 ? mid + 180 : mid;
    out += `<text x="${lx}" y="${ly}" text-anchor="middle" dominant-baseline="middle"
             font-family="Space Grotesk" font-size="16" letter-spacing="1" fill="var(--ink)"
             transform="rotate(${rot},${lx},${ly})">${esc(a.name)}</text>`;
  });

  // hub
  out += `<circle cx="${C}" cy="${C}" r="${R0}" fill="var(--paper)" stroke="var(--line)"/>`;
  if (ev) {
    const all = Object.values(ev.scores).filter((v) => v > 0);
    const avg = all.length ? (all.reduce((s, v) => s + v, 0) / all.length) : 0;
    out += `<text x="${C}" y="${C - 4}" text-anchor="middle" font-family="Space Grotesk" font-weight="700" font-size="24" fill="var(--ink)">${avg.toFixed(1)}</text>
            <text x="${C}" y="${C + 16}" text-anchor="middle" font-family="Inter" font-size="10" fill="var(--mid)">overall</text>`;
  }
  svg.innerHTML = out;
}

/* ================= settings ================= */
function renderSettings() {
  const wrap = $("#settings-areas");
  wrap.innerHTML = "";
  DB.areas.forEach((a, i) => {
    const div = document.createElement("div");
    div.className = "s-area";
    div.innerHTML = `<div class="s-num">AREA ${String(i + 1).padStart(2, "0")}</div>
      <input type="text" value="${esc(a.name)}" data-i="${i}" class="s-name">
      <textarea rows="5" data-i="${i}" class="s-cats" placeholder="One category per line (max 5)">${a.cats.map(esc).join("\n")}</textarea>`;
    wrap.appendChild(div);
  });
}
$("#btn-save-settings").addEventListener("click", async () => {
  $$(".s-name").forEach((inp) => {
    const v = inp.value.trim();
    if (v) DB.areas[+inp.dataset.i].name = v;
  });
  $$(".s-cats").forEach((ta) => {
    const cats = ta.value.split("\n").map((s) => s.trim()).filter(Boolean).slice(0, 5);
    if (cats.length) DB.areas[+ta.dataset.i].cats = cats;
  });
  await persist();
  buildWheel(); renderAreaPane();
  flash("#settings-flash", "Saved ✓");
});

/* export / import / backup reminder */
function relock() {
  if (SB) { try { SB.auth.signOut(); } catch { } }
  location.reload();
}
function downloadJSON(name, obj) {
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}
async function markExported() {
  DB.lastExport = Date.now();
  await persist();
  renderBackupNote();
}
async function exportReadable() {
  downloadJSON(`twolve-backup-${todayISO()}.json`, DB);
  await markExported();
}
async function exportEncrypted() {
  await persist(); // make sure vault on disk is current
  const vault = JSON.parse(localStorage.getItem(VAULT_KEY));
  downloadJSON(`twolve-encrypted-${todayISO()}.json`, { format: "twolve-encrypted", ...vault });
  await markExported();
}
$("#btn-export").addEventListener("click", exportReadable);
$("#btn-export-enc").addEventListener("click", exportEncrypted);

let bnDismissed = false;
function backupDue() {
  const hasData = DB.entries.length + DB.goals.length + DB.evaluations.length > 0;
  if (!DB.lastExport) return hasData;
  return Date.now() - DB.lastExport > 14 * 86400000;
}
function renderBackupNote() {
  const n = $("#backup-note");
  if (bnDismissed || !backupDue()) { n.classList.add("hidden"); return; }
  const days = DB.lastExport ? Math.floor((Date.now() - DB.lastExport) / 86400000) : null;
  $("#bn-text").textContent = days == null
    ? "You haven't exported a backup of this journal yet."
    : `Your last backup was ${days} days ago.`;
  n.classList.remove("hidden");
}
$("#bn-export").addEventListener("click", exportReadable);
$("#bn-close").addEventListener("click", () => { bnDismissed = true; renderBackupNote(); });

$("#import-file").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  try {
    const obj = JSON.parse(await file.text());
    if (obj.format === "twolve-encrypted" || (obj.salt && obj.iv && obj.data)) {
      if (!confirm("Restore this encrypted backup? It replaces everything here, and you'll unlock it with the password it was created with.")) return;
      localStorage.setItem(VAULT_KEY, JSON.stringify({ salt: obj.salt, iv: obj.iv, data: obj.data }));
      alert("Encrypted backup restored. Log in with that backup's password.");
      relock();
      return;
    }
    if (!obj.areas || !obj.entries) throw 0;
    if (!confirm("Replace everything in this journal with the backup?")) return;
    DB = obj;
    await persist();
    buildWheel(); setArea(0);
    renderBackupNote();
    flash("#settings-flash", "Backup imported ✓");
  } catch { $("#settings-error").textContent = "That file doesn't look like a Twølve backup."; }
  e.target.value = "";
});

/* change password */
$("#btn-chg-pass").addEventListener("click", async () => {
  const err = $("#settings-error");
  err.textContent = "";
  try {
    const vault = JSON.parse(localStorage.getItem(VAULT_KEY));
    const oldKey = await deriveKey($("#chg-old").value, unb64(vault.salt));
    await decryptVault(oldKey, vault); // throws if wrong
  } catch { err.textContent = "Current password is wrong."; return; }
  const np = $("#chg-new").value;
  if (np.length < 6) { err.textContent = "New password: at least 6 characters."; return; }
  SALT = crypto.getRandomValues(new Uint8Array(16));
  KEY = await deriveKey(np, SALT);
  if (cloudMode() && SB) {
    const { error: e2 } = await SB.auth.updateUser({ password: np });
    if (e2) { err.textContent = "Journal re-encrypted, but account password change failed: " + e2.message; }
  }
  await persist();
  $("#chg-old").value = $("#chg-new").value = "";
  flash("#settings-flash", "Password changed ✓");
});

/* ================= boot ================= */
function bootApp() {
  buildWheel();
  setArea(0);
  $("#fld-date").value = todayISO();
  loadEntryInto(todayISO());
  renderBackupNote();
  if (!cloudMode()) setSync("this device only");
}
