const STORAGE_KEY = "passwort-notizen-tresor-v1";
const THEME_KEY = "passwort-notizen-theme";
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

const state = {
  key: null,
  salt: null,
  vault: { entries: [] },
  accountName: "",
  activeId: null,
  filter: "all",
  search: "",
  pendingConfirm: null,
};

const $ = (id) => document.getElementById(id);

const els = {
  lockScreen: $("lockScreen"),
  vaultScreen: $("vaultScreen"),
  lockHint: $("lockHint"),
  lockMessage: $("lockMessage"),
  unlockForm: $("unlockForm"),
  accountName: $("accountName"),
  masterPassword: $("masterPassword"),
  toggleMaster: $("toggleMaster"),
  toggleMasterIcon: $("toggleMasterIcon"),
  unlockButton: $("unlockButton"),
  accountLabel: $("accountLabel"),
  themeButton: $("themeButton"),
  exportButton: $("exportButton"),
  importFile: $("importFile"),
  lockButton: $("lockButton"),
  searchInput: $("searchInput"),
  entryCount: $("entryCount"),
  entryList: $("entryList"),
  entryForm: $("entryForm"),
  emptyState: $("emptyState"),
  formType: $("formType"),
  formTitle: $("formTitle"),
  deleteButton: $("deleteButton"),
  titleInput: $("titleInput"),
  usernameInput: $("usernameInput"),
  urlInput: $("urlInput"),
  passwordInput: $("passwordInput"),
  passwordFields: $("passwordFields"),
  notesInput: $("notesInput"),
  saveState: $("saveState"),
  lengthInput: $("lengthInput"),
  lengthOutput: $("lengthOutput"),
  symbolsInput: $("symbolsInput"),
  generateButton: $("generateButton"),
  togglePassword: $("togglePassword"),
  copyPassword: $("copyPassword"),
  newPasswordButton: $("newPasswordButton"),
  newNoteButton: $("newNoteButton"),
  confirmOverlay: $("confirmOverlay"),
  confirmTitle: $("confirmTitle"),
  confirmText: $("confirmText"),
  confirmCancel: $("confirmCancel"),
  confirmOk: $("confirmOk"),
  strengthMeter: $("strengthMeter"),
  strengthLabel: $("strengthLabel"),
  sb1: $("sb1"), sb2: $("sb2"), sb3: $("sb3"), sb4: $("sb4"),
};

// ── SVG ICONS ──
const EYE_OPEN = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
const EYE_CLOSED = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`;

// ── CRYPTO ──
function getStoredVault() {
  const raw = localStorage.getItem(STORAGE_KEY);
  return raw ? JSON.parse(raw) : null;
}
function bytesToBase64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}
function base64ToBytes(value) {
  return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
}
async function deriveKey(password, salt) {
  const material = await crypto.subtle.importKey("raw", textEncoder.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 260000, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}
async function encryptVault() {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    state.key,
    textEncoder.encode(JSON.stringify(state.vault))
  );
  localStorage.setItem(STORAGE_KEY, JSON.stringify({
    version: 1,
    accountName: state.accountName,
    salt: bytesToBase64(state.salt),
    iv: bytesToBase64(iv),
    data: bytesToBase64(encrypted),
    updatedAt: new Date().toISOString(),
  }));
}
async function decryptVault(password, stored) {
  const salt = base64ToBytes(stored.salt);
  const key = await deriveKey(password, salt);
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(stored.iv) },
    key,
    base64ToBytes(stored.data)
  );
  return { key, salt, vault: JSON.parse(textDecoder.decode(decrypted)) };
}

// ── UTILS ──
function uid() { return crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`; }
function now() { return new Date().toISOString(); }
function activeEntry() { return state.vault.entries.find((e) => e.id === state.activeId) || null; }
function filteredEntries() {
  const needle = state.search.trim().toLowerCase();
  return state.vault.entries
    .filter((e) => state.filter === "all" || e.type === state.filter)
    .filter((e) => !needle || [e.title, e.username, e.url, e.notes].join(" ").toLowerCase().includes(needle))
    .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
}

// ── PASSWORD STRENGTH ──
function passwordStrength(pw) {
  if (!pw) return 0;
  let score = 0;
  if (pw.length >= 10) score++;
  if (pw.length >= 16) score++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  return Math.min(4, Math.round(score * 4 / 5));
}

function updateStrengthMeter(pw) {
  if (!pw) {
    els.strengthMeter.style.display = "none";
    return;
  }
  els.strengthMeter.style.display = "";
  const level = passwordStrength(pw);
  const labels = ["", "Schwach", "Mäßig", "Gut", "Stark"];
  const cls = `filled-${level}`;
  [els.sb1, els.sb2, els.sb3, els.sb4].forEach((bar, i) => {
    bar.className = "strength-bar " + (i < level ? cls : "");
  });
  els.strengthLabel.textContent = labels[level] || "";
  els.strengthLabel.style.color = level <= 1 ? "var(--danger)" : level === 2 ? "#F59E0B" : "var(--success)";
}

// ── RENDER ──
function renderList() {
  const entries = filteredEntries();
  els.entryCount.textContent = String(entries.length);
  els.entryList.innerHTML = "";

  if (!entries.length) {
    const empty = document.createElement("p");
    empty.className = "message";
    empty.textContent = "Keine passenden Einträge.";
    els.entryList.append(empty);
    return;
  }

  const sections = state.filter === "all"
    ? [{ title: "Passwörter", type: "password" }, { title: "Notizen", type: "note" }]
    : [{ title: state.filter === "password" ? "Passwörter" : "Notizen", type: state.filter }];

  for (const section of sections) {
    const sectionEntries = entries.filter((e) => e.type === section.type);
    if (!sectionEntries.length) continue;
    const wrap = document.createElement("section");
    wrap.className = "entry-section";
    const heading = document.createElement("h4");
    heading.textContent = section.title;
    wrap.append(heading);
    for (const entry of sectionEntries) wrap.append(createEntryCard(entry));
    els.entryList.append(wrap);
  }
}

const LOCK_ICON = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`;
const NOTE_ICON = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>`;

function createEntryCard(entry) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = `entry-card ${entry.id === state.activeId ? "active" : ""}`;
  button.dataset.id = entry.id;
  const pillClass = entry.type === "note" ? "note" : "";
  const pillIcon = entry.type === "note" ? NOTE_ICON : LOCK_ICON;
  const pillLabel = entry.type === "note" ? "Notiz" : "Passwort";
  const sub = entry.type === "note"
    ? (entry.notes || "Leere Notiz").slice(0, 80)
    : (entry.username || entry.url || "Kein Login hinterlegt");
  button.innerHTML = `
    <span class="type-pill ${pillClass}">${pillIcon}${pillLabel}</span>
    <strong></strong>
    <span class="card-sub"></span>
  `;
  button.querySelector("strong").textContent = entry.title || "Ohne Titel";
  button.querySelector(".card-sub").textContent = sub;
  button.addEventListener("click", () => selectEntry(entry.id));
  return button;
}

function renderEditor() {
  const entry = activeEntry();
  if (!entry) {
    els.entryForm.classList.add("hidden");
    els.emptyState.classList.remove("hidden");
    return;
  }
  els.emptyState.classList.add("hidden");
  els.entryForm.classList.remove("hidden");
  els.formType.textContent = entry.type === "note" ? "Notiz" : "Passwort";
  els.formTitle.textContent = entry.title || "Neuer Eintrag";
  els.passwordFields.classList.toggle("hidden", entry.type === "note");
  els.titleInput.value = entry.title || "";
  els.usernameInput.value = entry.username || "";
  els.urlInput.value = entry.url || "";
  els.passwordInput.value = entry.password || "";
  els.notesInput.value = entry.notes || "";
  els.saveState.textContent = "";
  updateStrengthMeter(entry.password || "");
}

function render() { renderList(); renderEditor(); }
function selectEntry(id) { state.activeId = id; render(); }

function createEntry(type) {
  const entry = {
    id: uid(), type,
    title: type === "note" ? "Neue Notiz" : "Neues Passwort",
    username: "", url: "", password: "", notes: "",
    createdAt: now(), updatedAt: now(),
  };
  state.vault.entries.push(entry);
  state.activeId = entry.id;
  saveAndRender("Angelegt.");
}

async function saveAndRender(message = "Gespeichert.") {
  await encryptVault();
  render();
  els.saveState.textContent = message;
  window.setTimeout(() => { if (els.saveState.textContent === message) els.saveState.textContent = ""; }, 1800);
}

function fillActiveEntryFromForm() {
  const entry = activeEntry();
  if (!entry) return null;
  entry.title = els.titleInput.value.trim() || "Ohne Titel";
  entry.username = els.usernameInput.value.trim();
  entry.url = els.urlInput.value.trim();
  entry.password = els.passwordInput.value;
  entry.notes = els.notesInput.value.trim();
  entry.updatedAt = now();
  return entry;
}

function generatePassword(length, symbolsEnabled) {
  const letters = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const digits = "23456789";
  const symbols = "!@#$%&*?-_+=";
  const pool = letters + digits + (symbolsEnabled ? symbols : "");
  const bytes = crypto.getRandomValues(new Uint32Array(length));
  return Array.from(bytes, (v) => pool[v % pool.length]).join("");
}

function download(filename, text) {
  const blob = new Blob([text], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

// ── LOCK / UNLOCK ──
function setUnlocked() {
  els.lockScreen.classList.add("hidden");
  els.vaultScreen.classList.remove("hidden");
  els.accountLabel.textContent = state.accountName ? `Angemeldet als ${state.accountName}` : "";
  els.accountName.value = "";
  els.masterPassword.value = "";
  render();
}

function lock() {
  state.key = null; state.salt = null;
  state.vault = { entries: [] }; state.accountName = ""; state.activeId = null;
  els.vaultScreen.classList.add("hidden");
  els.lockScreen.classList.remove("hidden");
  els.lockMessage.textContent = "";
  updateLockCopy();
  els.masterPassword.focus();
}

function updateLockCopy() {
  const stored = getStoredVault();
  const hasVault = Boolean(stored);
  els.lockHint.textContent = hasVault
    ? "Gib deinen Account-Namen und dein Master-Passwort ein, um den Tresor zu entsperren."
    : "Erstelle einen Account mit Master-Passwort. Deine Daten bleiben verschlüsselt in diesem Browser.";
  els.accountName.placeholder = stored?.accountName || "z. B. Paul";
  const btn = els.unlockButton;
  btn.innerHTML = hasVault
    ? `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="width:16px;height:16px"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg> Entsperren`
    : `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="width:16px;height:16px"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> Tresor erstellen`;
}

// ── EVENTS ──
els.unlockForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const accountName = els.accountName.value.trim();
  const password = els.masterPassword.value;
  els.lockMessage.textContent = "Einen Moment…";
  try {
    if (!accountName) { els.lockMessage.textContent = "Bitte gib einen Account-Namen ein."; return; }
    const stored = getStoredVault();
    if (stored) {
      if (stored.accountName && stored.accountName.toLowerCase() !== accountName.toLowerCase()) {
        els.lockMessage.textContent = "Dieser Account-Name passt nicht zu diesem Tresor."; return;
      }
      const result = await decryptVault(password, stored);
      state.key = result.key; state.salt = result.salt;
      state.vault = result.vault; state.accountName = stored.accountName || accountName;
      if (!stored.accountName) await encryptVault();
    } else {
      state.salt = crypto.getRandomValues(new Uint8Array(16));
      state.key = await deriveKey(password, state.salt);
      state.vault = { entries: [] }; state.accountName = accountName;
      await encryptVault();
    }
    setUnlocked();
  } catch {
    els.lockMessage.textContent = "Master-Passwort stimmt nicht oder Backup ist beschädigt.";
  }
});

function toggleVisibility(input, btn, iconEl) {
  const show = input.type === "password";
  input.type = show ? "text" : "password";
  btn.innerHTML = show ? EYE_CLOSED : EYE_OPEN;
}

els.toggleMaster.addEventListener("click", () => toggleVisibility(els.masterPassword, els.toggleMaster));
els.togglePassword.addEventListener("click", () => toggleVisibility(els.passwordInput, els.togglePassword));

els.copyPassword.addEventListener("click", async () => {
  if (!els.passwordInput.value) return;
  await navigator.clipboard.writeText(els.passwordInput.value);
  els.saveState.textContent = "Passwort kopiert ✓";
  setTimeout(() => { if (els.saveState.textContent === "Passwort kopiert ✓") els.saveState.textContent = ""; }, 1800);
});

els.passwordInput.addEventListener("input", () => updateStrengthMeter(els.passwordInput.value));

els.entryForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  fillActiveEntryFromForm();
  await saveAndRender();
});

for (const input of [els.titleInput, els.usernameInput, els.urlInput, els.passwordInput, els.notesInput]) {
  input.addEventListener("change", async () => { fillActiveEntryFromForm(); await saveAndRender(); });
}

els.deleteButton.addEventListener("click", async () => {
  const entry = activeEntry();
  if (!entry) return;
  const ok = await openConfirm({
    title: "Eintrag löschen?",
    text: `"${entry.title || "Eintrag"}" wirklich löschen? Diese Aktion kann nicht rückgängig gemacht werden.`,
  });
  if (!ok) return;
  state.vault.entries = state.vault.entries.filter((item) => item.id !== entry.id);
  state.activeId = state.vault.entries[0]?.id || null;
  await saveAndRender("Gelöscht.");
});

els.newPasswordButton.addEventListener("click", () => createEntry("password"));
els.newNoteButton.addEventListener("click", () => createEntry("note"));

document.querySelectorAll("[data-create]").forEach((btn) => {
  btn.addEventListener("click", () => createEntry(btn.dataset.create));
});

document.querySelectorAll(".segment").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".segment").forEach((s) => s.classList.remove("active"));
    btn.classList.add("active");
    state.filter = btn.dataset.filter;
    renderList();
  });
});

els.searchInput.addEventListener("input", () => { state.search = els.searchInput.value; renderList(); });
els.lengthInput.addEventListener("input", () => { els.lengthOutput.textContent = els.lengthInput.value; });

els.generateButton.addEventListener("click", () => {
  const pw = generatePassword(Number(els.lengthInput.value), els.symbolsInput.checked);
  els.passwordInput.value = pw;
  updateStrengthMeter(pw);
  fillActiveEntryFromForm();
  saveAndRender("Passwort generiert.");
});

els.exportButton.addEventListener("click", () => {
  const stored = localStorage.getItem(STORAGE_KEY);
  if (!stored) return;
  download(`tresor-backup-${new Date().toISOString().slice(0, 10)}.json`, stored);
});

els.importFile.addEventListener("change", async () => {
  const file = els.importFile.files[0];
  if (!file) return;
  const text = await file.text();
  try {
    const parsed = JSON.parse(text);
    if (!parsed.salt || !parsed.iv || !parsed.data) throw new Error("Invalid backup");
    localStorage.setItem(STORAGE_KEY, JSON.stringify(parsed));
    alert("Backup importiert. Bitte mit dem passenden Master-Passwort neu entsperren.");
    lock();
  } catch {
    alert("Diese Datei ist kein gültiges Tresor-Backup.");
  } finally {
    els.importFile.value = "";
  }
});

els.lockButton.addEventListener("click", lock);

// ── CONFIRM MODAL ──
function openConfirm({ title, text }) {
  els.confirmTitle.textContent = title;
  els.confirmText.textContent = text;
  els.confirmOverlay.classList.remove("hidden");
  els.confirmOverlay.setAttribute("aria-hidden", "false");
  els.confirmCancel.focus();
  return new Promise((resolve) => { state.pendingConfirm = resolve; });
}
function closeConfirm(result) {
  els.confirmOverlay.classList.add("hidden");
  els.confirmOverlay.setAttribute("aria-hidden", "true");
  if (state.pendingConfirm) state.pendingConfirm(result);
  state.pendingConfirm = null;
}
els.confirmCancel.addEventListener("click", () => closeConfirm(false));
els.confirmOk.addEventListener("click", () => closeConfirm(true));
els.confirmOverlay.addEventListener("click", (e) => { if (e.target === els.confirmOverlay) closeConfirm(false); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && state.pendingConfirm) closeConfirm(false); });

// ── THEME ──
function applyTheme(theme) {
  const next = theme === "dark" ? "dark" : "light";
  document.body.dataset.theme = next;
  localStorage.setItem(THEME_KEY, next);
  const isDark = next === "dark";
  els.themeButton.innerHTML = isDark
    ? `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg> Hell`
    : `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg> Dunkel`;
}
els.themeButton.addEventListener("click", () => applyTheme(document.body.dataset.theme === "dark" ? "light" : "dark"));

// ── INIT ──
applyTheme(localStorage.getItem(THEME_KEY) || "light");
updateLockCopy();
