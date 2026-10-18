/* Telegram Drive web app. Plain JavaScript, no build step. */
"use strict";

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];

const state = { status: null, path: "/", entries: [], selected: new Set(), searching: null, accounts: [] };

// ---------- helpers ----------
async function api(method, url, body) {
  const opts = { method, credentials: "same-origin", headers: {} };
  if (method !== "GET") opts.headers["X-TgDrive"] = "1";
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const r = await fetch(url, opts);
  let data = null;
  try { data = await r.json(); } catch { /* empty */ }
  if (r.status === 401 && !url.startsWith("/api/login") && !url.startsWith("/api/setup")) {
    showAuth();
    throw new Error("Please sign in again");
  }
  if (!r.ok) throw new Error((data && data.detail) || `Error ${r.status}`);
  return data;
}

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) if (c !== null && c !== undefined) el.append(c);
  return el;
}

function fmtSize(n) {
  if (n === null || n === undefined) return "";
  const u = ["B", "KB", "MB", "GB", "TB", "PB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n < 10 && i ? n.toFixed(1) : Math.round(n)} ${u[i]}`;
}
function fmtDate(s) {
  if (!s) return "";
  const d = new Date(s);
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) +
    " " + d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}
function joinPath(dir, name) { return (dir.endsWith("/") ? dir : dir + "/") + name; }
function parentOf(p) { const i = p.replace(/\/$/, "").lastIndexOf("/"); return i <= 0 ? "/" : p.slice(0, i); }
function baseName(p) { return p.replace(/\/$/, "").split("/").pop(); }
function enc(p) { return encodeURIComponent(p); }

let toastTimer;
function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("show"), 3500);
}
async function run(fn, okMsg) {
  try { const r = await fn(); if (okMsg) toast(okMsg); return r; }
  catch (e) { toast(e.message); return null; }
}

function fillTo(el, pct) { el.style.width = `${pct.toFixed(1)}%`; return el; }
function bar(used, total) {
  const pct = total ? Math.min(100, (used / total) * 100) : 0;
  const cls = pct > 95 ? "bar full" : pct > 85 ? "bar high" : "bar";
  return h("div", { class: cls, role: "progressbar", "aria-valuemin": "0", "aria-valuemax": "100",
    "aria-valuenow": String(Math.round(pct)), "aria-label": "Storage used" },
    fillTo(h("span"), pct));
}

// ---------- dialogs ----------
function dialog({ title, fields = [], okText = "OK", danger = false, body = null }) {
  return new Promise((resolve) => {
    const dlg = $("#dlg");
    $("#dlg-title").textContent = title;
    const box = $("#dlg-body");
    box.replaceChildren();
    if (body) box.append(body);
    const inputs = {};
    for (const f of fields) {
      let input;
      if (f.options) {
        input = h("select", { name: f.name }, f.options.map((o) => h("option", { value: o.value, text: o.label })));
      } else {
        input = h("input", { name: f.name, value: f.value || "", type: f.type || "text", autocomplete: "off" });
      }
      inputs[f.name] = input;
      box.append(h("label", {}, f.label, input));
    }
    const ok = $("#dlg-ok");
    ok.textContent = okText;
    ok.className = danger ? "btn primary danger-bg" : "btn primary";
    dlg.onclose = () => {
      if (dlg.returnValue !== "ok") return resolve(null);
      const out = {};
      for (const [k, el] of Object.entries(inputs)) out[k] = el.value;
      resolve(out);
    };
    dlg.returnValue = "";
    dlg.showModal();
    const first = fields.length ? inputs[fields[0].name] : ok;
    first.focus();
    if (first.select && first.value) {
      const dot = first.value.lastIndexOf(".");
      first.setSelectionRange(0, dot > 0 ? dot : first.value.length);
    }
  });
}

// ---------- auth ----------
function showAuth() {
  $("#app").hidden = true;
  $("#auth").hidden = false;
  const setup = state.status && state.status.setup_needed;
  $("#auth-title").textContent = setup ? "Set up Telegram Drive" : "Sign in to Telegram Drive";
  $("#auth-hint").textContent = setup
    ? "Choose the password for this server. The setup code is printed in the server log (docker logs drivehub)."
    : state.status && state.status.demo ? "Demo password: demo-password" : "";
  $("#setup-code-row").hidden = !setup;
  $("#code-row").hidden = setup;
  $("#password").autocomplete = setup ? "new-password" : "current-password";
  $("#auth-submit").textContent = setup ? "Save password" : "Sign in";
  (setup ? $("#setup-code") : $("#password")).focus();
}

$("#auth-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("#auth-error");
  err.textContent = "";
  const setup = state.status.setup_needed;
  try {
    if (setup) {
      await api("POST", "/api/setup", { setup_code: $("#setup-code").value.trim(), password: $("#password").value });
    } else {
      await api("POST", "/api/login", { password: $("#password").value, code: $("#code").value });
    }
    $("#password").value = "";
    $("#code").value = "";
    await boot();
  } catch (ex) {
    err.textContent = ex.message;
  }
});

$("#logout").addEventListener("click", async () => {
  await run(() => api("POST", "/api/logout"));
  state.status.logged_in = false;
  showAuth();
});

// ---------- routing ----------
function route() {
  // The hash holds an encoded path, so names with %, ? or # survive the round trip.
  const raw = location.hash.slice(1) || "/files/";
  const qi = raw.indexOf("?");
  const pathPart = (qi < 0 ? raw : raw.slice(0, qi)).split("/").map(safeDecode).join("/");
  const query = qi < 0 ? "" : raw.slice(qi + 1);
  const params = new URLSearchParams(query || "");
  let view = "files";
  if (pathPart.startsWith("/accounts")) view = "accounts";
  else if (pathPart.startsWith("/settings")) view = "settings";
  if (!state.status.vault_ready) view = "vault";
  else if (view === "files" && state.status.accounts === 0) view = "accounts";
  for (const v of ["files", "accounts", "settings", "vault"]) $(`#view-${v}`).hidden = v !== view;
  $$("[data-nav]").forEach((a) => {
    if (a.dataset.nav === view) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
  if (view === "files") {
    const p = pathPart.slice("/files".length) || "/";
    state.searching = null;
    loadFolder(p);
  } else if (view === "accounts") {
    loadAccounts();
  } else if (view === "vault") {
    showVaultChoice();
  } else {
    loadSettings();
  }
}
window.addEventListener("hashchange", route);
function safeDecode(seg) { try { return decodeURIComponent(seg); } catch { return seg; } }
function encPath(p) { return p.split("/").map(encodeURIComponent).join("/"); }
function filesHref(path) { return "#/files" + (path === "/" ? "/" : encPath(path)); }
function go(path) { location.hash = filesHref(path); }

// ---------- files ----------
const ICONS = {
  folder: '<svg viewBox="0 0 24 24" class="icon" aria-hidden="true"><path fill="#f2b632" d="M3 6.5A1.5 1.5 0 0 1 4.5 5h4.6l2 2h8.4A1.5 1.5 0 0 1 21 8.5v9A1.5 1.5 0 0 1 19.5 19h-15A1.5 1.5 0 0 1 3 17.5z"/></svg>',
  file: (color) => `<svg viewBox="0 0 24 24" class="icon" aria-hidden="true"><path fill="${color}" d="M6 2.5h8l5 5v13a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1v-17a1 1 0 0 1 1-1z"/><path fill="#fff" opacity=".55" d="M14 2.5v5h5z"/></svg>`,
};
function iconFor(e) {
  if (e.is_dir) return ICONS.folder;
  const m = e.mime || "";
  const c = m.startsWith("image/") ? "#e5484d" : m.startsWith("video/") ? "#8e4ec6" : m.startsWith("audio/") ? "#d6409f"
    : m === "application/pdf" ? "#dc3e42" : m.includes("sheet") ? "#30a46c" : m.includes("presentation") ? "#f76b15"
    : m.includes("word") || m.startsWith("text/") ? "#3e63dd" : m.includes("zip") ? "#8d8d86" : "#7c8594";
  return ICONS.file(c);
}
function iconEl(e) { const s = h("span"); s.innerHTML = iconFor(e); return s.firstChild; }

async function loadFolder(path) {
  state.path = path;
  state.selected.clear();
  $("#search-head").hidden = true;
  $("#search").value = "";
  renderCrumbs();
  setEmpty("Loading…");
  $("#files-body").replaceChildren();
  try {
    const data = await api("GET", `/api/files?path=${enc(path)}`);
    if (state.path !== path) return;
    state.entries = data.entries;
    showAccountErrors(data.errors);
    renderFiles();
  } catch (e) {
    setEmpty(e.message);
  }
  loadStorageMini();
}

function showAccountErrors(errors) {
  const b = $("#account-errors");
  if (!errors || !errors.length) { b.hidden = true; return; }
  b.textContent = "Some accounts could not be reached: " + errors.map((e) => `${e.account} (${e.error})`).join("; ");
  b.hidden = false;
}

function setEmpty(text) { const e = $("#empty"); e.textContent = text || ""; e.hidden = !text; }

function renderCrumbs() {
  const nav = $("#crumbs");
  nav.replaceChildren();
  const parts = state.path.split("/").filter(Boolean);
  const items = [{ name: "My files", path: "/" }];
  parts.forEach((p, i) => items.push({ name: p, path: "/" + parts.slice(0, i + 1).join("/") }));
  items.forEach((it, i) => {
    if (i) nav.append(h("span", { class: "sep", "aria-hidden": "true", text: "›" }));
    if (i === items.length - 1) nav.append(h("span", { "aria-current": "page", text: it.name }));
    else nav.append(h("a", { href: filesHref(it.path), text: it.name }));
  });
  document.title = (parts.length ? parts[parts.length - 1] + " – " : "") + "Telegram Drive";
}

function renderFiles(list = state.entries, opts = {}) {
  const body = $("#files-body");
  body.replaceChildren();
  $("#check-all").checked = false;
  if (!list.length) {
    setEmpty(opts.search ? "No matches in any account." :
      state.accounts.length === 0 && state.path === "/" ? "No files yet. Upload files or drop them here." : "This folder is empty. Drop files here to upload.");
  } else setEmpty("");
  for (const e of list) {
    const tr = h("tr", { "data-path": e.path });
    const check = h("input", { type: "checkbox", "aria-label": `Select ${e.name}`, onchange: (ev) => {
      ev.target.checked ? state.selected.add(e.path) : state.selected.delete(e.path);
      tr.classList.toggle("selected", ev.target.checked);
      updateSelection();
    } });
    const nameBtn = e.is_dir
      ? h("a", { href: filesHref(e.path), text: e.name })
      : h("button", { type: "button", text: e.name, onclick: () => openFile(e) });
    const nameCell = h("div", { class: "name-cell" }, iconEl(e), h("div", {}, nameBtn,
      opts.search ? h("div", { class: "sub", text: `in ${e.folder}` }) : null));
    const acc = h("td", { class: "col-acc" }, (e.accounts || [e.account]).filter(Boolean).map((a) => h("span", { class: "badge", text: a })));
    const kebab = h("button", { class: "btn ghost kebab", type: "button", "aria-label": `Actions for ${e.name}`, "aria-haspopup": "menu",
      onclick: (ev) => openMenu(ev.currentTarget, e), text: "⋯" });
    tr.append(h("td", { class: "col-check" }, check), h("td", {}, nameCell), acc,
      h("td", { class: "col-size", text: e.is_dir ? "" : fmtSize(e.size) }),
      h("td", { class: "col-date", text: fmtDate(e.modified) }), h("td", { class: "col-act" }, kebab));
    tr.addEventListener("contextmenu", (ev) => { ev.preventDefault(); openMenu(kebab, e, ev); });
    body.append(tr);
  }
  updateSelection();
}

function updateSelection() {
  const n = state.selected.size;
  $("#selection-info").textContent = n ? `${n} selected` : "";
  $("#btn-delete-selected").hidden = !n;
}

$("#check-all").addEventListener("change", (ev) => {
  $$("#files-body tr").forEach((tr) => {
    const cb = $("input[type=checkbox]", tr);
    cb.checked = ev.target.checked;
    cb.dispatchEvent(new Event("change"));
  });
});

// ---------- context menu ----------
function closeMenu() { const m = $("#menu"); m.hidden = true; m.replaceChildren(); }
document.addEventListener("click", (ev) => { if (!ev.target.closest("#menu") && !ev.target.closest(".kebab")) closeMenu(); });
document.addEventListener("keydown", (ev) => { if (ev.key === "Escape") closeMenu(); });

function openMenu(anchor, e, ev) {
  const m = $("#menu");
  m.replaceChildren();
  const item = (label, fn, cls) => h("button", { type: "button", role: "menuitem", class: cls, text: label, onclick: () => { closeMenu(); fn(); } });
  if (e.is_dir) m.append(item("Open", () => go(e.path)));
  else {
    m.append(item("Open / preview", () => openFile(e)));
    m.append(item("Download", () => download(e)));
  }
  m.append(h("hr"));
  m.append(item("Rename", () => renameItem(e)));
  m.append(item("Move or copy…", () => moveItem(e)));
  m.append(item("Get share link", () => shareItem(e)));
  m.append(h("hr"));
  m.append(item("Delete", () => deleteItems([e.path]), "danger"));
  m.hidden = false;
  const r = anchor.getBoundingClientRect();
  const x = ev ? ev.clientX : r.right;
  const y = ev ? ev.clientY : r.bottom;
  const w = m.offsetWidth, hgt = m.offsetHeight;
  m.style.left = Math.max(8, Math.min(x - (ev ? 0 : w), innerWidth - w - 8)) + "px";
  m.style.top = Math.max(8, Math.min(y + 4, innerHeight - hgt - 8)) + "px";
  $("button", m).focus();
}

function download(e) {
  const a = h("a", { href: `/api/download?path=${enc(e.path)}`, download: e.name });
  document.body.append(a); a.click(); a.remove();
}

async function openFile(e) {
  const m = e.mime || "";
  const url = `/api/download?path=${enc(e.path)}&inline=1`;
  const body = $("#preview-body");
  body.replaceChildren();
  if (m.startsWith("image/") && !m.includes("svg")) body.append(h("img", { src: url, alt: e.name }));
  else if (m.startsWith("video/")) body.append(h("video", { src: url, controls: true, autoplay: true }));
  else if (m.startsWith("audio/")) body.append(h("audio", { src: url, controls: true, autoplay: true }));
  else if (m === "application/pdf") body.append(h("iframe", { src: url, title: e.name }));
  else if (m.startsWith("text/") || /\.(md|json|csv|log|ya?ml|py|js|ts|sh|ini|conf|toml)$/i.test(e.name)) {
    if ((e.size || 0) > 2 * 1024 * 1024) return download(e);
    const pre = h("pre", { text: "Loading…" });
    body.append(pre);
    fetch(url, { credentials: "same-origin" }).then((r) => r.text()).then((t) => { pre.textContent = t; });
  } else return download(e);
  $("#preview-title").textContent = e.name;
  $("#preview-download").href = `/api/download?path=${enc(e.path)}`;
  $("#preview-download").setAttribute("download", e.name);
  $("#preview").showModal();
}
$("#preview-close").addEventListener("click", () => $("#preview").close());
$("#preview").addEventListener("close", () => $("#preview-body").replaceChildren());

async function renameItem(e) {
  const r = await dialog({ title: `Rename "${e.name}"`, fields: [{ name: "name", label: "New name", value: e.name }], okText: "Rename" });
  if (!r || !r.name.trim() || r.name.trim() === e.name) return;
  if (r.name.includes("/")) return toast("Names cannot contain /");
  await run(() => api("POST", "/api/move", { src: e.path, dst: joinPath(parentOf(e.path), r.name.trim()) }), "Renamed");
  refresh();
}

async function moveItem(e) {
  const r = await dialog({
    title: `Move or copy "${e.name}"`,
    fields: [
      { name: "dst", label: "Destination folder", value: parentOf(e.path) },
      { name: "mode", label: "Action", options: [{ value: "move", label: "Move" }, { value: "copy", label: "Copy" }] },
    ],
    okText: "Go",
  });
  if (!r) return;
  const dir = "/" + r.dst.split("/").filter(Boolean).join("/");
  const ok = await run(() => api("POST", r.mode === "copy" ? "/api/copy" : "/api/move", { src: e.path, dst: joinPath(dir, e.name) }),
    r.mode === "copy" ? "Copied" : "Moved");
  if (ok) refresh();
}

async function shareItem(e) {
  if (e.is_dir) return toast("Only files can be shared");
  const r = await dialog({ title: `Share "${e.name}"`, body: h("p", { class: "muted", text: "Creates a link that lets anyone download this file, decrypted, until it expires. You can revoke it in Settings." }),
    fields: [{ name: "days", label: "Link expires after", options: [1, 7, 30].map((d) => ({ value: d, label: `${d} day${d > 1 ? "s" : ""}` })) }], okText: "Create link" });
  if (!r) return;
  const data = await run(() => api("POST", "/api/share", { path: e.path, days: Number(r.days) }));
  if (!data) return;
  const body = h("div", {}, h("p", { class: "muted", text: "Anyone with this link can download the file until it expires." }),
    data.links.map((l) => h("p", {}, h("span", { class: "badge", text: l.account }), " ", h("a", { href: l.link, target: "_blank", rel: "noopener", text: l.link }))));
  if (navigator.clipboard && data.links.length === 1) navigator.clipboard.writeText(data.links[0].link).then(() => toast("Link copied"), () => {});
  await dialog({ title: "Share link", body, okText: "Done" });
}

async function deleteItems(paths) {
  const label = paths.length === 1 ? `"${baseName(paths[0])}"` : `${paths.length} items`;
  const r = await dialog({ title: `Delete ${label}?`, body: h("p", { text: "This permanently deletes the files and removes their parts from Telegram. It cannot be undone." }), okText: "Delete", danger: true });
  if (!r) return;
  const ok = await run(() => api("POST", "/api/delete", { paths }), "Deleted");
  if (ok) refresh();
}
$("#btn-delete-selected").addEventListener("click", () => deleteItems([...state.selected]));

$("#btn-mkdir").addEventListener("click", async () => {
  const r = await dialog({ title: "New folder", fields: [{ name: "name", label: "Folder name", value: "" }], okText: "Create" });
  if (!r || !r.name.trim()) return;
  if (r.name.includes("/")) return toast("Names cannot contain /");
  const ok = await run(() => api("POST", "/api/mkdir", { path: joinPath(state.path, r.name.trim()) }), "Folder created");
  if (ok) refresh();
});
$("#btn-refresh").addEventListener("click", async () => { await run(() => api("POST", "/api/refresh")); refresh(); });
function refresh() {
  if (state.searching) doSearch(state.searching);
  else loadFolder(state.path);
}

// ---------- uploads ----------
$("#btn-upload").addEventListener("click", () => $("#file-input").click());
$("#btn-upload-folder").addEventListener("click", () => $("#folder-input").click());
$("#file-input").addEventListener("change", (e) => { uploadFiles([...e.target.files].map((f) => [f, f.name])); e.target.value = ""; });
$("#folder-input").addEventListener("change", (e) => { uploadFiles([...e.target.files].map((f) => [f, f.webkitRelativePath || f.name])); e.target.value = ""; });

const queue = [];
let active = 0;
function uploadFiles(pairs) {
  if (!pairs.length) return;
  const dir = state.path;
  const panel = $("#uploads");
  panel.hidden = false;
  for (const [file, rel] of pairs) {
    const row = h("div", { class: "up-row" }, h("div", { text: rel }), bar(0, 1));
    panel.append(row);
    queue.push({ file, rel, dir, row });
  }
  pump();
}
function pump() {
  while (active < 2 && queue.length) {
    const job = queue.shift();
    active++;
    sendFile(job).finally(() => {
      active--;
      if (!queue.length && !active) {
        setTimeout(() => { if (!active) { $("#uploads").hidden = true; $("#uploads").replaceChildren(); } }, 2500);
        if (!state.searching) loadFolder(state.path);
      }
      pump();
    });
  }
}
function sendFile({ file, rel, dir, row }) {
  return new Promise((resolve) => {
    const fd = new FormData();
    fd.append("path", dir);
    fd.append("relpaths", rel);
    fd.append("files", file, file.name);
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/upload");
    xhr.setRequestHeader("X-TgDrive", "1");
    const fill = $(".bar > span", row);
    xhr.upload.onprogress = (e) => { if (e.lengthComputable) fill.style.width = `${(e.loaded / e.total) * 95}%`; };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        fill.style.width = "100%";
        $("div", row).textContent = `${rel} – done`;
      } else {
        let msg = `error ${xhr.status}`;
        try { msg = JSON.parse(xhr.responseText).detail; } catch { /* ignore */ }
        $(".bar", row).classList.add("full");
        $("div", row).textContent = `${rel} – ${msg}`;
        toast(`Upload failed: ${msg}`);
      }
      resolve();
    };
    xhr.onerror = () => { $("div", row).textContent = `${rel} – network error`; resolve(); };
    xhr.send(fd);
  });
}

// drag and drop (folders supported through the entries API)
let dragDepth = 0;
const filesView = $("#view-files");
filesView.addEventListener("dragenter", (e) => { if (hasFiles(e)) { dragDepth++; $("#drop").hidden = false; } });
filesView.addEventListener("dragleave", () => { if (--dragDepth <= 0) { dragDepth = 0; $("#drop").hidden = true; } });
filesView.addEventListener("dragover", (e) => { if (hasFiles(e)) e.preventDefault(); });
filesView.addEventListener("drop", async (e) => {
  e.preventDefault();
  dragDepth = 0;
  $("#drop").hidden = true;
  if (state.searching) return toast("Open a folder to upload into it");
  const items = [...e.dataTransfer.items].map((i) => i.webkitGetAsEntry && i.webkitGetAsEntry()).filter(Boolean);
  if (!items.length) return uploadFiles([...e.dataTransfer.files].map((f) => [f, f.name]));
  const pairs = [];
  await Promise.all(items.map((entry) => walk(entry, "", pairs)));
  uploadFiles(pairs);
});
function hasFiles(e) { return e.dataTransfer && [...e.dataTransfer.types].includes("Files"); }
function walk(entry, prefix, out) {
  return new Promise((resolve) => {
    if (entry.isFile) entry.file((f) => { out.push([f, prefix + f.name]); resolve(); }, () => resolve());
    else if (entry.isDirectory) {
      const reader = entry.createReader();
      const all = [];
      const read = () => reader.readEntries(async (batch) => {
        if (batch.length) { all.push(...batch); read(); }
        else { await Promise.all(all.map((c) => walk(c, prefix + entry.name + "/", out))); resolve(); }
      }, () => resolve());
      read();
    } else resolve();
  });
}

// ---------- search ----------
$("#search-form").addEventListener("submit", (e) => { e.preventDefault(); const q = $("#search").value.trim(); if (q) doSearch(q); });
$("#btn-clear-search").addEventListener("click", () => { state.searching = null; loadFolder(state.path); });
async function doSearch(q) {
  if (!location.hash.startsWith("#/files")) location.hash = "#/files/";
  state.searching = q;
  $("#search-head").hidden = false;
  $("#search-title").textContent = `Results for "${q}"`;
  $("#files-body").replaceChildren();
  setEmpty("Searching all accounts…");
  const data = await run(() => api("GET", `/api/search?q=${enc(q)}`));
  if (!data || state.searching !== q) return;
  state.entries = data.results;
  renderFiles(data.results, { search: true });
}

// ---------- storage ----------
async function loadStorageMini() {
  const data = await run(() => api("GET", "/api/accounts"));
  if (!data) return;
  state.accounts = data.accounts.filter((a) => !a.error);
  const box = $("#storage-mini");
  box.replaceChildren();
  if (!data.accounts.length) return;
  box.append(h("div", { text: `${fmtSize(data.used)} stored in ${data.accounts.length} Telegram account${data.accounts.length > 1 ? "s" : ""} · no storage limit` }));
}

async function loadAccounts() {
  $("#tg-missing").hidden = state.status.telegram_configured;
  $("#tg-form").hidden = !state.status.telegram_configured;
  $("#tg-demo").hidden = !state.status.demo;
  const list = $("#accounts-list");
  const data = await run(() => api("GET", "/api/accounts"));
  if (!data) return;
  state.status.accounts = data.accounts.length;
  state.accounts = data.accounts.filter((a) => !a.error);
  const backup = data.last_backup ? `Index last backed up ${fmtDate(new Date(data.last_backup * 1000).toISOString())}.` : "The index has not been backed up yet.";
  $("#pool-card").replaceChildren(
    h("h2", { text: "Your storage" }),
    h("div", { class: "pool-num", text: fmtSize(data.used) }),
    h("p", { class: "muted", text: data.accounts.length ? `Stored, encrypted, in ${data.accounts.length} Telegram account${data.accounts.length === 1 ? "" : "s"}. Telegram sets no total storage limit. ${backup}` : "No Telegram account linked yet. Add one below to start uploading." }));
  list.replaceChildren(...data.accounts.map((a) => h("div", { class: "card acc-card" },
    h("div", { class: "acc-top" },
      h("div", {}, h("div", { class: "acc-label", text: a.label }), h("div", { class: "muted", text: `${a.name} · ${a.phone}` })),
      h("div", { class: "acc-actions" },
        h("button", { class: "btn small", type: "button", text: "Rename", onclick: () => renameAccount(a) }),
        h("button", { class: "btn small danger", type: "button", text: "Unlink", onclick: () => unlinkAccount(a) }))),
    a.error ? h("p", { class: "warn-text", text: a.error }) : null,
    h("div", { class: "muted", text: `${fmtSize(a.stored)} in ${a.parts} encrypted part${a.parts === 1 ? "" : "s"} in Saved Messages` }))));
}
async function renameAccount(a) {
  const r = await dialog({ title: "Rename account", fields: [{ name: "label", label: "Short name shown on files", value: a.label }], okText: "Save" });
  if (!r || !r.label.trim()) return;
  if (await run(() => api("PATCH", `/api/accounts/${a.id}`, { label: r.label.trim() }), "Saved")) loadAccounts();
}
async function unlinkAccount(a) {
  if (a.parts > 0) {
    const r = await dialog({ title: `Unlink ${a.label}?`, body: h("p", { text: `${a.parts} file parts are stored in this account. Move them to your other accounts first, or the files that use them can no longer be opened.` }),
      fields: [{ name: "how", label: "What to do", options: [{ value: "move", label: "Move the parts to my other accounts, then unlink" }, { value: "force", label: "Unlink anyway (those files become unreadable)" }] }], okText: "Continue", danger: true });
    if (!r) return;
    if (r.how === "move") {
      toast("Moving parts… this can take a while for big files");
      const moved = await run(() => api("POST", `/api/accounts/${a.id}/evacuate`));
      if (!moved) return;
    }
    if (await run(() => api("DELETE", `/api/accounts/${a.id}?force=true`), "Unlinked")) loadAccounts();
    return;
  }
  const r = await dialog({ title: `Unlink ${a.label}?`, body: h("p", { text: "Nothing is stored in this account. To end the session completely, also remove \"Telegram Drive\" in Telegram under Settings → Devices." }), okText: "Unlink", danger: true });
  if (!r) return;
  if (await run(() => api("DELETE", `/api/accounts/${a.id}`), "Unlinked")) loadAccounts();
}

// Telegram login: phone → code → (optional) two-step password
const tgLogin = { step: "phone", id: "" };
function tgStep(step, hint) {
  tgLogin.step = step;
  $("#tg-phone-row").hidden = step !== "phone";
  $("#tg-code-row").hidden = step !== "code";
  $("#tg-pw-row").hidden = step !== "password";
  $("#tg-cancel").hidden = step === "phone";
  $("#tg-submit").textContent = step === "phone" ? "Send code" : step === "code" ? "Verify code" : "Sign in";
  $("#tg-hint").textContent = hint ? `(hint: ${hint})` : "";
  const focus = { phone: "#tg-phone", code: "#tg-code", password: "#tg-password" }[step];
  $(focus).focus();
}
$("#tg-cancel").addEventListener("click", () => { $("#tg-error").textContent = ""; tgStep("phone"); });
$("#tg-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("#tg-error");
  err.textContent = "";
  const btn = $("#tg-submit");
  btn.disabled = true;
  try {
    if (tgLogin.step === "phone") {
      const r = await api("POST", "/api/telegram/start", { phone: $("#tg-phone").value });
      tgLogin.id = r.login_id;
      tgStep("code");
      toast("Telegram sent a login code to your Telegram app");
    } else {
      const r = tgLogin.step === "code"
        ? await api("POST", "/api/telegram/code", { login_id: tgLogin.id, code: $("#tg-code").value })
        : await api("POST", "/api/telegram/password", { login_id: tgLogin.id, password: $("#tg-password").value });
      if (r.status === "password_needed") { tgStep("password", r.hint); return; }
      toast(`Linked ${r.account.name}`);
      for (const id of ["#tg-phone", "#tg-code", "#tg-password"]) $(id).value = "";
      tgStep("phone");
      loadAccounts();
    }
  } catch (ex) {
    err.textContent = ex.message;
    if (/expired|start again/.test(ex.message)) tgStep("phone");
  } finally {
    btn.disabled = false;
  }
});

// ---------- vault ----------
function showVaultChoice() {
  $("#vault-choose").hidden = false;
  $("#vault-show").hidden = true;
  $("#vault-restore").hidden = true;
}
$("#vault-new").addEventListener("click", async () => {
  const r = await run(() => api("POST", "/api/vault/create"));
  if (!r) return;
  $("#vault-key").textContent = r.recovery_key;
  $("#vault-choose").hidden = true;
  $("#vault-show").hidden = false;
});
$("#vault-saved").addEventListener("change", (e) => { $("#vault-continue").disabled = !e.target.checked; });
$("#vault-continue").addEventListener("click", () => { state.status.vault_ready = true; location.hash = "#/accounts"; route(); });
$("#vault-restore-open").addEventListener("click", () => { $("#vault-choose").hidden = true; $("#vault-restore").hidden = false; $("#vault-restore-key").focus(); });
$("#vault-restore").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("#vault-error").textContent = "";
  try {
    await api("POST", "/api/vault/restore", { recovery_key: $("#vault-restore-key").value });
    state.status.vault_ready = true;
    toast("Key restored. Link your Telegram accounts, then rebuild from Settings.");
    location.hash = "#/accounts";
    route();
  } catch (ex) { $("#vault-error").textContent = ex.message; }
});

// ---------- settings ----------
async function loadSettings() {
  $("#dav-url").textContent = state.status.dav_url;
  $("#version").textContent = `Telegram Drive ${state.status.version} · an independent open-source project, not affiliated with Telegram.`;
  loadAppPasswords();
  renderTotp();
  loadShares();
  const data = await run(() => api("GET", "/api/accounts"));
  if (data) $("#btn-replace-key").hidden = data.accounts.some((a) => a.parts > 0);
  if (data) $("#backup-info").textContent = data.last_backup ? `Index last backed up ${fmtDate(new Date(data.last_backup * 1000).toISOString())}.` : "The index has not been backed up yet; it is backed up automatically shortly after each change.";
}
$("#btn-show-key").addEventListener("click", async () => {
  const r = await dialog({ title: "Show recovery key", fields: [{ name: "password", label: "Your Telegram Drive password", type: "password" }], okText: "Show" });
  if (!r) return;
  const k = await run(() => api("POST", "/api/vault/recovery-key", { password: r.password }));
  if (!k) return;
  await dialog({ title: "Recovery key", body: h("div", {}, h("p", { class: "recovery" }, h("code", { id: "shown-key", text: k.recovery_key }), " ", h("button", { class: "btn small", type: "button", "data-copy": "#shown-key", text: "Copy" })), h("p", { class: "muted", text: "Keep it somewhere safe and private. Anyone with this key and access to your Telegram accounts can read your files." })), okText: "Done" });
});
$("#btn-replace-key").addEventListener("click", async () => {
  const r = await dialog({ title: "Use a different recovery key", body: h("p", { class: "muted", text: "Possible only while this drive stores no files. Use it when you restored with the wrong key." }), fields: [{ name: "recovery_key", label: "Recovery key" }, { name: "password", label: "Your Telegram Drive password", type: "password" }], okText: "Replace key" });
  if (!r) return;
  if (await run(() => api("POST", "/api/vault/restore", r), "Recovery key replaced. You can rebuild from Telegram now.")) loadSettings();
});
$("#btn-backup").addEventListener("click", async () => { if (await run(() => api("POST", "/api/backup"), "Index backed up to Telegram")) loadSettings(); });
$("#btn-rebuild").addEventListener("click", async () => {
  const r = await dialog({ title: "Rebuild from Telegram", body: h("p", { text: "Reads the newest encrypted index backup and any newer files from the Saved Messages of your linked accounts. If this drive already has files, the restored ones go into a new \"Restored\" folder." }), okText: "Rebuild" });
  if (!r) return;
  toast("Rebuilding… reading Saved Messages");
  const s = await run(() => api("POST", "/api/rebuild"));
  if (s) toast(`Restored ${s.files} files and ${s.folders} folders, recovered ${s.recovered} newer files`);
});
async function loadShares() {
  const rows = await run(() => api("GET", "/api/shares"));
  if (!rows) return;
  $("#share-list").replaceChildren(...(rows.length ? rows.map((r) => h("li", {},
    h("span", {}, h("strong", { text: r.path }), h("span", { class: "muted", text: ` · expires ${fmtDate(new Date(r.expires * 1000).toISOString())}` })),
    h("button", { class: "btn small danger", type: "button", text: "Revoke", onclick: async () => {
      if (await run(() => api("DELETE", `/api/shares/${r.id}`), "Link revoked")) loadShares();
    } }))) : [h("li", { class: "muted", text: "No active share links." })]));
}
document.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-copy]");
  if (!btn) return;
  navigator.clipboard.writeText($(btn.dataset.copy).textContent).then(() => toast("Copied"), () => toast("Copy failed"));
});
async function loadAppPasswords() {
  const list = $("#app-pw-list");
  const rows = await run(() => api("GET", "/api/app-passwords"));
  if (!rows) return;
  list.replaceChildren(...(rows.length ? rows.map((r) => h("li", {},
    h("span", {}, h("strong", { text: r.name }), h("span", { class: "muted", text: ` · created ${fmtDate(new Date(r.created * 1000).toISOString())}${r.last_used ? " · last used " + fmtDate(new Date(r.last_used * 1000).toISOString()) : ""}` })),
    h("button", { class: "btn small danger", type: "button", text: "Revoke", onclick: async () => {
      if (await run(() => api("DELETE", `/api/app-passwords/${r.id}`), "Revoked")) loadAppPasswords();
    } }))) : [h("li", { class: "muted", text: "No app passwords yet." })]));
}
$("#app-pw-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const r = await run(() => api("POST", "/api/app-passwords", { name: $("#app-pw-name").value }));
  if (!r) return;
  $("#app-pw-name").value = "";
  const box = $("#app-pw-new");
  box.replaceChildren(h("strong", { text: "New app password (shown once): " }), h("code", { id: "new-pw", text: r.password }), " ",
    h("button", { class: "btn small", type: "button", "data-copy": "#new-pw", text: "Copy" }));
  box.hidden = false;
  loadAppPasswords();
});
async function renderTotp() {
  const area = $("#totp-area");
  area.replaceChildren();
  if (state.status.totp_enabled) {
    area.append(h("p", { text: "Two-factor sign-in is on. You need your authenticator app code to sign in." }),
      h("button", { class: "btn danger", type: "button", text: "Turn off", onclick: async () => {
        const r = await dialog({ title: "Turn off two-factor sign-in", fields: [{ name: "password", label: "Password", type: "password" }], okText: "Turn off", danger: true });
        if (!r) return;
        if (await run(() => api("POST", "/api/totp/disable", { password: r.password }), "Two-factor sign-in turned off")) { state.status.totp_enabled = false; renderTotp(); }
      } }));
    return;
  }
  area.append(h("p", { class: "muted", text: "Recommended if the server is reachable from the internet. Works with Google Authenticator, Microsoft Authenticator, Aegis, 1Password and others." }),
    h("button", { class: "btn", type: "button", text: "Set up two-factor sign-in", onclick: async () => {
      const s = await run(() => api("POST", "/api/totp/setup"));
      if (!s) return;
      const qr = h("div", { class: "qr" });
      qr.innerHTML = s.qr_svg;
      const body = h("div", {}, h("p", { text: "Scan this code with your authenticator app, then enter the 6-digit code it shows." }), qr,
        h("p", { class: "muted" }, "Or enter this key manually: ", h("code", { text: s.secret })));
      const r = await dialog({ title: "Set up two-factor sign-in", body, fields: [{ name: "code", label: "6-digit code" }], okText: "Turn on" });
      if (!r) return;
      if (await run(() => api("POST", "/api/totp/enable", { secret: s.secret, code: r.code }), "Two-factor sign-in is on")) { state.status.totp_enabled = true; renderTotp(); }
    } }));
}
$("#pw-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const ok = await run(() => api("POST", "/api/password", { current: $("#pw-current").value, new: $("#pw-new").value }), "Password changed; other devices were signed out");
  if (ok) { $("#pw-current").value = ""; $("#pw-new").value = ""; }
});

// ---------- start ----------
async function boot() {
  state.status = await api("GET", "/api/status");
  if (!state.status.logged_in) return showAuth();
  $("#auth").hidden = true;
  $("#app").hidden = false;
  $("#demo-banner").hidden = !state.status.demo;
  route();
}
boot().catch((e) => { document.body.textContent = "Cannot reach the server: " + e.message; });
if ("serviceWorker" in navigator) navigator.serviceWorker.register("/sw.js").catch(() => {});
