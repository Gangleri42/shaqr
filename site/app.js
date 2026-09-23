// The shaQR pitch page: split as you type, recover from any k plates.
//
// This is an ES module. It imports the shaQR module from js/, a link to the
// repository's js/ directory. The module hashes with WebCrypto, and browsers
// offer WebCrypto only to secure contexts: the page has to come over HTTPS or
// from localhost (python3 -m http.server), and modules do not load from
// file:// URLs.
//
// qrcode.js, jsQR.js, zxing/reader.js and mono-glyphs.js are classic scripts
// loaded before this one; they define the globals QRCode, jsQR, ZXingWASM and
// MONO_GLYPHS.

import {
  split,
  combine,
  audit,
  group,
  shareAt,
  parseHeader,
  encode,
  decode,
  ShaqrError,
  TypeBytes,
  TypeText,
  TypeDescriptor,
} from "./js/shaqr.js";
import { DescriptorError, canonical, pack, quorum, unpack } from "./js/descriptor.js";
import { buildCardSvg, fileName as cardFileName, keyLabel } from "./cards.js";
import { EXAMPLES } from "./examples.js";

const MAX_N = 255;

// A Shamir share of the payload for comparison carries the same 9 bytes of
// type, terminator, header and check as a shaQR share (SPEC.md, Sizes).
const SHAMIR_EXTRA = 9;

const $ = (sel) => document.querySelector(sel);

const inputEl = $("#desc-input");
const kEl = $("#k");
const nEl = $("#n");
const encryptEl = $("#encrypt");
const splitStatus = $("#split-status");
const splitNote = $("#split-note");
const splitActions = $("#split-actions");
const partsGrid = $("#parts-grid");
const pasteBox = $("#paste-box");
const pasteEl = $("#paste-input");
const pasteTries = $("#paste-tries");
const pasteReport = $("#paste-report");
const recGrid = $("#rec-grid");
const recStatus = $("#rec-status");
const recMeter = $("#rec-meter");
const recResults = $("#rec-results");
const dlgCam = $("#dlg-cam");
const camVideo = $("#cam-video");
const camView = $(".cam-view");
const camFrame = $("#cam-frame");
const camProgress = $(".cam-progress");
const camSteps = $("#cam-steps");
const btnZoom = $("#btn-zoom");
const btnTorch = $("#btn-torch");
const dlgZoom = $("#dlg-zoom");
const zoomCanvas = $("#zoom-canvas");
const zoomLabel = $("#zoom-label");
const zoomText = $("#zoom-text");
const toastEl = $("#toast");

const utf8 = new TextEncoder();
const secure = window.isSecureContext && !!(globalThis.crypto && crypto.subtle);

// current is the split on show in tab 1: the payload, how it was split and
// the shares, or null.
let current = null;
let wanted = { k: 2, n: 3 };
let splitGen = 0;
let lastText = "";

// rec holds what tab 2 works on. Every entry is one share: a plate mirrored
// from the current split, a code the camera read, or a share in the text box.
const rec = { signature: null, entries: [] };
let recGen = 0;
let recOutcome = null;
let pasteRejected = 0;

let camStream = null;
let camTrack = null;
let camDetector = null;
let camCanvas = null;
let camCtx = null;
let camTimer = 0;
let camCloseTimer = 0;
let camMode = "parts";
let torchOn = false;
let roiMisses = 0;
let zoom = 2;
let zxingReady = false;
let lastBadScan = "";

const ZOOM_LEVELS = [1, 2, 3];
const ROI_SCAN = 800;
const FULL_SCAN = 1280;
const ROI_JSQR = [400, 800];
const FULL_JSQR = [640, 1280];
const ROI_FALLBACK_AFTER = 10;
let zoomCopy = "";
let toastTimer = 0;

const hasZXing = typeof ZXingWASM !== "undefined" && typeof ZXingWASM.readBarcodes === "function";
const camSupported = "BarcodeDetector" in window || hasZXing || typeof jsQR === "function";

function initZXing() {
  if (!hasZXing || zxingReady) return;
  zxingReady = true;
  try {
    ZXingWASM.prepareZXingModule({
      overrides: {
        locateFile: (path) => (path.endsWith(".wasm") ? "vendor/zxing/zxing_reader.wasm" : path),
      },
    });
  } catch {}
}

async function zxingDecode(imageData) {
  if (!hasZXing) return null;
  try {
    const results = await ZXingWASM.readBarcodes(imageData, {
      formats: ["QRCode"],
      maxNumberOfSymbols: 1,
      textMode: "Plain",
      tryHarder: true,
      tryInvert: true,
      tryRotate: true,
      tryDownscale: true,
    });
    return results && results.length ? results[0].text : null;
  } catch {
    return null;
  }
}

const tabButtons = {
  split: $("#tabbtn-split"),
  recover: $("#tabbtn-recover"),
  about: $("#tabbtn-about"),
};

const panels = {
  split: $("#tab-split"),
  recover: $("#tab-recover"),
  about: $("#tab-about"),
};

function switchTab(name) {
  for (const key of Object.keys(panels)) {
    const on = key === name;
    tabButtons[key].setAttribute("aria-selected", String(on));
    panels[key].hidden = !on;
  }
  if (name === "recover") syncRecover();
  else camStop();
}

// Bytes, text and QR codes.

function sameBytes(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

const hex = (bytes) => Array.from(bytes, (v) => v.toString(16).padStart(2, "0")).join("");

// Share text is upper-case base32 after "SHAQR:", so every character is in
// the QR alphanumeric set. One alphanumeric segment is what SPEC.md sizes.
const qrSegments = (text) => [{ data: text, mode: "alphanumeric" }];

function qrFor(text) {
  return QRCode.create(qrSegments(text), { errorCorrectionLevel: "L" });
}

function qrVersion(text) {
  try {
    return qrFor(text).version;
  } catch {
    return null;
  }
}

function drawQR(canvas, text, width) {
  QRCode.toCanvas(canvas, qrSegments(text), { errorCorrectionLevel: "L", width }, () => {
    canvas.style.width = "";
    canvas.style.height = "";
  });
}

function plateLabel({ tag, x, n, k, open }) {
  return `${tag} · plate ${x}${n ? ` of ${n}` : ""} · any ${k} · ${open ? "open" : "encrypted"}`;
}

// plateCard builds one card: the QR code of a share and its labels.
function plateCard({ text, num, pill, pillClass, sub, key, source, onClick }) {
  const card = document.createElement("button");
  card.type = "button";
  card.className = "part";
  card.setAttribute("aria-pressed", "true");

  const canvas = document.createElement("canvas");
  const meta = document.createElement("span");
  meta.className = "meta";
  const numEl = document.createElement("span");
  numEl.className = "num";
  const numText = document.createElement("span");
  numText.textContent = num;
  numEl.append(numText);
  if (source) {
    const src = document.createElement("span");
    src.className = "src";
    src.textContent = source;
    numEl.append(src);
  }
  const pillEl = document.createElement("span");
  pillEl.className = `tag ${pillClass}`;
  pillEl.textContent = pill;
  meta.append(numEl, pillEl);

  const subEl = document.createElement("span");
  subEl.className = "sub";
  subEl.textContent = sub;
  subEl.hidden = !sub;
  const whyEl = document.createElement("span");
  whyEl.className = "sub why";
  whyEl.hidden = true;
  const keyEl = document.createElement("span");
  keyEl.className = "sub key";
  keyEl.textContent = key ? `key ${key}` : "";
  keyEl.hidden = !key;

  card.append(canvas, meta, subEl, whyEl, keyEl);
  drawQR(canvas, text, 232);
  if (onClick) card.addEventListener("click", onClick);
  return { card, numText, pillEl, subEl, whyEl, keyEl };
}

// Tab 1: split.

function clamp(v, lo, hi) {
  return Math.min(hi, Math.max(lo, Math.floor(Number(v)) || lo));
}

function setQuorumControls(k, n, locked) {
  kEl.value = String(k);
  nEl.value = String(n);
  for (const el of document.querySelectorAll(".ofn-n input, .ofn-n button")) el.disabled = locked;
  for (const el of document.querySelectorAll(".ofn-n")) {
    el.classList.toggle("locked", locked);
    el.title = locked ? "k and n come from the descriptor" : "";
  }
}

const descriptorCall = /^(sh|wsh|wpkh|pkh|pk|tr|rawtr|combo|multi|sortedmulti|multi_a|sortedmulti_a)\(/;

// multiCalls returns the arguments of every multi, sortedmulti, multi_a and
// sortedmulti_a call in a descriptor, split at the commas of that call.
function multiCalls(desc) {
  const calls = [];
  const re = /(?:sorted)?multi(?:_a)?\(/g;
  for (let m = re.exec(desc); m; m = re.exec(desc)) {
    const args = [];
    let depth = 0;
    let start = re.lastIndex;
    let i = start;
    for (; i < desc.length; i++) {
      const c = desc[i];
      if (c === "(" || c === "{") depth++;
      else if (c === ")" || c === "}") {
        if (depth === 0) break;
        depth--;
      } else if (c === "," && depth === 0) {
        args.push(desc.slice(start, i));
        start = i + 1;
      }
    }
    args.push(desc.slice(start, i));
    calls.push(args);
  }
  return calls;
}

// A key that a derived set can rest on: an extended key, which may have
// children, or a hex public key (compressed, x-only or uncompressed), each
// with an optional [origin]. A derived set is safe only when nobody can
// guess the keys (DESCRIPTOR.md), so placeholders such as "a" do not count.
const base58 = "[1-9A-HJ-NP-Za-km-z]";
const realKey = new RegExp(
  `^(\\[[^\\]]*\\])?([xt](pub|prv)${base58}{107}(/.*)?|0[23][0-9a-fA-F]{64}|04[0-9a-fA-F]{128}|[0-9a-fA-F]{64})$`
);

// planFor decides how to split text (DESCRIPTOR.md): a descriptor that has
// one multi holding every key, and every key an extended key or a hex
// public key, is packed in canonical form as type D, with k and n from the
// descriptor, for a derived set, or an open set when Encrypt is off.
// Anything else is text, type U, with the k and n the user picked, for a
// session set or an open set. For a descriptor with no such multi this
// departs from DESCRIPTOR.md, which has the user give k and n and still
// packs it.
function planFor(text) {
  const bare = text.replace(/\s+/g, "");
  let desc = null;
  let descErr = null;
  try {
    desc = canonical(text);
  } catch (err) {
    descErr = err;
  }
  const q = quorum(desc || text);

  if (!desc && q && descErr && descErr.code === "checksum") {
    throw new Error("The descriptor checksum does not match. Check the text after the #.");
  }
  if (desc && !q) {
    const multis = multiCalls(desc.replace(/#.*$/, ""));
    if (multis.length === 1) {
      const [threshold, ...keys] = multis[0];
      const t = Number(threshold);
      if (/^[0-9]+$/.test(threshold) && (t < 1 || t > keys.length)) {
        return { stop: `The threshold ${t} is not between 1 and the number of keys, ${keys.length}.` };
      }
    }
  }
  const keysReal = !!q && q.keys.every((key) => realKey.test(key));
  if (desc && q && keysReal) {
    const n = q.keys.length;
    if (q.k < 2) return { stop: `A 1-of-${n} descriptor makes no set: put the plain descriptor on every plate.` };
    if (n > MAX_N) return { stop: `${n} keys: a set has at most ${MAX_N} plates.` };
    return {
      kind: "descriptor",
      text: desc,
      type: TypeDescriptor,
      derived: true,
      k: q.k,
      n,
      keys: q.keys.map(keyLabel),
      changed: desc !== bare,
    };
  }
  return {
    kind: "text",
    text,
    type: TypeText,
    derived: false,
    k: wanted.k,
    n: wanted.n,
    keys: null,
    looksLikeDescriptor: !!desc && descriptorCall.test(bare),
    oneMulti: !!q,
  };
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// base58Check decodes s, a string of base58 characters, as base58check,
// whose last four bytes are the first four of a double SHA-256 of the
// others, and returns the others, or null when the check does not match.
async function base58Check(s) {
  let v = 0n;
  for (const c of s) v = v * 58n + BigInt(base58Alphabet.indexOf(c));
  const bytes = [];
  for (; v > 0n; v >>= 8n) bytes.unshift(Number(v & 0xffn));
  // Every leading 1 stands for a zero byte.
  const zeros = s.length - s.replace(/^1+/, "").length;
  const raw = new Uint8Array([...Array(zeros).fill(0), ...bytes]);
  if (raw.length < 4) return null;
  const body = raw.subarray(0, raw.length - 4);
  const once = await crypto.subtle.digest("SHA-256", body);
  const twice = new Uint8Array(await crypto.subtle.digest("SHA-256", once));
  return sameBytes(twice.subarray(0, 4), raw.subarray(body.length)) ? body : null;
}

// holdsPrivateKey reports whether text holds a private key, which
// DESCRIPTOR.md never lets into an open set: an extended key whose key
// starts with a 00 byte, as that of an xprv or tprv does, or a WIF key,
// 0x80 or 0xEF and 32 bytes, with 01 after them when the key is
// compressed. descbackup looks at the keys of a descriptor; this looks at
// every run of base58 in any text, which finds the same keys and more.
async function holdsPrivateKey(text) {
  for (const run of text.match(new RegExp(`${base58}{50,112}`, "g")) || []) {
    const raw = await base58Check(run);
    if (!raw) continue;
    const wif = (raw.length === 33 || (raw.length === 34 && raw[33] === 0x01)) && (raw[0] === 0x80 || raw[0] === 0xef);
    if (wif || (raw.length === 78 && raw[45] === 0x00)) return true;
  }
  return false;
}

function clearSplit(message, cls = "status") {
  current = null;
  partsGrid.innerHTML = "";
  splitActions.hidden = true;
  splitNote.hidden = true;
  splitStatus.className = cls;
  splitStatus.textContent = message;
}

// shareSize gives the bytes, text characters and QR version of a share, or
// of any bytes written as one.
function shareSize(share) {
  const text = encode(share);
  return { bytes: share.length, chars: text.length, version: qrVersion(text) };
}

const qrName = (version) => (version ? `QR version ${version}` : "too long for one QR code");

// sizeLine is the status line of a split: the size of its shares, and for
// comparison that of a share of the descriptor as text, cut the same way,
// when plain is given, and of a full Shamir share of the payload.
function sizeLine(share, plain, payload) {
  const s = shareSize(share);
  const shamir = shareSize(new Uint8Array(payload.length + SHAMIR_EXTRA));
  const head = `${s.bytes} bytes per share, ${s.chars} characters, ${qrName(s.version)}.`;
  if (!plain) return `${head} A full Shamir share would be ${shamir.bytes} bytes, ${qrName(shamir.version)}.`;
  const p = shareSize(plain);
  return (
    `${head} Without packing a share would be ${p.bytes} bytes, ${qrName(p.version)}. ` +
    `A full Shamir share of the packed descriptor would be ${shamir.bytes} bytes, ${qrName(shamir.version)}.`
  );
}

// noteFor says what kind of set a split made, and why.
function noteFor(plan, payload, open) {
  if (plan.kind === "descriptor") {
    return (
      `Descriptor in canonical form, packed from ${plan.text.length} characters to ${payload.length} bytes, ` +
      (open
        ? "in an open set: the same wallet always gives the same plates, and each plate shows part of the descriptor in the clear. "
        : "in a derived set: the same wallet always gives the same plates. ") +
      "k and n come from the descriptor, and each plate names its key." +
      (plan.changed
        ? " Recovery gives back the canonical form, which can differ from your input in key order, hardened marks, children and checksum."
        : "")
    );
  }
  return (
    (!plan.looksLikeDescriptor
      ? ""
      : plan.oneMulti
        ? "Not every key here looks like an extended key or a hex public key. A derived set needs keys nobody can guess, so this page splits it as text with the k and n above. "
        : "This descriptor has no single multi that holds every key. DESCRIPTOR.md has you give k and n; this page splits it as text with the k and n above. ") +
    (open
      ? "Text, in an open set: there is no key, so the same text always gives the same plates, and each plate shows part of it in the clear."
      : "Text, in a session set: the key is random, so the plates are new each time.")
  );
}

async function runSplit() {
  const gen = ++splitGen;
  const text = inputEl.value.trim();
  const open = !encryptEl.checked;
  lastText = text;

  if (!text) {
    setQuorumControls(wanted.k, wanted.n, false);
    return clearSplit("Paste a descriptor or any other secret. It splits as you type.");
  }
  if (!secure) {
    return clearSplit(
      "This page needs HTTPS or localhost: browsers offer WebCrypto only to secure contexts.",
      "status err"
    );
  }

  let plan;
  try {
    plan = planFor(text);
  } catch (err) {
    setQuorumControls(wanted.k, wanted.n, false);
    return clearSplit(err.message, "status err");
  }
  if (plan.stop) {
    setQuorumControls(wanted.k, wanted.n, false);
    return clearSplit(plan.stop, "status warn");
  }
  setQuorumControls(plan.k, plan.n, plan.kind === "descriptor");

  let payload;
  let shares;
  let plain = null;
  try {
    if (open && (await holdsPrivateKey(text))) {
      if (gen === splitGen) {
        clearSplit("This holds a private key, and an open set would show it on the plates. Turn Encrypt on.", "status warn");
      }
      return;
    }
    const options = open ? { open } : { derived: plan.derived };
    payload = plan.kind === "descriptor" ? await pack(plan.text) : utf8.encode(plan.text);
    shares = await split(payload, plan.type, plan.k, plan.n, options);
    if (plan.kind === "descriptor") {
      [plain] = await split(utf8.encode(plan.text), TypeText, plan.k, plan.n, options);
    }
  } catch (err) {
    if (gen === splitGen) clearSplit(err.message, "status err");
    return;
  }
  if (gen !== splitGen) return;

  const texts = shares.map(encode);
  const head = await parseHeader(shares[0]);
  if (gen !== splitGen) return;

  const version = qrVersion(texts[0]);
  current = { ...plan, payload, open, shares, texts, tag: head.tag, id: hex(head.id), version };

  splitStatus.className = "status";
  splitStatus.textContent = sizeLine(shares[0], plain, payload);
  splitNote.textContent = noteFor(plan, payload, open);
  splitNote.hidden = false;

  partsGrid.innerHTML = "";
  if (!version) {
    current = null;
    splitActions.hidden = true;
    splitStatus.className = "status warn";
    splitStatus.textContent += " Raise k to make the shares shorter.";
    return;
  }
  splitActions.hidden = false;

  const frag = document.createDocumentFragment();
  texts.forEach((t, i) => {
    const plate = {
      text: t,
      tag: current.tag,
      x: i + 1,
      n: current.n,
      k: current.k,
      open,
      key: current.keys ? current.keys[i] : "",
    };
    const { card } = plateCard({
      text: t,
      num: String(i + 1).padStart(2, "0"),
      pill: open ? `${current.tag} open` : current.tag,
      pillClass: "set",
      sub: "",
      key: plate.key,
      onClick: () => openZoom(plate),
    });
    frag.append(card);
  });
  partsGrid.append(frag);
}

function openZoom(plate) {
  drawQR(zoomCanvas, plate.text, 440);
  zoomLabel.textContent = plateLabel(plate) + (plate.key ? ` · key ${plate.key}` : "");
  zoomText.textContent = plate.text;
  zoomCopy = plate.text;
  dlgZoom.showModal();
}

// Tab 2: recover.

// syncRecover mirrors the current split into tab 2, as unselected plates.
// Plates the camera read for an earlier split go with it; the text box is
// read again.
function syncRecover() {
  pasteTries.hidden = !current;
  const signature = current ? current.texts.join("|") : null;
  if (rec.signature === signature) return;
  rec.signature = signature;
  pasteBox.open = !current || pasteEl.value.trim() !== "";
  rec.entries = rec.entries.filter((e) => e.source === "paste");
  if (current) {
    const mirrored = current.shares.map((raw, i) => ({
      raw,
      text: current.texts[i],
      source: "split",
      checked: false,
      n: current.n,
      key: current.keys ? current.keys[i] : "",
    }));
    rec.entries = [...mirrored, ...rec.entries];
  }
  renderRec();
  updateRec();
}

let pasteTimer = 0;

// A line that starts with # is a label (SPEC.md, Text form).
const withoutLabels = (text) =>
  text
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("#"))
    .join("\n");

function readPaste() {
  const text = pasteEl.value;
  const { shares, rejected } = decode(text);
  const old = rec.entries.filter((e) => e.source === "paste");
  rec.entries = rec.entries.filter((e) => e.source !== "paste");
  for (const raw of shares) {
    // "SHAQR:" with nothing after it yet is a share still being typed.
    if (!raw.length) continue;
    const was = old.find((e) => sameBytes(e.raw, raw));
    rec.entries.push({ raw, text: encode(raw), source: "paste", checked: was ? was.checked : true });
  }
  pasteReport.innerHTML = "";
  for (const err of rejected) {
    const li = document.createElement("li");
    li.textContent = `Damaged: ${err.message.replace(/^shaqr: malformed text: /, "")}.`;
    pasteReport.append(li);
  }
  const rest = withoutLabels(text);
  if (rest.trim() && !/shaqr:/i.test(rest) && !rejected.length) {
    const li = document.createElement("li");
    li.textContent = "No share found. A share starts with SHAQR:.";
    pasteReport.append(li);
  }
  pasteReport.hidden = pasteReport.children.length === 0;
  pasteRejected = rejected.length;
  renderRec();
  updateRec();
}

function entryNum(e) {
  if (e.head) return String(e.head.x).padStart(2, "0");
  if (e.source === "split") return String(rec.entries.indexOf(e) + 1).padStart(2, "0");
  return "?";
}

const sourceName = { split: "", scan: "scanned", paste: "typed" };

function renderRec() {
  recGrid.innerHTML = "";
  const frag = document.createDocumentFragment();
  for (const e of rec.entries) {
    const view = plateCard({
      text: e.text,
      num: entryNum(e),
      pill: "…",
      pillClass: "data",
      sub: "",
      key: e.key,
      source: sourceName[e.source],
      onClick: () => {
        e.checked = !e.checked;
        paintEntry(e);
        updateRec();
      },
    });
    e.view = view;
    paintEntry(e);
    frag.append(view.card);
  }
  recGrid.append(frag);
}

const pills = {
  ok: ["ok", "ok"],
  damaged: ["damaged", "bad"],
  version: ["other version", "data"],
  malformed: ["malformed", "bad"],
  disputed: ["disputed", "bad"],
  wrong: ["wrong", "bad"],
  pending: ["…", "data"],
};

const reasons = {
  other: "another set",
  wrong: "off the set",
  disputed: "same plate number, different share",
  damaged: "check failed",
  version: "made by another version",
  malformed: "malformed share",
};

function paintEntry(e) {
  if (!e.view) return;
  const { card, numText, pillEl, subEl, whyEl, keyEl } = e.view;
  numText.textContent = entryNum(e);
  card.classList.toggle("off", !e.checked);
  card.setAttribute("aria-pressed", String(e.checked));

  const state = e.checked ? e.state || e.intrinsic || "pending" : e.intrinsic || "pending";
  card.dataset.state = e.checked ? state : "";
  if (state === "other") {
    pillEl.textContent = e.head.tag;
    pillEl.className = "tag warn";
  } else {
    const [text, cls] = pills[state];
    pillEl.textContent = text;
    pillEl.className = `tag ${cls}`;
  }

  const plate = e.source === "split" ? `plate ${rec.entries.indexOf(e) + 1}${e.n ? ` of ${e.n}` : ""}` : "";
  subEl.textContent = e.head ? plateLabel({ ...e.head, n: e.n }) : plate;
  subEl.hidden = !subEl.textContent;
  whyEl.textContent = reasons[state] || "";
  whyEl.hidden = !whyEl.textContent;
  keyEl.textContent = e.key ? `key ${e.key}` : "";
  keyEl.hidden = !e.key;
}

// readHeads verifies each share once, as a scanner would the moment it
// reads it (SPEC.md, Recovering, step 1).
async function readHeads() {
  for (const e of rec.entries) {
    if (e.intrinsic) continue;
    try {
      e.head = await parseHeader(e.raw);
      e.intrinsic = "ok";
    } catch (err) {
      if (!(err instanceof ShaqrError)) throw err;
      e.intrinsic = { check: "damaged", "other-version": "version", malformed: "malformed" }[err.code] || "damaged";
    }
  }
}

// readDescriptor unpacks the payload of a recovered type D set into
// s.text, or records in s.unpackError why it does not unpack, and names
// the key of each plate from the quorum of the text.
async function readDescriptor(s) {
  try {
    s.text = await unpack(s.result.payload);
  } catch (err) {
    if (!(err instanceof DescriptorError)) throw err;
    s.unpackError = err.code;
    return;
  }
  const q = quorum(s.text);
  if (q) for (const e of s.members) if (!e.key && q.keys[e.head.x - 1]) e.key = keyLabel(q.keys[e.head.x - 1]);
}

// assess works out the state of every selected share and recovers every set
// that holds k of them. It returns the outcome for the status line.
async function assess() {
  const selected = rec.entries.filter((e) => e.checked);
  for (const e of rec.entries) e.state = null;
  const readable = selected.filter((e) => e.head);
  const byRaw = new Map(readable.map((e) => [e.raw, e]));
  const { sets, rejected } = await group(readable.map((e) => e.raw));
  for (const r of rejected) if (r.error.code === "disputed") readable[r.index].state = "disputed";

  const infos = sets.map((raws) => {
    const members = raws.map((r) => byRaw.get(r));
    const [first] = members;
    const xs = new Set(members.filter((e) => e.state !== "disputed").map((e) => e.head.x));
    const disputedXs = new Set(members.filter((e) => e.state === "disputed").map((e) => e.head.x));
    return {
      raws,
      members,
      k: first.head.k,
      tag: first.head.tag,
      id: hex(first.head.id),
      open: first.head.open,
      have: xs.size,
      disputed: disputedXs.size,
      disputedXs,
      result: null,
      text: null,
      unpackError: null,
      error: null,
      wrong: [],
    };
  });

  // With a split on show its set is the one to recover. Another set takes
  // its place only when it has k plates; one stray plate of another wallet
  // stays another set.
  let primary = current ? infos.find((s) => s.id === current.id) : null;
  if (!primary) {
    const ready = infos.filter((s) => s.have >= s.k);
    const pool = current || ready.length ? ready : infos;
    primary = pool.reduce((best, s) => (!best || s.have > best.have ? s : best), null);
  }

  for (const s of infos) {
    if (s !== primary) for (const e of s.members) e.state = "other";
    if (s.have < s.k) continue;
    try {
      const { type, payload } = await combine(s.raws);
      s.result = { type, payload };
      if (s.members.length > s.k) {
        const bad = await audit(s.raws);
        for (const x of bad) {
          const truth = await shareAt(s.raws, x);
          for (const e of s.members) {
            if (e.head.x === x && !sameBytes(e.raw, truth)) e.state = "wrong";
          }
          s.wrong.push(x);
        }
      }
      for (const e of s.members) if (e.state === "disputed") e.state = "ok";
      if (type === TypeDescriptor) await readDescriptor(s);
    } catch (err) {
      if (!(err instanceof ShaqrError)) throw err;
      s.error = err;
    }
  }
  for (const e of selected) if (!e.state) e.state = e.intrinsic || "pending";

  const damaged = selected.filter((e) => e.intrinsic === "damaged").length;
  const version = selected.filter((e) => e.intrinsic === "version").length;
  const malformed = selected.filter((e) => e.intrinsic === "malformed").length;
  const others = infos.filter((s) => s !== primary);
  return { selected, infos, primary, others, damaged, version, malformed };
}

async function updateRec() {
  const gen = ++recGen;
  await readHeads();
  if (gen !== recGen) return;
  const out = await assess();
  if (gen !== recGen) return;
  recOutcome = out;

  for (const e of rec.entries) paintEntry(e);
  renderResults(out);
  renderRecStatus(out);
  updateCamProgress();
  maybeCloseCamera();
}

function plural(n, one, many) {
  return `${n} ${n === 1 ? one : many}`;
}

function renderRecStatus({ selected, infos, primary, others, damaged, version, malformed }) {
  // The headline says where the recovery stands; more lists what was left
  // out, on a quieter line of its own.
  const setStatus = (cls, msg, pct, ok, more = "") => {
    recStatus.className = cls;
    recStatus.replaceChildren(msg);
    if (more) {
      const s = document.createElement("span");
      s.className = "status-more";
      s.textContent = more;
      recStatus.append(" ", s);
    }
    recMeter.style.width = `${pct}%`;
    recMeter.classList.toggle("ok", !!ok);
    recMeter.classList.toggle("warn", cls === "status warn" && !!ok);
    recMeter.classList.toggle("bad", cls === "status err");
  };

  if (!rec.entries.length && pasteRejected) {
    return setStatus("status err", "No share in the text decodes.", 0);
  }
  if (!rec.entries.length) {
    return setStatus("status", "Split something in tab 1, scan plates with the camera, or type their text.", 0);
  }
  if (!selected.length) {
    const k = current ? `any ${current.k} of set ${current.tag}` : "any k of one set";
    return setStatus("status", `Select the plates you have: ${k} bring it back.`, 0);
  }

  const extra = [];
  if (damaged) extra.push(`${plural(damaged, "share fails its check", "shares fail their check")} and ${damaged === 1 ? "is" : "are"} left out.`);
  if (version) extra.push(`${plural(version, "share", "shares")} made by another version, left out.`);
  if (malformed) extra.push(`${plural(malformed, "malformed share", "malformed shares")}, left out.`);
  for (const s of others) {
    const count = plural(s.members.length, "plate", "plates");
    if (s.result) extra.push(`Set ${s.tag} recovered too, from ${plural(s.have, "plate", "plates")}.`);
    else if (primary && s.tag === primary.tag) extra.push(`${count} tagged ${s.tag} with another format, length or threshold, left out.`);
    else extra.push(`${count} of another set, ${s.tag}, left out.`);
  }
  const tail = extra.join(" ");

  if (!primary && current && infos.length) {
    return setStatus("status", `Select the plates of set ${current.tag}: any ${current.k} bring it back.`, 0, false, tail);
  }
  if (!primary) return setStatus("status err", "No selected share passes its check.", 0, false, tail);

  const pct = Math.min(100, Math.round((primary.have / primary.k) * 100));
  const xs = [...primary.disputedXs];
  const disputed = !xs.length
    ? ""
    : xs.length === 1
      ? `, not counting plate ${xs[0]}, which two different shares claim`
      : `, not counting plates ${xs.join(", ")}, each claimed by two different shares`;

  if (primary.result) {
    const wrong = primary.wrong
      .map((x) =>
        primary.disputedXs.has(x)
          ? ` Two different shares claim plate ${x}; the one marked wrong is off the set.`
          : ` Plate ${x} is wrong and should be replaced.`
      )
      .join("");
    return setStatus(
      primary.wrong.length ? "status warn" : "status ok",
      `Recovered set ${primary.tag} from ${plural(primary.have, "plate", "plates")}.${wrong}`,
      100,
      true,
      tail
    );
  }
  if (primary.error && primary.error.code === "id") {
    const spare = primary.have > primary.k ? "No k of them match the set id." : "They do not match the set id, so one of them is wrong. A spare plate would name it.";
    return setStatus("status err", `Set ${primary.tag}: ${plural(primary.have, "plate", "plates")}. ${spare}`, pct, false, tail);
  }
  if (primary.error) {
    return setStatus("status err", `Set ${primary.tag}: ${primary.error.message.replace(/^shaqr: /, "")}.`, pct, false, tail);
  }
  const need = primary.k - primary.have;
  return setStatus(
    "status warn",
    `Set ${primary.tag}: ${primary.have} of ${primary.k} plates${disputed}. ${need} more needed.`,
    pct,
    false,
    tail
  );
}

const typeNames = { [TypeDescriptor]: "descriptor", [TypeText]: "text", [TypeBytes]: "bytes" };

// resultNote describes a recovered set, and for a descriptor whether it
// unpacked and is in canonical form. It never quotes the payload.
function resultNote(s) {
  const { type, payload } = s.result;
  const kind = typeNames[type] || `content type 0x${type.toString(16).padStart(2, "0")}`;
  const head = `Set ${s.tag}, ${s.open ? "open" : "encrypted"}, ${kind}`;
  if (type !== TypeDescriptor) return { text: `${head}, ${payload.length} bytes.`, cls: "" };
  if (s.unpackError === "not-packed") {
    return { text: `${head}: its ${payload.length} bytes are not the packed form of a descriptor.`, cls: "bad" };
  }
  if (s.unpackError) return { text: `${head}: its ${payload.length} bytes do not unpack.`, cls: "bad" };
  const unpacked = `${head} packed in ${payload.length} bytes, unpacked to ${s.text.length} characters.`;
  if (isCanonical(s.text)) return { text: unpacked, cls: "" };
  return { text: `${unpacked} It is not in canonical form.`, cls: "warn" };
}

// isCanonical reports whether text is a descriptor in canonical form.
function isCanonical(text) {
  try {
    return canonical(text) === text;
  } catch {
    return false;
  }
}

function renderResults({ infos, primary }) {
  recResults.innerHTML = "";
  const done = infos.filter((s) => s.result).sort((a, b) => (a === primary ? -1 : b === primary ? 1 : 0));
  for (const s of done) {
    const { type, payload } = s.result;
    const body = s.text || (type === TypeText ? new TextDecoder().decode(payload) : hex(payload));

    const card = document.createElement("div");
    card.className = "card result";
    const match = document.createElement("p");
    match.className = "match";
    const same = current && current.id === s.id && current.type === type && sameBytes(current.payload, payload);
    match.textContent = same ? "✓ matches the original" : `✓ recovered set ${s.tag}`;

    const { text, cls } = resultNote(s);
    const note = document.createElement("p");
    note.className = `note result-note ${cls}`;
    note.textContent = text;

    const pre = document.createElement("pre");
    pre.textContent = body;
    const copy = document.createElement("button");
    copy.className = "btn";
    copy.textContent = s.text ? "Copy descriptor" : type === TypeText ? "Copy text" : "Copy hex";
    copy.addEventListener("click", () => copyText(body));
    card.append(match, note, pre, copy);
    recResults.append(card);
  }
}

// Bad plates for the demo, made from the current split.

async function withCheck(share) {
  const label = utf8.encode("shaQR v1 check");
  const n = share.length - 4;
  const msg = new Uint8Array(label.length + n);
  msg.set(label);
  msg.set(share.subarray(0, n), label.length);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", msg));
  share.set(digest.subarray(0, 4), n);
  return share;
}

// randomBytes fills n bytes from the system source, which gives at most
// 65536 at a time.
function randomBytes(n) {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 65536) crypto.getRandomValues(out.subarray(i, Math.min(n, i + 65536)));
  return out;
}

// handTyped writes share text the way someone copies it from steel: lower
// case, in groups of four, over several lines.
function handTyped(text) {
  const prefix = "shaqr:";
  const groups = text.slice(prefix.length).toLowerCase().match(/.{1,4}/g);
  const lines = [];
  for (let i = 0; i < groups.length; i += 8) lines.push(groups.slice(i, i + 8).join(" "));
  return `${prefix}\n${lines.join("\n")}`;
}

async function tryBadPlate(kind) {
  if (!current) return;
  let block;
  if (kind === "typo") {
    const text = current.texts[0];
    const at = 40;
    const swap = text[at] === "Q" ? "R" : "Q";
    block = `# plate 1 of set ${current.tag}, typed by hand with one letter wrong\n${handTyped(text.slice(0, at) + swap + text.slice(at + 1))}`;
  } else if (kind === "other") {
    const other = await split(randomBytes(current.payload.length), TypeBytes, current.k, current.n, { open: current.open });
    block = `# a plate of another wallet\n${encode(other[0])}`;
  } else {
    const x = Math.min(2, current.n);
    const forged = new Uint8Array(current.shares[x - 1]);
    // The first byte of the data part, which every share has, after the
    // header and, in an encrypted set, the key part.
    forged[current.open ? 19 : 19 + 32] ^= 0x01;
    await withCheck(forged);
    block = `# plate ${x}, rewritten by someone who saw the secret, with a valid check\n${encode(forged)}`;
  }
  pasteEl.value = (pasteEl.value.trim() ? `${pasteEl.value.trim()}\n` : "") + block + "\n";
  pasteBox.open = true;
  readPaste();
}

// Camera.

// The camera's progress bar has one segment for each of the k plates the
// main set needs, whatever the number of plates on show.
function updateCamProgress() {
  if (camMode !== "parts" || !dlgCam.open) {
    camProgress.hidden = true;
    return;
  }
  const primary = recOutcome && recOutcome.primary;
  const segs = primary ? primary.k : current ? current.k : 0;
  const fill = primary ? Math.min(primary.k, primary.have) : 0;
  if (!segs) {
    camProgress.hidden = true;
    return;
  }
  if (camSteps.children.length !== segs) {
    camSteps.replaceChildren(...Array.from({ length: segs }, () => document.createElement("i")));
    camSteps.style.gap = segs > 120 ? "0px" : segs > 60 ? "1px" : "2px";
  }
  [...camSteps.children].forEach((s, i) => {
    s.className = i < fill ? "on" : "";
  });
  camProgress.classList.toggle("ok", !!(primary && primary.result));
  camProgress.hidden = false;
}

// maybeCloseCamera closes the camera once the main set is recovered, from
// k plates, however many more there are.
function maybeCloseCamera() {
  if (camMode !== "parts" || !dlgCam.open || !recOutcome) return;
  const primary = recOutcome.primary;
  if (!primary || !primary.result || camCloseTimer) return;
  const msg = `Set ${primary.tag} recovered.`;
  camCloseTimer = setTimeout(() => {
    camCloseTimer = 0;
    camStop();
    toast(msg);
  }, 700);
}

async function camStart(mode) {
  if (!camSupported) {
    toast("QR scanning is not available in this browser.");
    return;
  }
  if (!window.isSecureContext) {
    toast("Camera needs HTTPS or localhost.");
    return;
  }

  camMode = mode;

  try {
    camStream = await navigator.mediaDevices.getUserMedia({
      video: {
        facingMode: "environment",
        width: { ideal: 1920 },
        height: { ideal: 1080 },
      },
    });
  } catch (err) {
    toast(`Camera unavailable: ${err.message}`);
    return;
  }

  camVideo.srcObject = camStream;
  try {
    await camVideo.play();
  } catch {}

  camTrack = camStream.getVideoTracks()[0] || null;
  if (camTrack) {
    try {
      await camTrack.applyConstraints({ advanced: [{ focusMode: "continuous" }] });
    } catch {}
    try {
      const caps = camTrack.getCapabilities ? camTrack.getCapabilities() : null;
      btnTorch.hidden = !(caps && caps.torch);
    } catch {
      btnTorch.hidden = true;
    }
  }

  torchOn = false;
  roiMisses = 0;
  lastBadScan = "";
  btnTorch.setAttribute("aria-pressed", "false");

  initZXing();
  dlgCam.showModal();
  applyZoom();
  sizeCamFrame();
  updateCamProgress();
  camDetector = "BarcodeDetector" in window ? new window.BarcodeDetector({ formats: ["qr_code"] }) : null;
  camLoop();
}

function sizeCamFrame() {
  const w = camVideo.videoWidth;
  const h = camVideo.videoHeight;
  if (!w || !h) return;
  camView.style.aspectRatio = `${w} / ${h}`;
  camFrame.style.height = `${(Math.min(w, h) / h) * 100}%`;
}

function applyZoom() {
  camVideo.style.transform = `scale(${zoom})`;
  btnZoom.textContent = `${zoom}×`;
  sizeCamFrame();
}

function cycleZoom() {
  zoom = ZOOM_LEVELS[(ZOOM_LEVELS.indexOf(zoom) + 1) % ZOOM_LEVELS.length];
  applyZoom();
}

async function toggleTorch() {
  if (!camTrack) return;
  torchOn = !torchOn;
  try {
    await camTrack.applyConstraints({ advanced: [{ torch: torchOn }] });
    btnTorch.setAttribute("aria-pressed", String(torchOn));
  } catch {
    torchOn = false;
    toast("Torch not available on this camera.");
  }
}

function drawScanRegion(full) {
  if (!camCanvas) {
    camCanvas = document.createElement("canvas");
    camCtx = camCanvas.getContext("2d", { willReadFrequently: true });
  }

  const w = camVideo.videoWidth;
  const h = camVideo.videoHeight;
  if (!w || !h) return false;

  camCtx.imageSmoothingEnabled = full;
  if (full) {
    const scale = Math.min(1, FULL_SCAN / Math.max(w, h));
    camCanvas.width = Math.round(w * scale);
    camCanvas.height = Math.round(h * scale);
    camCtx.drawImage(camVideo, 0, 0, camCanvas.width, camCanvas.height);
  } else {
    const side = Math.round(Math.min(w, h) / zoom);
    camCanvas.width = ROI_SCAN;
    camCanvas.height = ROI_SCAN;
    camCtx.drawImage(camVideo, (w - side) / 2, (h - side) / 2, side, side, 0, 0, ROI_SCAN, ROI_SCAN);
  }
  return true;
}

function stretchContrast(im) {
  const q = im.data;
  const hist = new Uint32Array(256);
  for (let i = 0; i < q.length; i += 4) {
    hist[(q[i] * 77 + q[i + 1] * 150 + q[i + 2] * 29) >> 8]++;
  }
  const cut = (q.length / 4) * 0.02;
  let lo = 0;
  let acc = 0;
  for (; lo < 255; lo++) {
    acc += hist[lo];
    if (acc >= cut) break;
  }
  let hi = 255;
  acc = 0;
  for (; hi > 0; hi--) {
    acc += hist[hi];
    if (acc >= cut) break;
  }
  if (hi - lo < 8) return im;

  const scale = 255 / (hi - lo);
  for (let i = 0; i < q.length; i += 4) {
    let v = ((q[i] * 77 + q[i + 1] * 150 + q[i + 2] * 29) >> 8) - lo;
    v = v < 0 ? 0 : v > 255 ? 255 : (v * scale) | 0;
    q[i] = q[i + 1] = q[i + 2] = v;
  }
  return im;
}

function decodeCanvas(sizes) {
  const srcW = camCanvas.width;
  const srcH = camCanvas.height;
  const maxDim = Math.max(srcW, srcH);
  for (const size of sizes) {
    const scale = size / maxDim;
    const cw = Math.max(1, Math.round(srcW * scale));
    const ch = Math.max(1, Math.round(srcH * scale));
    const scratch = document.createElement("canvas");
    scratch.width = cw;
    scratch.height = ch;
    const sx = scratch.getContext("2d", { willReadFrequently: true });
    sx.imageSmoothingEnabled = true;
    sx.drawImage(camCanvas, 0, 0, cw, ch);
    const im = stretchContrast(sx.getImageData(0, 0, cw, ch));
    const code = jsQR(im.data, cw, ch, { inversionAttempts: "attemptBoth" });
    if (code) return code.data;
  }
  return null;
}

async function camLoop() {
  if (!camStream) return;
  try {
    const full = roiMisses >= ROI_FALLBACK_AFTER;
    let value = null;

    if (drawScanRegion(full)) {
      if (camDetector) {
        try {
          const codes = await camDetector.detect(camCanvas);
          if (codes.length) value = codes[0].rawValue;
        } catch {}
      }
      if (value == null) {
        value = await zxingDecode(camCtx.getImageData(0, 0, camCanvas.width, camCanvas.height));
      }
      if (value == null) value = decodeCanvas(full ? FULL_JSQR : ROI_JSQR);
    }

    if (value) {
      roiMisses = 0;
      await handleScan(value);
    } else if (full) {
      roiMisses = 0;
    } else {
      roiMisses++;
    }
  } catch {}
  if (camStream) camTimer = setTimeout(camLoop, 150);
}

function camStop() {
  clearTimeout(camTimer);
  clearTimeout(camCloseTimer);
  camCloseTimer = 0;
  if (camStream) {
    camStream.getTracks().forEach((t) => t.stop());
    camStream = null;
  }
  camTrack = null;
  camDetector = null;
  torchOn = false;
  roiMisses = 0;
  btnTorch.hidden = true;
  btnTorch.setAttribute("aria-pressed", "false");
  camVideo.srcObject = null;
  if (dlgCam.open) dlgCam.close();
}

// handleScan takes the text of one QR code. A shaQR share is one code, so
// there is no series to follow: each code is decoded and checked on its own.
async function handleScan(value) {
  const text = (value || "").trim();
  if (!text) return;

  if (camMode === "single") {
    camStop();
    if (/shaqr:/i.test(text)) {
      switchTab("recover");
      await addScanned(text);
      return;
    }
    switchTab("split");
    inputEl.value = text;
    runSplit();
    return;
  }
  await addScanned(text);
}

async function addScanned(text) {
  const { shares } = decode(text);
  if (!shares.length) {
    if (text !== lastBadScan) {
      lastBadScan = text;
      toast(/shaqr:/i.test(text) ? "That code does not decode as a share." : "That is not a shaQR code.");
    }
    return;
  }

  let fresh = null;
  for (const raw of shares) {
    if (!raw.length) continue;
    const same = rec.entries.find((e) => sameBytes(e.raw, raw));
    if (same) {
      if (same.checked) continue;
      same.checked = true;
      fresh = same;
      continue;
    }
    fresh = { raw, text: encode(raw), source: "scan", checked: true };
    rec.entries.push(fresh);
  }
  if (!fresh) return;

  renderRec();
  await updateRec();
  if (fresh.view) {
    fresh.view.card.classList.add("flash");
    setTimeout(() => fresh.view && fresh.view.card.classList.remove("flash"), 650);
  }
  if (fresh.head) toast(`Plate ${fresh.head.x} of set ${fresh.head.tag} scanned.`);
  else if (fresh.intrinsic === "damaged") toast("That plate is damaged: its check fails.");
  else if (fresh.intrinsic === "version") toast("That share was made by another version.");
  else toast("That share is malformed.");
}

// Downloads.

function download(name, blob) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

const setName = () => `shaqr-${current.k}of${current.n}-${current.tag.slice(1)}`;

function downloadPng() {
  if (!current) return;
  const scale = 4;
  const quiet = 4;
  const codes = current.texts.map((t) => qrFor(t).modules);
  const side = (codes[0].size + 2 * quiet) * scale;
  const labelH = current.keys ? 44 : 26;
  const cols = Math.min(current.n, Math.max(3, Math.ceil(Math.sqrt(current.n))));
  const rows = Math.ceil(current.n / cols);
  const gap = 24;

  const canvas = document.createElement("canvas");
  canvas.width = cols * side + (cols + 1) * gap;
  canvas.height = rows * (side + labelH) + (rows + 1) * gap;
  const ctx = canvas.getContext("2d");
  ctx.fillStyle = "#fff";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.textAlign = "center";
  ctx.textBaseline = "top";

  codes.forEach((m, i) => {
    const x0 = gap + (i % cols) * (side + gap);
    const y0 = gap + Math.floor(i / cols) * (side + labelH + gap);
    ctx.fillStyle = "#000";
    for (let r = 0; r < m.size; r++) {
      for (let c = 0; c < m.size; c++) {
        if (m.data[r * m.size + c]) ctx.fillRect(x0 + (c + quiet) * scale, y0 + (r + quiet) * scale, scale, scale);
      }
    }
    const cx = x0 + side / 2;
    ctx.font = "600 15px system-ui, sans-serif";
    ctx.fillText(plateLabel({ ...current, x: i + 1 }), cx, y0 + side);
    if (current.keys) {
      ctx.font = "14px ui-monospace, monospace";
      ctx.fillStyle = "#555";
      ctx.fillText(`key ${current.keys[i]}`, cx, y0 + side + 20);
    }
  });
  canvas.toBlob((blob) => download(`${setName()}.png`, blob), "image/png");
}

function downloadCards() {
  if (!current) return;
  let files;
  try {
    files = current.texts.map((text, i) => {
      const matrix = qrFor(text).modules;
      const card = {
        text,
        matrix: { size: matrix.size, data: matrix.data },
        x: i + 1,
        n: current.n,
        k: current.k,
        tag: current.tag,
        open: current.open,
        key: current.keys ? current.keys[i] : "",
        kind: current.kind,
      };
      return { name: cardFileName(card), svg: buildCardSvg(card, MONO_GLYPHS) };
    });
  } catch {
    toast("These shares are too long for an 85 x 55 mm card.");
    return;
  }
  files.forEach(({ name, svg }, i) => {
    setTimeout(() => download(name, new Blob([svg], { type: "image/svg+xml" })), i * 300);
  });
  toast(`Downloading ${current.n} card SVGs.`);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast("Copied.");
  } catch {
    toast("Copy failed.");
  }
}

function toast(msg) {
  toastEl.textContent = msg;
  toastEl.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toastEl.classList.remove("show"), 2200);
}

// Wiring.

function readQuorum(changed) {
  let k = clamp(kEl.value, 2, MAX_N);
  let n = clamp(nEl.value, 2, MAX_N);
  if (n < k) {
    if (changed === "n") k = n;
    else n = k;
  }
  wanted = { k, n };
  kEl.value = String(k);
  nEl.value = String(n);
}

let debounce;
inputEl.addEventListener("input", () => {
  clearTimeout(debounce);
  debounce = setTimeout(() => {
    if (inputEl.value.trim() !== lastText) runSplit();
  }, 300);
});

kEl.addEventListener("change", () => {
  readQuorum("k");
  runSplit();
});
nEl.addEventListener("change", () => {
  readQuorum("n");
  runSplit();
});

// paintMode highlights the line beside the Encrypt switch that describes
// its state.
function paintMode() {
  for (const el of document.querySelectorAll("[data-mode]")) {
    el.classList.toggle("on", (el.dataset.mode === "on") === encryptEl.checked);
  }
}

encryptEl.addEventListener("change", () => {
  paintMode();
  runSplit();
});

document.querySelectorAll(".ofn-n button").forEach((btn) =>
  btn.addEventListener("click", () => {
    const el = btn.dataset.for === "k" ? kEl : nEl;
    el.value = String(clamp(Number(el.value) + Number(btn.dataset.step), 2, MAX_N));
    readQuorum(btn.dataset.for);
    runSplit();
  })
);

document.querySelectorAll("[data-example]").forEach((btn) =>
  btn.addEventListener("click", () => {
    inputEl.value = EXAMPLES[btn.dataset.example];
    runSplit();
  })
);

document.querySelectorAll("[data-try]").forEach((btn) => btn.addEventListener("click", () => tryBadPlate(btn.dataset.try)));

$("#btn-clear").addEventListener("click", () => {
  inputEl.value = "";
  runSplit();
  inputEl.focus();
});

pasteEl.addEventListener("input", () => {
  clearTimeout(pasteTimer);
  pasteTimer = setTimeout(readPaste, 250);
});

$("#btn-scan-single").addEventListener("click", () => camStart("single"));
$("#btn-cam").addEventListener("click", () => camStart("parts"));
$("#btn-cam-stop").addEventListener("click", camStop);
$("#btn-zoom").addEventListener("click", cycleZoom);
$("#btn-torch").addEventListener("click", toggleTorch);
camVideo.addEventListener("loadedmetadata", sizeCamFrame);
dlgCam.addEventListener("close", camStop);

$("#btn-all").addEventListener("click", () => {
  rec.entries.forEach((e) => (e.checked = true));
  rec.entries.forEach(paintEntry);
  updateRec();
});
$("#btn-none").addEventListener("click", () => {
  rec.entries.forEach((e) => (e.checked = false));
  rec.entries.forEach(paintEntry);
  updateRec();
});
$("#btn-zoom-copy").addEventListener("click", () => copyText(zoomCopy));
$("#btn-zoom-close").addEventListener("click", () => dlgZoom.close());
$("#btn-dl").addEventListener("click", downloadPng);
$("#btn-dl-svg").addEventListener("click", downloadCards);

for (const key of Object.keys(tabButtons)) {
  tabButtons[key].addEventListener("click", () => switchTab(key));
}

paintMode();
runSplit();
