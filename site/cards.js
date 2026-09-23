// 85 x 55 mm plate cards for shaQR shares, as SVG. Text is drawn from the
// glyph outlines in vendor/mono-glyphs.js, so a laser or an engraver never
// has to resolve a font.
//
// A card is { text, matrix: { size, data }, x, n, k, tag, open, key,
// kind }: the share text, its QR matrix, the plate index x and the set's n
// and k, the set tag ("#7B63"), whether the set is open, the key the plate
// belongs to for a descriptor (keyLabel below, or "") and kind,
// "descriptor" or "text".
//
// Every label line on a card starts with "#". A share runs on across
// white space when it is typed back, and SPEC.md asks that a label next
// to it start with a character outside base32 so that the two stay apart.

import { fingerprint } from "./js/descriptor.js";

// keyLabel names the key a descriptor plate belongs to, as descbackup
// does: "[28645006]", its origin fingerprint, or "...Xy12AbCd", the last 8
// characters of the key without its origin and children, when it has no
// origin. Sibling xpubs share their first characters and differ at the end.
export function keyLabel(key) {
  const fp = fingerprint(key);
  if (fp) return `[${fp}]`;
  const bare = key.replace(/^\[[^\]]*\]/, "").split("/")[0];
  return bare.length > 8 ? `...${bare.slice(-8)}` : bare;
}

const CARD_W = 85;
const CARD_H = 55;
const MARGIN = 3;
const QUIET = 4;
const MODULE_MAX = 0.6;
const HEAD_MM = 2.8;
const FOOT_MM = 2.3;
const BODY_MAX = 2.8;
const BODY_MIN = 1.4;
const LINE_H = 1.16;
const QR_GAP = 1.5;
const STROKE_MM = 0.1;

function textGroup(glyphs, str, x, baseline, mm, mode, color) {
  const k = mm / glyphs.unitsPerEm;
  const attrs =
    mode === "solid"
      ? `fill="${color || "#000"}" fill-rule="evenodd" stroke="none"`
      : `fill="none" fill-rule="evenodd" stroke="${color || "#000"}" stroke-width="${STROKE_MM / k}" stroke-linecap="round" stroke-linejoin="round"`;
  let pen = 0;
  const parts = [`<g transform="translate(${x} ${baseline}) scale(${k} -${k})" ${attrs}>`];
  for (const ch of str) {
    const d = glyphs.glyphs[ch];
    if (d) parts.push(`<path transform="translate(${pen} 0)" d="${d}"/>`);
    pen += glyphs.advance;
  }
  parts.push("</g>");
  return parts.join("");
}

function qrPath(matrix, x, y, module, mode) {
  const { size, data } = matrix;
  let d = "";
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (!data[r * size + c]) continue;
      d += `M${x + c * module} ${y + r * module}h${module}v${module}h-${module}z`;
    }
  }
  const attrs =
    mode === "solid"
      ? 'fill="#000" fill-rule="evenodd" stroke="none"'
      : `fill="none" fill-rule="evenodd" stroke="#000" stroke-width="${STROKE_MM}" stroke-linecap="square" stroke-linejoin="miter"`;
  return `<path d="${d}" ${attrs}/>`;
}

const charWidth = (glyphs, mm) => (glyphs.advance / glyphs.unitsPerEm) * mm;

// wrap cuts text into lines of the given widths; the last width repeats.
function wrap(text, widths) {
  const out = [];
  for (let rest = text, i = 0; rest.length; i++) {
    const n = Math.max(1, widths[Math.min(i, widths.length - 1)]);
    out.push(rest.slice(0, n));
    rest = rest.slice(n);
  }
  return out;
}

// layout places the QR code at the right edge of the body and flows the
// share text beside it and then below it, at the largest text size that
// fits the card.
function layout(card, glyphs) {
  const bodyTop = MARGIN + HEAD_MM + 2;
  const bodyBottom = CARD_H - MARGIN - FOOT_MM - 1.6;
  const height = bodyBottom - bodyTop;
  const module = Math.min(MODULE_MAX, height / (card.matrix.size + 2 * QUIET));
  const qrBox = (card.matrix.size + 2 * QUIET) * module;
  const qrX = CARD_W - MARGIN - qrBox;

  for (let mm = BODY_MAX; mm >= BODY_MIN; mm -= 0.05) {
    const charW = charWidth(glyphs, mm);
    const lineH = mm * LINE_H;
    const beside = Math.floor((qrX - MARGIN - QR_GAP) / charW);
    const full = Math.floor((CARD_W - 2 * MARGIN) / charW);
    const qrLines = Math.floor(qrBox / lineH);
    const widths = Array(qrLines).fill(beside).concat([full]);
    const lines = wrap(card.text, widths);
    if (lines.length * lineH <= height) return { mm, lineH, lines, module, qrBox, qrX, bodyTop };
  }
  throw new Error(`a share of ${card.text.length} characters does not fit a card`);
}

// labels returns the head and foot lines of a card. The head carries the
// set, with "open" after it for an open set, and the foot the key and the
// quorum. Both start with "#".
function labels(card, glyphs) {
  const set = card.tag.toUpperCase();
  const headLeft = `${set} shaQR ${card.k}-of-${card.n}${card.open ? " open" : ""}`;
  const headRight = `PLATE ${String(card.x).padStart(2, "0")}/${String(card.n).padStart(2, "0")}`;
  const what = card.kind === "descriptor" ? "THE WALLET" : "THE SECRET";
  const room = Math.floor((CARD_W - 2 * MARGIN) / charWidth(glyphs, FOOT_MM));
  const key = card.key ? `KEY ${card.key}  ` : "";
  let foot = `# ${key}ANY ${card.k} OF ${card.n} PLATES REBUILD ${what}`;
  if (foot.length > room) foot = `# ${key}ANY ${card.k} OF ${card.n} REBUILD IT`;
  return { headLeft, headRight, foot };
}

function buildCardContent(card, glyphs, mode) {
  const { mm, lineH, lines, module, qrBox, qrX, bodyTop } = layout(card, glyphs);
  const { headLeft, headRight, foot } = labels(card, glyphs);
  const headW = charWidth(glyphs, HEAD_MM);

  const out = [];
  out.push(textGroup(glyphs, headLeft, MARGIN, MARGIN + HEAD_MM, HEAD_MM, mode));
  out.push(textGroup(glyphs, headRight, CARD_W - MARGIN - headRight.length * headW, MARGIN + HEAD_MM, HEAD_MM, mode));
  lines.forEach((line, i) => {
    out.push(textGroup(glyphs, line, MARGIN, bodyTop + mm + i * lineH, mm, mode));
  });
  out.push(qrPath(card.matrix, qrX + QUIET * module, bodyTop + QUIET * module, module, mode));
  out.push(textGroup(glyphs, foot, MARGIN, CARD_H - MARGIN, FOOT_MM, mode));
  return out.join("\n");
}

// buildCardSvg returns one card, drawn as outlines for an engraver.
export function buildCardSvg(card, glyphs) {
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" width="${CARD_W}mm" height="${CARD_H}mm" ` +
    `viewBox="0 0 ${CARD_W} ${CARD_H}">\n` +
    buildCardContent(card, glyphs, "line") +
    "\n</svg>"
  );
}

function centered(glyphs, str, y, mm, mode, color) {
  const w = str.length * charWidth(glyphs, mm);
  return textGroup(glyphs, str, (210 - w) / 2, y, mm, mode, color);
}

// buildSheetSvg lays the cards of one set out on A4 paper, two across.
export function buildSheetSvg(cards, glyphs, { mode = "solid" } = {}) {
  const [{ k, n, kind, open }] = cards;
  const cols = 2;
  const gapX = 20;
  const gapY = 16;
  const top = 38;
  const x0 = (210 - (cols * CARD_W + (cols - 1) * gapX)) / 2;
  const what = kind === "descriptor" ? "the wallet descriptor" : "the secret";

  const out = [];
  out.push(`<svg xmlns="http://www.w3.org/2000/svg" width="210mm" height="297mm" viewBox="0 0 210 297">`);
  out.push(`<rect width="210" height="297" fill="#fff"/>`);
  out.push(centered(glyphs, "shaQR short secret shares", 20, 6, mode));
  const sub = `any ${k} of ${n} plates rebuild ${what}${open ? ", and each shows part of it" : ""}`;
  out.push(centered(glyphs, sub, 27, 3, mode, "#6f675e"));

  cards.forEach((card, i) => {
    const col = i % cols;
    const row = Math.floor(i / cols);
    const lastAlone = row === Math.ceil(cards.length / cols) - 1 && cards.length % cols === 1;
    const x = lastAlone ? (210 - CARD_W) / 2 : x0 + col * (CARD_W + gapX);
    const y = top + row * (CARD_H + gapY);
    out.push(`<g transform="translate(${x} ${y})">`);
    out.push(
      `<rect x="0.1" y="0.1" width="${CARD_W - 0.2}" height="${CARD_H - 0.2}" rx="2" fill="none" stroke="#ccc" stroke-width="0.2"/>`
    );
    out.push(buildCardContent(card, glyphs, mode));
    out.push(`</g>`);
  });

  out.push(centered(glyphs, `Scan any ${k} of the ${n} codes to recover ${what}.`, 288, 2.6, mode, "#6f675e"));
  out.push(`</svg>`);
  return out.join("\n");
}

export function fileName(card) {
  const set = card.tag.replace("#", "").toUpperCase();
  return `shaqr-${card.k}of${card.n}-${set}-plate-${String(card.x).padStart(2, "0")}.svg`;
}
