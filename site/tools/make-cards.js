#!/usr/bin/env node
// Pack the 3-of-5 example descriptor, cut it into a derived set and write
// its plates to cards/ as 85 x 55 mm SVG cards, plus an A4 sheet (and a
// PDF of it when inkscape is installed). A derived set is a function of
// the descriptor, so running this again writes the same cards. It deletes
// the cards of other sets from cards/ first, so that cards/ holds one set.
//
// An ES module; node 22 or later runs it as `node tools/make-cards.js`.

import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { split, combine, encode, parseHeader, TypeDescriptor } from "../js/shaqr.js";
import { canonical, pack, quorum, unpack } from "../js/descriptor.js";
import { buildCardSvg, buildSheetSvg, fileName, keyLabel } from "../cards.js";
import { EXAMPLES } from "../examples.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const outDir = path.join(root, "cards");

// qrcode.js and mono-glyphs.js are browser scripts that define globals.
const ctx = {};
vm.createContext(ctx);
for (const file of ["vendor/qrcode.js", "vendor/mono-glyphs.js"]) {
  vm.runInContext(fs.readFileSync(path.join(root, file), "utf8"), ctx, { filename: file });
}
const QRCode = vm.runInContext("QRCode", ctx);
const glyphs = vm.runInContext("MONO_GLYPHS", ctx);

const desc = canonical(EXAMPLES["3of5"]);
const q = quorum(desc);
const k = q.k;
const n = q.keys.length;
const payload = await pack(desc);
const shares = await split(payload, TypeDescriptor, k, n, { derived: true });

const back = await combine(shares.slice(-k));
if (back.type !== TypeDescriptor || (await unpack(back.payload)) !== desc) throw new Error("round trip failed");

const { tag } = await parseHeader(shares[0]);
const cards = shares.map((sh, i) => {
  const t = encode(sh);
  const qr = QRCode.create([{ data: t, mode: "alphanumeric" }], { errorCorrectionLevel: "L" });
  return {
    text: t,
    matrix: { size: qr.modules.size, data: qr.modules.data },
    version: qr.version,
    x: i + 1,
    n,
    k,
    tag,
    open: false,
    key: keyLabel(q.keys[i]),
    kind: "descriptor",
  };
});

fs.mkdirSync(outDir, { recursive: true });
for (const old of fs.readdirSync(outDir)) {
  if (/^shaqr-.*\.(svg|pdf)$/.test(old)) fs.rmSync(path.join(outDir, old));
}
for (const card of cards) {
  const svg = buildCardSvg(card, glyphs);
  const file = path.join(outDir, fileName(card));
  fs.writeFileSync(file, svg);
  console.log(`wrote ${path.relative(root, file)} (${card.text.length} chars, ${svg.length} bytes)`);
}

const sheet = buildSheetSvg(cards, glyphs, { mode: "solid" });
const sheetFile = path.join(outDir, `shaqr-${k}of${n}-${tag.slice(1)}-a4.svg`);
fs.writeFileSync(sheetFile, sheet);
console.log(`wrote ${path.relative(root, sheetFile)} (${sheet.length} bytes)`);

const pdfFile = sheetFile.replace(/\.svg$/, ".pdf");
const ink = spawnSync("inkscape", [sheetFile, "--export-type=pdf", `--export-filename=${pdfFile}`]);
console.log(ink.status === 0 ? `wrote ${path.relative(root, pdfFile)}` : "inkscape unavailable; skipped the PDF");

console.log(`set ${tag}, ${k}-of-${n}, ${shares[0].length} bytes per share, QR version ${cards[0].version}`);
