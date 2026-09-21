/* Rebuilds the QBANK block inside index.html from data/bank-*.json.
   Run this after editing any data/bank-<subject>.json file, before deploying.
   Usage: node tools/build.js */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const DATA_DIR = path.join(ROOT, "data");
const INDEX = path.join(ROOT, "index.html");

const manifest = JSON.parse(fs.readFileSync(path.join(DATA_DIR, "manifest.json"), "utf8"));

let all = [];
for (const s of manifest.subjects) {
  const file = path.join(DATA_DIR, s.file);
  const list = JSON.parse(fs.readFileSync(file, "utf8"));
  if (list.length !== s.count) {
    throw new Error(`${s.file}: manifest says ${s.count} questions, file has ${list.length}`);
  }
  all = all.concat(list);
}

// stable, deterministic order regardless of file/subject order
all.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

const seenIds = new Set();
for (const q of all) {
  if (!q.id) throw new Error(`question missing id: ${q.q?.slice(0, 60)}`);
  if (seenIds.has(q.id)) throw new Error(`duplicate id: ${q.id}`);
  seenIds.add(q.id);
  if (!Array.isArray(q.opts) || q.opts.length !== 4) throw new Error(`${q.id}: opts must have 4 entries`);
  if (!(q.ans >= 0 && q.ans <= 3)) throw new Error(`${q.id}: ans must be 0-3`);
}
if (all.length !== manifest.total) {
  throw new Error(`manifest.total is ${manifest.total}, but found ${all.length} questions`);
}

const html = fs.readFileSync(INDEX, "utf8");
const startMarker = "const QBANK = [";
const startIdx = html.indexOf(startMarker);
if (startIdx === -1) throw new Error("QBANK start marker not found in index.html");
const arrayStart = startIdx + startMarker.length - 1;

let depth = 0, i = arrayStart, inStr = null, escaped = false;
for (; i < html.length; i++) {
  const c = html[i];
  if (inStr) {
    if (escaped) escaped = false;
    else if (c === "\\") escaped = true;
    else if (c === inStr) inStr = null;
    continue;
  }
  if (c === '"' || c === "'" || c === "`") { inStr = c; continue; }
  if (c === "[") depth++;
  else if (c === "]") { depth--; if (depth === 0) break; }
}
if (depth !== 0) throw new Error("could not find matching close bracket for QBANK");

const before = html.slice(0, startIdx);
const after = html.slice(i + 2); // skip "];"
const newBlock = `const QBANK = ${JSON.stringify(all)};`;

fs.writeFileSync(INDEX, before + newBlock + after);
console.log(`OK — wrote ${all.length} questions into index.html from ${manifest.subjects.length} data files.`);
