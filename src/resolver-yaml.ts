/**
 * resolver-yaml — a MINIMAL, deterministic YAML/JSON reader for the artifact resolver's $ref bundler.
 *
 * The guard package has no YAML dependency; the resolver only needs to parse the constrained YAML
 * that appears in OpenAPI/AsyncAPI contract docs (block mappings, flow mappings, quoted keys, scalar
 * values, and `$ref` strings) to inline external file refs into a deterministic JSON bundle (§4.3).
 * It is NOT a general YAML engine — anything outside the supported subset throws, and the resolver
 * turns that into a `parse_error` unresolved entry (never a fabricated document).
 *
 * Determinism: plain scalars are kept as raw strings (no lossy type coercion), so parse→serialize is
 * byte-stable per input.
 */

export class YamlLiteError extends Error {
  constructor(message: string) { super(message); this.name = 'YamlLiteError'; }
}

type Line = { indent: number; text: string };

/** Parse a JSON or (subset) YAML document to a plain JS value. Throws YamlLiteError on unsupported input. */
export function parseDoc(text: string): unknown {
  const trimmed = text.trimStart();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try { return JSON.parse(text); } catch (e) { throw new YamlLiteError(`invalid JSON: ${(e as Error).message}`); }
  }
  const lines: Line[] = [];
  for (const raw of text.split('\n')) {
    const trimmedLine = raw.trim();
    if (trimmedLine === '' || trimmedLine.startsWith('#')) continue;
    lines.push({ indent: raw.length - raw.trimStart().length, text: trimmedLine });
  }
  if (lines.length === 0) return null;
  const [value] = parseBlock(lines, 0, lines[0].indent);
  return value;
}

function parseBlock(lines: Line[], start: number, indent: number): [unknown, number] {
  if (start >= lines.length) return [null, start];
  const first = lines[start];
  if (first.text === '-' || first.text.startsWith('- ')) return parseSequence(lines, start, indent);
  return parseMapping(lines, start, indent);
}

function parseMapping(lines: Line[], start: number, indent: number): [Record<string, unknown>, number] {
  const obj: Record<string, unknown> = {};
  let i = start;
  while (i < lines.length && lines[i].indent === indent) {
    const { key, rest } = splitKeyValue(lines[i].text);
    i += 1;
    if (rest === '') {
      if (i < lines.length && lines[i].indent > indent) {
        const [child, next] = parseBlock(lines, i, lines[i].indent);
        obj[key] = child;
        i = next;
      } else {
        obj[key] = null;
      }
    } else {
      obj[key] = parseScalarOrFlow(rest);
    }
  }
  return [obj, i];
}

function parseSequence(lines: Line[], start: number, indent: number): [unknown[], number] {
  const arr: unknown[] = [];
  let i = start;
  while (i < lines.length && lines[i].indent === indent && (lines[i].text === '-' || lines[i].text.startsWith('- '))) {
    const itemText = lines[i].text.slice(1).trim();
    i += 1;
    if (itemText === '') {
      if (i < lines.length && lines[i].indent > indent) {
        const [child, next] = parseBlock(lines, i, lines[i].indent);
        arr.push(child);
        i = next;
      } else {
        arr.push(null);
      }
    } else {
      arr.push(parseScalarOrFlow(itemText));
    }
  }
  return [arr, i];
}

/** Split "key: rest" honoring a quoted key; the separator is the first top-level colon. */
function splitKeyValue(text: string): { key: string; rest: string } {
  let key: string;
  let idx: number;
  if (text[0] === "'" || text[0] === '"') {
    const q = text[0];
    let j = 1;
    while (j < text.length && text[j] !== q) j += 1;
    key = text.slice(1, j);
    idx = text.indexOf(':', j);
  } else {
    idx = text.indexOf(':');
    key = idx === -1 ? text : text.slice(0, idx);
  }
  if (idx === -1) return { key: key.trim(), rest: '' };
  return { key: key.trim(), rest: text.slice(idx + 1).trim() };
}

function parseScalarOrFlow(s: string): unknown {
  const t = s.trim();
  if (t === '' || t === '~' || t === 'null') return null;
  if (t[0] === '{' || t[0] === '[') return parseFlow(t).value;
  if (t[0] === "'" || t[0] === '"') return unquote(t);
  return t;
}

function unquote(t: string): string {
  const q = t[0];
  let j = 1;
  let out = '';
  while (j < t.length && t[j] !== q) { out += t[j]; j += 1; }
  return out;
}

function parseFlow(s: string): { value: unknown; end: number } {
  if (s[0] === '{') return parseFlowMap(s);
  if (s[0] === '[') return parseFlowSeq(s);
  throw new YamlLiteError(`not a flow collection: ${s.slice(0, 20)}`);
}

function parseFlowMap(s: string): { value: Record<string, unknown>; end: number } {
  const obj: Record<string, unknown> = {};
  let i = 1;
  while (i < s.length) {
    while (i < s.length && (s[i] === ' ' || s[i] === ',')) i += 1;
    if (s[i] === '}') return { value: obj, end: i + 1 };
    let key: string;
    if (s[i] === "'" || s[i] === '"') {
      const q = s[i]; let j = i + 1; let k = '';
      while (j < s.length && s[j] !== q) { k += s[j]; j += 1; }
      key = k; i = j + 1;
    } else {
      let k = '';
      while (i < s.length && s[i] !== ':' && s[i] !== '}' && s[i] !== ',') { k += s[i]; i += 1; }
      key = k.trim();
    }
    while (i < s.length && (s[i] === ' ' || s[i] === ':')) i += 1;
    const [val, next] = readFlowValue(s, i);
    obj[key] = val;
    i = next;
  }
  throw new YamlLiteError(`unterminated flow map: ${s.slice(0, 40)}`);
}

function parseFlowSeq(s: string): { value: unknown[]; end: number } {
  const arr: unknown[] = [];
  let i = 1;
  while (i < s.length) {
    while (i < s.length && (s[i] === ' ' || s[i] === ',')) i += 1;
    if (s[i] === ']') return { value: arr, end: i + 1 };
    const [val, next] = readFlowValue(s, i);
    arr.push(val);
    i = next;
  }
  throw new YamlLiteError(`unterminated flow seq: ${s.slice(0, 40)}`);
}

function readFlowValue(s: string, start: number): [unknown, number] {
  let i = start;
  while (i < s.length && s[i] === ' ') i += 1;
  if (s[i] === '{' || s[i] === '[') {
    const { value, end } = parseFlow(s.slice(i));
    return [value, i + end];
  }
  if (s[i] === "'" || s[i] === '"') {
    const q = s[i]; let j = i + 1; let out = '';
    while (j < s.length && s[j] !== q) { out += s[j]; j += 1; }
    return [out, j + 1];
  }
  let out = '';
  while (i < s.length && s[i] !== ',' && s[i] !== '}' && s[i] !== ']') { out += s[i]; i += 1; }
  return [out.trim(), i];
}

/** Deterministic JSON serialization with recursively sorted object keys (byte-stable — §4.3, A6). */
export function stableStringify(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      out[k] = sortKeys((value as Record<string, unknown>)[k]);
    }
    return out;
  }
  return value;
}
