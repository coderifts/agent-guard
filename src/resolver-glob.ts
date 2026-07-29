/**
 * resolver-glob — a correct POSIX-path glob matcher for SSOT selection (§5). The naive `fnmatch`
 * fails on the double-star token (which must span zero-or-more path segments); this handles it (plus
 * `*` / `?`) precisely so a `generated` double-star pattern matches `generated/x.json`,
 * `a/generated/b.yaml`, etc., but not `src/x.yaml`.
 */

/** Compile a glob to an anchored RegExp. Double-star spans segments; `*`/`?` stay within a segment. */
export function globToRegExp(glob: string): RegExp {
  let re = '';
  for (let i = 0; i < glob.length; i += 1) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        i += 1;
        if (glob[i + 1] === '/') { re += '(?:.*/)?'; i += 1; } else { re += '.*'; }
      } else {
        re += '[^/]*';
      }
    } else if (c === '?') {
      re += '[^/]';
    } else if ('.+^${}()|[]\\'.includes(c)) {
      re += `\\${c}`;
    } else {
      re += c;
    }
  }
  return new RegExp(`^${re}$`);
}

/** True iff `path` matches `glob`. */
export function matchGlob(glob: string, path: string): boolean {
  return globToRegExp(glob).test(path);
}

/** True iff `path` matches ANY of the globs (also accepts an exact-path equality). */
export function matchAny(globs: string[] | undefined, path: string): boolean {
  if (!Array.isArray(globs)) return false;
  return globs.some((g) => g === path || matchGlob(g, path));
}

/** Index of the FIRST glob matching `path` (exact or glob), else -1 (first-match-wins). */
export function firstMatchIndex(globs: string[] | undefined, path: string): number {
  if (!Array.isArray(globs)) return -1;
  for (let i = 0; i < globs.length; i += 1) {
    if (globs[i] === path || matchGlob(globs[i], path)) return i;
  }
  return -1;
}
