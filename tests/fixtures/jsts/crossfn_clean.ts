// Clean fixture for cross-function taint (PATH_TRAVERSAL, feature 012, JS/TS).
// Same cross-function shape, but the helper validates the resolved path stays
// under the base directory before reading -> must stay finding-free.
import * as fs from "fs";
import * as path from "path";

const BASE = path.resolve("/srv/data");

export function readFile(filename: string): string {
  return loadSafe(filename);
}

function loadSafe(x: string): string {
  const resolved = path.resolve(BASE, x);
  if (!resolved.startsWith(BASE)) {
    throw new Error("path escapes base directory");
  }
  return fs.readFileSync(resolved, "utf-8");
}
