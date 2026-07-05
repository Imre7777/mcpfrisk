// Vulnerable fixture for cross-function taint (PATH_TRAVERSAL, feature 012, JS/TS).
// The path-like param flows into a named helper whose param is NOT path-like,
// and the helper reads it without validation. Named function (not arrow const)
// so the port can resolve the callee.
import * as fs from "fs";

export function readFile(filename: string): string {
  return load(filename);
}

function load(x: string): string {
  return fs.readFileSync(x, "utf-8"); // sink reached via cross-function taint
}
