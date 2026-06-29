import * as fs from "fs";
import * as path from "path";

const BASE = path.resolve("/data/documents");

// Sicher: Pfad wird aufgelöst und gegen das Basisverzeichnis geprüft.
export function readFileTool(filePath: string): string {
  const full = path.resolve(BASE, filePath);
  if (!full.startsWith(BASE)) {
    throw new Error("Access outside the documents directory is not allowed.");
  }
  return fs.readFileSync(full, "utf-8");
}
