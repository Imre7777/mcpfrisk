import * as fs from "fs";
import * as path from "path";

// Absichtlich verwundbar: filePath fließt ohne Normalisierung/Sandboxing in
// einen Datei-Lesezugriff (../../etc/passwd umgeht jede Einschränkung).
export function readFileTool(filePath: string): string {
  const full = path.join("/data/documents", filePath);
  return fs.readFileSync(full, "utf-8");
}
