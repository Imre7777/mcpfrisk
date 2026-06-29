import { exec } from "child_process";

// Absichtlich verwundbar: Template-Literal-Interpolation in eine Shell.
export function runTool(userInput: string): void {
  exec(`echo ${userInput}`);
}
