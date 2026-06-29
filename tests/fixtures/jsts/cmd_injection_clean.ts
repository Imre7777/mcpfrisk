import { execFile } from "child_process";

// Sicher: execFile mit Argument-Array, keine Shell, keine Interpolation.
export function runTool(userInput: string): void {
  execFile("echo", [userInput]);
}
