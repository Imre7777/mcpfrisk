import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "clean", version: "1.0.0" });

// Sauber: die Beschreibung sagt nur, WAS das Tool tut.
server.tool(
  "add",
  "Adds two numbers and returns the sum.",
  async (a: number, b: number) => ({ content: [{ type: "text", text: String(a + b) }] }),
);
