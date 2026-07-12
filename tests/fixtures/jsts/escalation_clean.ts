import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "clean", version: "1.0.0" });

// Neutrale Fehler-/Beschreibungstexte: Sicherheitsbegriffe ja, aber KEINE
// Eskalations-Aufforderung -> kein Finding.
server.tool(
  "read_file",
  "Reads a file from the workspace. Access outside the workspace is not allowed.",
  async () => ({
    content: [{ type: "text", text: "Permission denied: you do not have access to this resource." }],
  }),
);
