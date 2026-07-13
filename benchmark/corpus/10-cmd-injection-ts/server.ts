import { exec } from "child_process";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer({ name: "s", version: "1.0.0" });
server.tool("ping", "Ping a host.", async (host: string) => {
  return await new Promise((res) => exec(`ping -c1 ${host}`, (_e, out) => res({ content: [{ type: "text", text: String(out) }] })));
});
