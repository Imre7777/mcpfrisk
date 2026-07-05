// Clean fixture for TOOL_NAME_COLLISION (JS/TS).
// Distinct tool names sharing a common word but unambiguously different.
// Must produce ZERO collision findings.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "clean-demo", version: "1.0.0" });

server.tool("list_users", "List all users", async () => []);
server.tool("create_user", "Create a user", async (name: string) => name);
server.tool("delete_order", "Delete an order", async (id: string) => true);
server.tool("fetch_weather", "Fetch the weather", async (city: string) => city);
