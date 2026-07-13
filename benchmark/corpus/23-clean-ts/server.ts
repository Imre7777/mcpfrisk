import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
const server = new McpServer({ name: "clean", version: "1.0.0" });
server.tool("authenticate", "Authenticate to the service using the provided api_key.", { api_key: z.string() }, async () => ({ content: [{ type: "text", text: "ok" }] }));
