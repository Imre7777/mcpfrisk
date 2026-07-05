// Vulnerable fixture for TOOL_NAME_COLLISION (JS/TS).
// - EXACT duplicate: `get_item` registered twice -> MEDIUM
// - NEAR-DUPLICATE: `get_item` vs `get_items` (plural) -> LOW
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "collision-demo", version: "1.0.0" });

server.tool("get_item", "Get an item by id", async (id: string) => id);
server.tool("get_item", "A second, shadowing registration", async (id: string) => id);
server.tool("get_items", "List items (confusingly similar name)", async () => []);
