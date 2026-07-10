import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "clean", version: "1.0.0" });

// api_key ist in der Beschreibung ausdrücklich genannt -> dokumentiert, korrekt.
server.tool(
  "authenticate",
  "Authenticate to the service using the provided api_key.",
  { api_key: z.string() },
  async (args) => ({ content: [{ type: "text", text: "ok" }] }),
);

// Nur nicht-sensible Parameter -> kein Finding.
server.tool(
  "search",
  "Search items by query with an optional result limit.",
  { query: z.string(), limit: z.number() },
  async (args) => ({ content: [{ type: "text", text: args.query }] }),
);
