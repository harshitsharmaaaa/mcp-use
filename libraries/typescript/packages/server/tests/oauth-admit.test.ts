import { afterEach, describe, expect, it } from "vitest";
import { MCPServer } from "../src/index.js";
import {
  oauthCustomProvider,
  type OAuthMetadata,
} from "../src/oauth/index.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/server";

interface TestUser {
  id: string;
}

const resource = "https://shop.example.test/mcp";
const metadata = { issuer: "https://issuer.example.test" } as OAuthMetadata;

function request(token?: string): Request {
  return new Request(resource, {
    method: "POST",
    headers: {
      accept: "application/json, text/event-stream",
      "content-type": "application/json",
      ...(token !== undefined && { authorization: `Bearer ${token}` }),
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "whoami", arguments: {} },
    }),
  });
}

function createServer(seen: JSONRPCMessage[][]) {
  const oauth = oauthCustomProvider<TestUser>({
    resource,
    requiredScopes: ["shop"],
    oauthMetadata: metadata,
    admit: async (incoming, messages) => {
      seen.push(messages);
      const authorization = incoming.headers.get("authorization");
      if (authorization === null || !authorization.startsWith("Bearer ")) {
        return new Response("denied by adapter", { status: 403 });
      }
      const bearer = authorization.slice("Bearer ".length);
      return {
        bearer,
        authInfo: {
          token: bearer,
          clientId: "client-1",
          scopes: ["shop"],
          expiresAt: Date.now() / 1000 + 600,
          resource: new URL(resource),
        },
      };
    },
    mapAuthInfo: (authInfo) => ({
      user: { id: authInfo.token },
      payload: { sub: authInfo.token },
      permissions: ["shop:read"],
    }),
  });
  const server = new MCPServer<TestUser>({
    name: "auth-admission-test",
    version: "1.0.0",
    oauth,
    logging: { enabled: false },
  });
  server.tool({ name: "whoami" }, async (_args, ctx) => ({
    content: [{ type: "text", text: ctx.auth.user.id }],
  }));
  return server;
}

async function responseText(response: Response): Promise<string> {
  const body = (await response.json()) as {
    result: { content: Array<{ type: string; text: string }> };
  };
  return body.result.content[0]!.text;
}

describe("OAuth admission hook", () => {
  const servers: MCPServer<TestUser>[] = [];
  afterEach(async () => {
    await Promise.all(servers.splice(0).map((server) => server.close()));
  });

  it("admits fetch requests and maps verified identity into callbacks", async () => {
    const seen: JSONRPCMessage[][] = [];
    const server = createServer(seen);
    servers.push(server);

    const response = await server.fetch(request("user-42"));

    expect(response.status).toBe(200);
    expect(await responseText(response)).toBe("user-42");
    expect(seen).toHaveLength(1);
    expect(seen[0]).toHaveLength(1);
    expect(seen[0]![0]).toMatchObject({ method: "tools/call" });
  });

  it("returns adapter responses without entering MCP dispatch", async () => {
    const seen: JSONRPCMessage[][] = [];
    const server = createServer(seen);
    servers.push(server);

    const response = await server.fetch(request());

    expect(response.status).toBe(403);
    expect(await response.text()).toBe("denied by adapter");
    expect(seen).toHaveLength(1);
  });

  it("uses the same admission hook when serving through listen()", async () => {
    const seen: JSONRPCMessage[][] = [];
    const server = createServer(seen);
    servers.push(server);
    const { url } = await server.listen(0);

    const response = await fetch(url, {
      method: "POST",
      headers: {
        accept: "application/json, text/event-stream",
        "content-type": "application/json",
        authorization: "Bearer listener-user",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: "whoami", arguments: {} },
      }),
    });

    expect(response.status).toBe(200);
    expect(await responseText(response)).toBe("listener-user");
    expect(seen).toHaveLength(1);
    expect(seen[0]![0]).toMatchObject({ method: "tools/call" });
  });
});
