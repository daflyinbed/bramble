// Minimal Nostr-subset signaling relay for P2P sync testing/self-hosting.
// See docs/p2p-sync.md. This is NOT a full Nostr relay: it speaks just enough of
// NIP-01 (REQ / EVENT / CLOSE) to fan out *ephemeral* events (kind 20000-29999)
// to current subscribers, and stores nothing. The vault never touches it; it
// only relays encrypted, group-key-addressed signaling blobs.
//
// Run:  node nostr-relay/node/relay.mjs            (defaults to ws://localhost:7400)
//       PORT=9000 node nostr-relay/node/relay.mjs
//
// Clients publish:  ["EVENT", { kind: 20000, tags: [["d", roomId]], content, ... }]
//          and sub: ["REQ", subId, { kinds: [20000], "#d": [roomId] }]
//
// POST /ice-servers serves the STUN/TURN list (see ../cf-worker/src/index.ts);
// peers across networks need it or ICE falls back to host-only candidates.
// Override the default public STUN list with ICE_SERVERS, a JSON array of
// RTCIceServer objects, e.g.
//   ICE_SERVERS='[{"urls":["stun:stun.example:3478"]},{"urls":["turn:turn.example:3478"],"username":"u","credential":"p"}]'

import { createServer } from "node:http";
import { WebSocketServer } from "ws";

const PORT = Number(process.env.PORT ?? 7400);

// Cheap abuse guards (kept in parity with cf-worker): a signaling blob is a few
// KB of encrypted SDP/ICE, so reject larger frames before parsing, and bound
// subscriptions per connection (a device needs ~1).
const MAX_MSG_BYTES = 64 * 1024;
const MAX_SUBS_PER_CONN = 8;

// Keepalive, in parity with cf-worker (where it is a hibernation auto-response) and
// @core/sync/signaling-client. Clients ping a quiet socket so an intermediary doesn't drop it, and
// read the answer as proof the relay is still there.
const PING = "ping";
const PONG = "pong";

// Default public STUN servers; enough for srflx candidates on common NATs. TURN
// (needed for symmetric NATs / hard firewalls) only if configured via env.
const DEFAULT_ICE_SERVERS = [
	{ urls: ["stun:stun.cloudflare.com:3478"] },
	{ urls: ["stun:stun.l.google.com:19302"] },
];

function parseIceServers() {
	const raw = process.env.ICE_SERVERS;
	if (!raw) return DEFAULT_ICE_SERVERS;
	try {
		const parsed = JSON.parse(raw);
		if (!Array.isArray(parsed)) throw new Error("not an array");
		return parsed.filter((s) => s && (typeof s.urls === "string" || Array.isArray(s.urls)));
	} catch {
		return DEFAULT_ICE_SERVERS;
	}
}
const ICE_SERVERS = parseIceServers();

/** True if `event` matches a single REQ `filter` (kinds, authors, #<tag>). */
function matches(filter, event) {
	if (filter.kinds && !filter.kinds.includes(event.kind)) return false;
	if (filter.authors && !filter.authors.includes(event.pubkey)) return false;
	for (const [key, vals] of Object.entries(filter)) {
		if (!key.startsWith("#") || !Array.isArray(vals)) continue;
		const tag = key.slice(1);
		const present = event.tags?.filter((t) => t[0] === tag).map((t) => t[1]) ?? [];
		if (!vals.some((v) => present.includes(v))) return false;
	}
	return true;
}

const sockets = new Set();

// Plain HTTP for the health probe and the ICE mint; the WS server shares the
// same listener and handles the Upgrade handshake itself.
const httpServer = createServer((req, res) => {
	if (req.method === "POST" && req.url.split("?")[0] === "/ice-servers") {
		res.writeHead(200, {
			"content-type": "application/json",
			"access-control-allow-origin": "*",
			"access-control-allow-methods": "POST, OPTIONS",
			"access-control-allow-headers": "Content-Type",
		});
		res.end(JSON.stringify({ iceServers: ICE_SERVERS, ttl: 86400 }));
		return;
	}
	if (req.method === "OPTIONS" && req.url.split("?")[0] === "/ice-servers") {
		res.writeHead(204, {
			"access-control-allow-origin": "*",
			"access-control-allow-methods": "POST, OPTIONS",
			"access-control-allow-headers": "Content-Type",
		});
		res.end();
		return;
	}
	res.writeHead(200, { "content-type": "text/plain" });
	res.end("bramble signaling relay");
});

const wss = new WebSocketServer({ server: httpServer });

wss.on("connection", (ws) => {
	ws.subs = new Map(); // per-connection: subId -> filters
	sockets.add(ws);
	ws.on("close", () => sockets.delete(ws));

	ws.on("message", (raw) => {
		if (raw.length > MAX_MSG_BYTES) return;
		if (raw.toString() === PING) return ws.send(PONG);

		let msg;
		try {
			msg = JSON.parse(raw.toString());
		} catch {
			return;
		}
		if (!Array.isArray(msg)) return;
		const [type] = msg;

		if (type === "REQ") {
			const [, subId, ...filters] = msg;
			if (!ws.subs.has(subId) && ws.subs.size >= MAX_SUBS_PER_CONN) return;
			ws.subs.set(subId, filters);
			ws.send(JSON.stringify(["EOSE", subId])); // no stored events: ephemeral only
			return;
		}
		if (type === "CLOSE") {
			ws.subs.delete(msg[1]);
			return;
		}
		if (type === "EVENT") {
			const event = msg[1];
			if (!event || event.kind < 20000 || event.kind >= 30000) {
				ws.send(JSON.stringify(["OK", event?.id ?? "", false, "only ephemeral kinds"]));
				return;
			}
			// Fan out to every other socket's matching subscription; store nothing.
			for (const peer of sockets) {
				if (peer === ws) continue;
				for (const [subId, filters] of peer.subs) {
					if (filters.some((f) => matches(f, event))) {
						peer.send(JSON.stringify(["EVENT", subId, event]));
						break;
					}
				}
			}
			ws.send(JSON.stringify(["OK", event.id ?? "", true, ""]));
		}
	});
});

httpServer.listen(PORT, () => {
	console.log(`bramble signaling relay on ws://localhost:${PORT}`);
});
