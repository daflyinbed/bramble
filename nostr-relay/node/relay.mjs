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

// Structured trace: every connection, REQ, EVENT fan-out and HTTP hit on one
// line, so a failed sync can be followed end-to-end. Room ids are HMACs and
// author pubkeys are already public on the wire, so 8-char prefixes identify a
// session without leaking anything the relay doesn't see by design; payload
// content is ciphertext and logged as a byte size only.
const log = (...args) => console.log(new Date().toISOString(), ...args);
const short = (s) => String(s ?? "").slice(0, 8);

// The relay may sit behind a reverse proxy/CDN (e.g. a self-host fronted by an
// edge service), where the socket address is the edge node, not the client. Such
// proxies APPEND the address they see to X-Forwarded-For, so the last entry is
// the one added by the trusted hop closest to us; client-supplied entries in
// front of it are spoofable. Informational only — never gate on it.
const clientOf = (req) => {
	const xff = req.headers["x-forwarded-for"];
	const last = typeof xff === "string" ? xff.split(",").pop().trim() : "";
	return last ? `${req.socket.remoteAddress} xff=${last}` : req.socket.remoteAddress;
};

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
	} catch (e) {
		log(`ICE_SERVERS invalid (${e.message}); falling back to defaults`);
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
let connSeq = 0;

// Plain HTTP for the health probe and the ICE mint; the WS server shares the
// same listener and handles the Upgrade handshake itself.
const httpServer = createServer((req, res) => {
	if (req.method === "POST" && req.url.split("?")[0] === "/ice-servers") {
		log(`http  ice-servers  ${clientOf(req)}`);
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

wss.on("connection", (ws, req) => {
	ws.subs = new Map(); // per-connection: subId -> filters
	const id = `conn${String(++connSeq).padStart(3, "0")}`;
	const openedAt = Date.now();
	sockets.add(ws);
	log(`${id} open  ${clientOf(req)} (${sockets.size} peers)`);
	ws.on("close", () => {
		sockets.delete(ws);
		log(`${id} close ${Math.round((Date.now() - openedAt) / 1000)}s (${sockets.size} peers)`);
	});

	ws.on("message", (raw) => {
		if (raw.length > MAX_MSG_BYTES) {
			log(`${id} drop  frame ${raw.length}B > ${MAX_MSG_BYTES}B`);
			return;
		}
		if (raw.toString() === PING) return ws.send(PONG);

		let msg;
		try {
			msg = JSON.parse(raw.toString());
		} catch {
			log(`${id} drop  unparseable ${raw.length}B`);
			return;
		}
		if (!Array.isArray(msg)) return;
		const [type] = msg;

		if (type === "REQ") {
			const [, subId, ...filters] = msg;
			if (!ws.subs.has(subId) && ws.subs.size >= MAX_SUBS_PER_CONN) {
				log(`${id} drop  REQ ${short(subId)}: over ${MAX_SUBS_PER_CONN} subs`);
				return;
			}
			ws.subs.set(subId, filters);
			log(`${id} REQ   ${short(subId)} rooms=${filters.map((f) => short(f?.["#d"]?.[0])).join(",") || "?"}`);
			ws.send(JSON.stringify(["EOSE", subId])); // no stored events: ephemeral only
			return;
		}
		if (type === "CLOSE") {
			ws.subs.delete(msg[1]);
			return;
		}
		if (type === "EVENT") {
			const event = msg[1];
			const room = short(event?.tags?.find((t) => t?.[0] === "d")?.[1]);
			if (!event || event.kind < 20000 || event.kind >= 30000) {
				log(`${id} rej   kind=${event?.kind} room=${room}`);
				ws.send(JSON.stringify(["OK", event?.id ?? "", false, "only ephemeral kinds"]));
				return;
			}
			// Fan out to every other socket's matching subscription; store nothing.
			let fanout = 0;
			for (const peer of sockets) {
				if (peer === ws) continue;
				for (const [subId, filters] of peer.subs) {
					if (filters.some((f) => matches(f, event))) {
						peer.send(JSON.stringify(["EVENT", subId, event]));
						fanout++;
						break;
					}
				}
			}
			log(`${id} EVENT kind=${event.kind} room=${room} author=${short(event.pubkey)} ${raw.length}B -> ${fanout} peer(s)`);
			ws.send(JSON.stringify(["OK", event.id ?? "", true, ""]));
		}
	});
});

httpServer.listen(PORT, () => {
	log(`bramble signaling relay on ws://localhost:${PORT} (${ICE_SERVERS.length} ice server entries)`);
});
