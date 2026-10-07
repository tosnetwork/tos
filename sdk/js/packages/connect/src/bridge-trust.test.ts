import { describe, it, expect, vi, afterEach } from "vitest";
import { TosConnect } from "./TosConnect.js";
import { generateSessionKeypair, encryptMessage, decryptMessage } from "./session.js";
import { bytesToHex, hexToBytes, toBase64Url, fromBase64Url } from "./utils.js";
import { MemoryStorageAdapter } from "./storage.js";

class FakeEvents {
  static last: FakeEvents;
  onmessage?: (event: { data: string }) => void;
  onopen?: () => void;
  onerror?: () => void;
  constructor(public url: string) { FakeEvents.last = this; }
  close() {}
}
const wallet = {name:"Pairing wallet", appName:"pairing", imageUrl:"", platforms:[],
  universalLink:"https://wallet.example/connect", bridgeUrl:"https://bridge.example"};
const connected = {event:"connect", payload:{device:{platform:"web", appName:"pairing", appVersion:"1", maxProtocolVersion:2, features:[]},
  items:[{name:"tos_addr", address:"0:"+"01".repeat(32), network:"-239", publicKey:"02".repeat(32), walletStateInit:""}]}};
afterEach(() => vi.unstubAllGlobals());

function pair() {
  vi.stubGlobal("EventSource", FakeEvents);
  const trusted = generateSessionKeypair();
  const stranger = generateSessionKeypair();
  const sdk = new TosConnect({manifestUrl:"https://dapp.example/manifest.json", storage:new MemoryStorageAdapter()});
  const link = sdk.connect(wallet, {walletSessionPublicKey:bytesToHex(trusted.publicKey)})!;
  const client = hexToBytes(new URL(link).searchParams.get("id")!);
  const deliver = (key: ReturnType<typeof generateSessionKeypair>, event: unknown) => {
    const message = encryptMessage(new TextEncoder().encode(JSON.stringify(event)), client, key.secretKey);
    FakeEvents.last.onmessage!({data:JSON.stringify({from:bytesToHex(key.publicKey), message:toBase64Url(message)})});
  };
  return {sdk, trusted, stranger, deliver, client};
}
describe("authenticated wallet pairing", () => {
  it("refuses a bridge flow without a trusted sender", () => {
    const sdk = new TosConnect({manifestUrl:"https://dapp.example/manifest.json"});
    expect(() => sdk.connect(wallet)).toThrow("trusted wallet session public key");
  });
  it("refuses a low-order pairing key", () => {
    const sdk = new TosConnect({manifestUrl:"https://dapp.example/manifest.json"});
    expect(() => sdk.connect(wallet, {walletSessionPublicKey:"00".repeat(32)})).toThrow("Invalid wallet session");
  });
  it("ignores an unbound encrypted connect and pins the verified sender", async () => {
    const {sdk, trusted, stranger, deliver} = pair();
    deliver(stranger, connected);
    expect(sdk.connected).toBe(false);
    deliver(trusted, connected);
    expect(sdk.connected).toBe(true);
    const original = sdk.account;
    deliver(stranger, {...connected, payload:{...connected.payload, items:[{...connected.payload.items[0], address:"attacker"}]}});
    deliver(stranger, {event:"disconnect", payload:{}});
    deliver(stranger, {id:"1", result:"attacker-response"});
    expect(sdk.account).toEqual(original);
    // Even an authenticated sender cannot replace an established account with
    // another connect event; the user has to initiate a fresh connection.
    deliver(trusted, {...connected, payload:{...connected.payload, items:[{...connected.payload.items[0], address:"changed"}]}});
    expect(sdk.account).toEqual(original);
    deliver(trusted, {event:"disconnect", payload:{}});
    expect(sdk.connected).toBe(false);
  });
  it("ignores a foreign sender's response to a real pending RPC", async () => {
    const {sdk, trusted, stranger, deliver, client} = pair();
    let id = "";
    vi.stubGlobal("fetch", vi.fn(async (_url, options) => {
      const bytes = decryptMessage(fromBase64Url(options.body), client, trusted.secretKey)!;
      id = JSON.parse(new TextDecoder().decode(bytes)).id;
      return {ok:true};
    }));
    deliver(trusted, connected);
    const pending = sdk.sendTransaction({validUntil:Math.floor(Date.now()/1000)+60, messages:[]});
    let resolved = false;
    void pending.then(() => { resolved = true; });
    await Promise.resolve();
    deliver(stranger, {id, result:JSON.stringify({boc:"forged"})});
    await Promise.resolve();
    expect(resolved).toBe(false);
    deliver(trusted, {id, result:JSON.stringify({boc:"authorized"})});
    await expect(pending).resolves.toEqual({boc:"authorized"});
  });
  it("does not restore a session established by the former unbound handshake", async () => {
    const storage = new MemoryStorageAdapter();
    await storage.setItem("session_v2", JSON.stringify({wallet:{account:{address:"attacker"}}}));
    const sdk = new TosConnect({manifestUrl:"https://dapp.example/manifest.json", storage});
    await expect(sdk.restoreConnection()).rejects.toThrow("No persisted session");
  });
});
