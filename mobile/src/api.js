// api.js — public Alpha Blockchain API (no keys server-side)
const BASE = "https://api.alphacoin.network/api";
// fallback to the web host if the api subdomain is unreachable
const FALLBACK = "https://alphacoin.network/api";

async function get(path) {
  try {
    const r = await fetch(BASE + "/" + path);
    if (r.ok) return await r.json();
    throw new Error("http " + r.status);
  } catch (e) {
    const r2 = await fetch(FALLBACK + "/" + path);
    if (!r2.ok) throw new Error("api unreachable");
    return await r2.json();
  }
}

export const api = {
  stats:      ()          => get("stats"),
  utxos:      (addr)      => get("utxos/" + addr),
  address:    (addr)      => get("address/" + addr),
  stakes:     ()          => get("stakes"),
  stakeinfo:  ()          => get("stakeinfo"),
  minework:   (addr)      => get("minework?address=" + addr),
  submitwork: (wid, nonce)=> get(`submitwork?workid=${wid}&nonce=${nonce}`),
  broadcast:  (hex)       => get("broadcast?hex=" + hex),
};
