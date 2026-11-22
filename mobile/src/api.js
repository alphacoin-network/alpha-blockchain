// api.js — public Alpha Blockchain API (no keys server-side)
const BASE = "http://68.178.163.58/api";
// fallback to the web host if the api subdomain is unreachable
const FALLBACK = "http://68.178.163.58/api";

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
  minework:   (addr, pool) => get(`minework?address=${addr}${pool ? "&pool=1" : ""}`),
  submitwork: (wid, nonce)=> get(`submitwork?workid=${wid}&nonce=${nonce}`),
  submitshares:(wid, nonces)=> get(`submitwork?workid=${wid}&nonces=${nonces.join(",")}`),
  poolinfo:   (addr)      => get("poolinfo?address=" + addr),
  broadcast:  (hex)       => get("broadcast?hex=" + hex),
};
