import "react-native-get-random-values";
import React, { useEffect, useRef, useState } from "react";
import { SafeAreaView, View, Text, TextInput, TouchableOpacity,
         ScrollView, StyleSheet, Alert } from "react-native";
import QRCode from "react-native-qrcode-svg";
import { api } from "./src/api";
import { saveWif, loadWif, clearWif } from "./src/store";
import { randomPriv, privToPub, hash160, addrFromPub, wifEncode,
         wifDecode, addrToPkh, b2hex, hexToB, b2n, sha256d,
         buildSendTx, buildStakeTx, buildUnstakeTx, hashAsLEint,
         spkP2pkh, stakeSpk } from "./src/alphacrypto";

const keyFromWif = wif => {
  const priv = wifDecode(wif), pub = privToPub(priv);
  return { priv, pub, pkh: hash160(pub), addr: addrFromPub(pub), wif };
};

export default function App() {
  const [tab, setTab] = useState("wallet");
  const [key, setKey] = useState(null);
  const [stats, setStats] = useState(null);
  useEffect(() => { loadWif().then(w => { if (w) setKey(keyFromWif(w)); }); }, []);
  useEffect(() => { api.stats().then(setStats).catch(() => {}); }, [tab]);
  return (
    <SafeAreaView style={s.root}>
      <View style={s.header}>
        <Text style={s.brand}>◈ Alpha Wallet</Text>
        <Text style={s.net}>{stats ? `main · ${stats.height} blk` : "…"}</Text>
      </View>
      <ScrollView style={{ flex: 1 }}>
        {tab === "wallet" && <Wallet key_={key} setKey={setKey} stats={stats} />}
        {tab === "stake"  && <Stake  key_={key} stats={stats} />}
        {tab === "mine"   && <Mine   key_={key} />}
      </ScrollView>
      <View style={s.tabs}>
        {[["wallet","◈ Wallet"],["stake","◇ Stake"],["mine","⛏ Mine"]].map(([id,label]) => (
          <TouchableOpacity key={id} style={[s.tab, tab===id && s.tabOn]}
            onPress={() => setTab(id)}>
            <Text style={[s.tabTxt, tab===id && s.tabTxtOn]}>{label}</Text>
          </TouchableOpacity>
        ))}
      </View>
    </SafeAreaView>
  );
}

/* ================= WALLET ================= */
function Wallet({ key_, setKey, stats }) {
  const [wifIn, setWifIn] = useState("");
  const [to, setTo] = useState(""), [amt, setAmt] = useState("");
  const [status, setStatus] = useState(""), [bal, setBal] = useState(null);
  const refresh = async () => {
    if (!key_) return;
    try {
      const u = await api.utxos(key_.addr);
      const myspk = b2hex(spkP2pkh(key_.pkh));
      const mine = (u.utxos || []).filter(x => x.scriptPubKey === myspk);
      setBal(mine.reduce((a, x) => a + x.amount, 0));
    } catch (e) { setBal(null); }
  };
  useEffect(() => { refresh(); }, [key_]);

  const create = async () => {
    const k = keyFromWif(wifEncode(randomPriv()));
    await saveWif(k.wif); setKey(k);
    Alert.alert("Backup your key", "Your private key (WIF) is shown under 'Key'. Write it down — it is the ONLY backup.");
  };
  const import_ = async () => {
    try { const k = keyFromWif(wifIn.trim()); await saveWif(k.wif); setKey(k); setWifIn(""); }
    catch (e) { Alert.alert("Bad WIF", e.message); }
  };
  const send = async () => {
    setStatus("building…");
    try {
      const sats = Math.round(parseFloat(amt) * 1e8);
      if (!sats || sats <= 0) throw new Error("bad amount");
      const dest = addrToPkh(to.trim());
      const u = await api.utxos(key_.addr);
      const raw = buildSendTx(u.utxos || [], key_, dest, sats);
      setStatus("broadcasting…");
      const r = await api.broadcast(raw);
      if (r.error) throw new Error(r.error);
      setStatus("✓ sent! txid " + String(r.result || r).slice(0, 20) + "…");
      setTimeout(refresh, 3000);
    } catch (e) { setStatus("✗ " + e.message); }
  };
  const wipe = () => Alert.alert("Remove wallet?", "Make sure your WIF is backed up.",
    [{ text: "Cancel" }, { text: "Remove", style: "destructive",
      onPress: async () => { await clearWif(); setKey(null); setBal(null); } }]);

  if (!key_) return (
    <View style={s.card}>
      <Text style={s.h}>Self-custody wallet</Text>
      <Text style={s.dim}>Keys are generated on this device and never leave it.</Text>
      <Btn t="Create new wallet" onPress={create} />
      <TextInput style={s.in} placeholder="import WIF private key" placeholderTextColor="#666"
        value={wifIn} onChangeText={setWifIn} autoCapitalize="none" />
      <Btn t="Import wallet" onPress={import_} alt />
    </View>
  );
  return (
    <View>
      <View style={s.card}>
        <Text style={s.h}>Balance</Text>
        <Text style={s.bal}>{bal === null ? "…" : bal.toFixed(8)} <Text style={s.unit}>ALPHA</Text></Text>
        <Text style={s.dim} selectable>{key_.addr}</Text>
        <View style={{ alignItems: "center", marginVertical: 12 }}>
          <QRCode value={key_.addr} size={140} backgroundColor="white" />
        </View>
      </View>
      <View style={s.card}>
        <Text style={s.h}>Send</Text>
        <TextInput style={s.in} placeholder="to address (1…)" placeholderTextColor="#666"
          value={to} onChangeText={setTo} autoCapitalize="none" />
        <TextInput style={s.in} placeholder="amount ALPHA" placeholderTextColor="#666"
          value={amt} onChangeText={setAmt} keyboardType="decimal-pad" />
        <Btn t="Send ALPHA" onPress={send} />
        {!!status && <Text style={s.status}>{status}</Text>}
      </View>
      <View style={s.card}>
        <Text style={s.h}>Key (backup!)</Text>
        <Text style={s.wif} selectable>{key_.wif}</Text>
        <Btn t="Remove wallet from device" onPress={wipe} danger />
      </View>
    </View>
  );
}

/* ================= STAKE ================= */
function Stake({ key_, stats }) {
  const [info, setInfo] = useState(null), [stakes, setStakes] = useState([]);
  const [amt, setAmt] = useState(""), [blocks, setBlocks] = useState("4320");
  const [status, setStatus] = useState("");
  const refresh = () => {
    api.stakeinfo().then(setInfo).catch(() => {});
    api.stakes().then(setStakes).catch(() => {});
  };
  useEffect(refresh, []);
  const myStakes = key_ ? stakes.filter(x => x.owner_pkh === b2hex(key_.pkh)) : [];

  const lock = async () => {
    setStatus("building lock tx…");
    try {
      const sats = Math.round(parseFloat(amt) * 1e8);
      const bl = parseInt(blocks, 10);
      if (!sats || sats <= 0) throw new Error("bad amount");
      if (!bl || bl < 1) throw new Error("bad lock blocks");
      const u = await api.utxos(key_.addr);
      const unlock = (stats ? stats.height : 0) + bl;
      const raw = buildStakeTx(u.utxos || [], key_, unlock, sats);
      const r = await api.broadcast(raw);
      if (r.error) throw new Error(r.error);
      setStatus("✓ locked! stake_id " + String(r.result || r).slice(0, 20) + "…");
      setTimeout(refresh, 3000);
    } catch (e) { setStatus("✗ " + e.message); }
  };
  const unstake = async (st) => {
    setStatus("unlocking…");
    try {
      const u = await api.utxos(key_.addr);
      // find the locked outpoint — scriptPubKey = stakeSpk(unlock, pkh)
      const want = b2hex(stakeSpk(st.unlock_height, key_.pkh));
      const out = (u.utxos || []).find(x => x.scriptPubKey === want);
      if (!out) throw new Error("locked output not found (already spent?)");
      const raw = buildUnstakeTx({ ...out, txid: st.stake_id, vout: 0 },
        key_, st.unlock_height, key_.pkh);
      const r = await api.broadcast(raw);
      if (r.error) throw new Error(r.error);
      setStatus("✓ unstaked! txid " + String(r.result || r).slice(0, 20) + "…");
      setTimeout(refresh, 3000);
    } catch (e) { setStatus("✗ " + e.message); }
  };

  return (
    <View>
      <View style={s.card}>
        <Text style={s.h}>Alpha Staking — lock &amp; earn</Text>
        <Text style={s.dim}>Real CLTV lock: coins are unspendable by anyone
          until the unlock height. Rewards via stakedistribute, pro-rata.
          Staking is a yield layer — Alpha stays proof-of-work.</Text>
        {info && <Text style={s.statLine}>{info.total_staked_alpha} α locked · {info.positions} positions</Text>}
      </View>
      {key_ ? (
        <View style={s.card}>
          <Text style={s.h}>New lock</Text>
          <TextInput style={s.in} placeholder="amount ALPHA" placeholderTextColor="#666"
            value={amt} onChangeText={setAmt} keyboardType="decimal-pad" />
          <TextInput style={s.in} placeholder="lock blocks (4320 ≈ 30 days)" placeholderTextColor="#666"
            value={blocks} onChangeText={setBlocks} keyboardType="number-pad" />
          <Btn t="Lock (stake)" onPress={lock} />
          {!!status && <Text style={s.status}>{status}</Text>}
        </View>
      ) : <Text style={s.dimCenter}>create a wallet first</Text>}
      <View style={s.card}>
        <Text style={s.h}>Your positions</Text>
        {myStakes.length === 0 && <Text style={s.dim}>none</Text>}
        {myStakes.map(st => (
          <View key={st.stake_id} style={s.row}>
            <View style={{ flex: 1 }}>
              <Text style={s.mono}>{st.stake_id.slice(0, 16)}…</Text>
              <Text style={s.dim}>{st.amount_alpha} α · unlocks @ {st.unlock_height} · {st.status}</Text>
            </View>
            {st.status === "locked" && stats && stats.height >= st.unlock_height &&
              <Btn t="Unstake" onPress={() => unstake(st)} small />}
          </View>
        ))}
      </View>
    </View>
  );
}

/* ================= MINE ================= */
function Mine({ key_ }) {
  const [on, setOn] = useState(false);
  const [rate, setRate] = useState(0), [found, setFound] = useState(0);
  const [status, setStatus] = useState("idle — real SHA256d PoW, low hashrate on phone");
  const stop = useRef(false);
  const mining = useRef(false);

  const start = async () => {
    if (!key_) { Alert.alert("Wallet needed", "create a wallet first — rewards go to your address"); return; }
    stop.current = false; setOn(true); mining.current = true;
    let nonce = 0, hps = 0;
    const mine = async () => {
      try {
        const w = await api.minework(key_.addr);
        const hdr = hexToB(w.data), target = BigInt("0x" + w.target);
        const t0 = Date.now(); let n = nonce;
        // ~400ms chunks so the UI stays alive
        while (!stop.current && Date.now() - t0 < 400 && n < 0xffffffff) {
          const full = new Uint8Array(80); full.set(hdr);
          full[76] = n & 255; full[77] = (n >> 8) & 255;
          full[78] = (n >> 16) & 255; full[79] = (n >> 24) & 255;
          if (hashAsLEint(sha256d(full)) <= target) {
            const r = await api.submitwork(w.workid, n);
            if (r.error) setStatus("✗ " + r.error);
            else { setFound(f => f + 1); setStatus("🎉 BLOCK FOUND · height " + w.height); }
          }
          n++; hps++;
        }
        nonce = 0; // template refreshed each round
      } catch (e) { setStatus("✗ " + e.message); }
      if (!stop.current) {
        setRate(r => Math.round((hps * 2.5) / 1000 * 10) / 10); hps = 0;
        setTimeout(mine, 60);
      } else { mining.current = false; }
    };
    mine();
  };
  const halt = () => { stop.current = true; setOn(false); setStatus("stopped"); };

  return (
    <View>
      <View style={s.card}>
        <Text style={s.h}>Mobile mining</Text>
        <Text style={s.dim}>Real SHA256d proof-of-work against your own
          address. Honest note: a phone is tiny next to ASICs — this is for
          learning/network support, not profit. Watch battery &amp; heat.</Text>
        <Text style={s.statLine}>~{rate} kH/s · blocks found: {found}</Text>
        {on ? <Btn t="Stop mining" onPress={halt} danger />
            : <Btn t="Start mining" onPress={start} />}
        <Text style={s.status}>{status}</Text>
      </View>
    </View>
  );
}

/* ================= UI bits ================= */
const Btn = ({ t, onPress, alt, danger, small }) => (
  <TouchableOpacity onPress={onPress}
    style={[s.btn, alt && s.btnAlt, danger && s.btnDanger, small && { paddingVertical: 6, paddingHorizontal: 12 }]}>
    <Text style={s.btnTxt}>{t}</Text>
  </TouchableOpacity>
);
const s = StyleSheet.create({
  root: { flex: 1, backgroundColor: "#0d1117" },
  header: { flexDirection: "row", justifyContent: "space-between", alignItems: "center",
    padding: 14, borderBottomWidth: 1, borderColor: "#21262d" },
  brand: { color: "#f7931a", fontSize: 18, fontWeight: "700" },
  net: { color: "#7d8590", fontSize: 12 },
  card: { margin: 12, padding: 16, backgroundColor: "#161b22",
    borderRadius: 12, borderWidth: 1, borderColor: "#21262d" },
  h: { color: "#e6edf3", fontSize: 16, fontWeight: "700", marginBottom: 8 },
  dim: { color: "#7d8590", fontSize: 13, lineHeight: 19 },
  dimCenter: { color: "#7d8590", textAlign: "center", marginTop: 20 },
  bal: { color: "#f7931a", fontSize: 30, fontWeight: "800" },
  unit: { fontSize: 14, color: "#7d8590" },
  in: { backgroundColor: "#0d1117", borderWidth: 1, borderColor: "#30363d",
    borderRadius: 8, color: "#e6edf3", padding: 10, marginTop: 10, fontSize: 14 },
  btn: { backgroundColor: "#f7931a", borderRadius: 8, padding: 12,
    alignItems: "center", marginTop: 12 },
  btnAlt: { backgroundColor: "#30363d" },
  btnDanger: { backgroundColor: "#8b2f2f" },
  btnTxt: { color: "#fff", fontWeight: "700" },
  status: { color: "#58a6ff", marginTop: 10, fontSize: 12 },
  statLine: { color: "#e6edf3", marginTop: 8, fontWeight: "600" },
  mono: { color: "#e6edf3", fontFamily: "monospace", fontSize: 12 },
  wif: { color: "#ff7b72", fontSize: 11, fontFamily: "monospace" },
  row: { flexDirection: "row", alignItems: "center", marginTop: 10,
    borderTopWidth: 1, borderColor: "#21262d", paddingTop: 10 },
  tabs: { flexDirection: "row", borderTopWidth: 1, borderColor: "#21262d" },
  tab: { flex: 1, padding: 14, alignItems: "center" },
  tabOn: { backgroundColor: "#161b22" },
  tabTxt: { color: "#7d8590", fontWeight: "600" },
  tabTxtOn: { color: "#f7931a" },
});
