const api = p => fetch('/api/' + p).then(r => r.json());
const el = id => document.getElementById(id);
const short = h => h ? h.slice(0, 10) + '…' + h.slice(-8) : '—';
const fmt = n => Number(n).toLocaleString('en-US', { maximumFractionDigits: 8 });
const fmtHash = h => { h = Number(h);
  if (!isFinite(h) || h <= 0) return '—';
  const units = ['H/s','kH/s','MH/s','GH/s','TH/s','PH/s'];
  let u = 0; while (h >= 1000 && u < units.length - 1) { h /= 1000; u++; }
  return (h >= 100 ? Math.round(h) : h.toFixed(h >= 1 ? 2 : 4)) + ' ' + units[u]; };
const time = t => new Date(t * 1000).toLocaleString();
const ago = t => { const s = Math.max(0, Date.now() / 1000 - t);
  if (s < 60) return Math.floor(s) + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago'; };

function nav(active) {
  document.querySelector('nav').innerHTML = `
    <a class="brand" href="index.html"><img src="coin.svg" alt="alpha">Alpha Blockchain</a>
    <a href="index.html" ${active === 'home' ? 'class="active"' : ''}>Home</a>
    <a href="explorer.html" ${active === 'expl' ? 'class="active"' : ''}>Explorer</a>
    <a href="tokens.html" ${active === 'tok' ? 'class="active"' : ''}>Tokens</a>
    <a href="api.html" ${active === 'api' ? 'class="active"' : ''}>API</a>
    <a href="wallet.html" ${active === 'wallet' ? 'class="active"' : ''}>◈ Wallet</a>
    <a href="mine.html" ${active === 'mine' ? 'class="active"' : ''}>⛏ Mine</a>
    <a href="roadmap.html" ${active === 'rm' ? 'class="active"' : ''}>Roadmap</a>
    <a href="whitepaper.html" ${active === 'wp' ? 'class="active"' : ''}>Whitepaper</a>
    <div class="spacer"></div>
    <span class="chip" id="netchip">…</span>`;
  api('stats').then(s => {
    const c = el('netchip');
    if (c) c.textContent = `● ${s.chain} · ${fmt(s.height)} blocks`;
  }).catch(() => { const c = el('netchip'); if (c) c.textContent = 'node offline'; });
}

async function loadStats(targetId) {
  try {
    const s = await api('stats');
    el(targetId).innerHTML = `
      <div class="stat"><div class="k">Height</div><div class="v gold">${fmt(s.height)}</div></div>
      <div class="stat"><div class="k">Supply</div><div class="v gold">${fmt(s.supply)} α</div></div>
      <div class="stat"><div class="k">Difficulty</div><div class="v blue">${fmt(s.difficulty)}</div></div>
      <div class="stat"><div class="k">Hashrate</div><div class="v blue">${fmtHash(s.hashrate)}</div></div>
      <div class="stat"><div class="k">Mempool</div><div class="v green">${fmt(s.mempool)}</div></div>
      <div class="stat"><div class="k">Peers</div><div class="v green">${fmt(s.connections)}</div></div>
      <div class="stat"><div class="k">Tokens</div><div class="v gold">${fmt(s.tokens)}</div></div>
      <div class="stat"><div class="k">Network</div><div class="v blue">${s.chain}</div></div>`;
  } catch (e) {
    el(targetId).innerHTML = '<div class="loading">node offline — start alphad then alphaweb</div>';
  }
}
