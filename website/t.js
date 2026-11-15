
if('serviceWorker' in navigator)navigator.serviceWorker.register('sw.js');
window.addEventListener('error',e=>{const g=document.getElementById('gateMsg');if(g)g.textContent='⚠ '+(e.message||'script error');});
window.addEventListener('unhandledrejection',e=>{const g=document.getElementById('gateMsg');if(g)g.textContent='⚠ '+(e.reason&&e.reason.message||e.reason||'async error');});
const KEY='alpha_mine_last';
let mining=false,nonces=0,found=0,t0=0,work=null,addr='';
const thr=Math.min(4,navigator.hardwareConcurrency||2);
document.getElementById('th').textContent=thr+' cores';
// prefill address + balance from HD wallet
try{const hd=JSON.parse(localStorage.getItem('alpha_hd')||'{}');
 if(hd.addrs&&hd.addrs[0]){document.getElementById('addr').value=hd.addrs[0];loadBal(hd.addrs[0]);}}catch(e){}
function hexToBytes(h){const b=new Uint8Array(h.length/2);for(let i=0;i<b.length;i++)b[i]=parseInt(h.substr(i*2,2),16);return b;}
function bytesToHex(b){return [...b].map(x=>x.toString(16).padStart(2,'0')).join('');}
function ltTarget(hashHex,tHex){
 const bytes=hexToBytes(hashHex).reverse(); // server: int.from_bytes(hash,'little')
 return BigInt('0x'+bytesToHex(bytes))<BigInt('0x'+tHex);
}
async function getWork(){
 const r=await fetch('/api/minework?address='+encodeURIComponent(addr));
 const d=await r.json();if(d.error)throw new Error(d.error);
 work={id:d.workid,prefix:hexToBytes(d.data),target:d.target,height:d.height};
}
let workers=[];
const WORKER_SRC=`
onmessage=async function(e){
 const{prefix,target,start,step}=e.data;
 const buf=new Uint8Array(80);buf.set(prefix,0);const dv=new DataView(buf.buffer);
 let n=start>>>0,count=0;
 const tB=target;
 function lt(hx){ // reverse bytes -> little-endian bigint compare
  let rev='';for(let i=62;i>=0;i-=2)rev+=hx.substr(i,2);
  return BigInt('0x'+rev)<BigInt('0x'+tB);
 }
 while(true){
  for(let k=0;k<2000;k++){
   dv.setUint32(76,(n+k*step)>>>0,true);
   const d1=await crypto.subtle.digest('SHA-256',buf);
   const d2=await crypto.subtle.digest('SHA-256',d1);
   count++;
   const u=new Uint8Array(d2);let hx='';for(let i=0;i<32;i++)hx+=u[i].toString(16).padStart(2,'0');
   if(lt(hx)){postMessage({found:(n+k*step)>>>0});}
  }
  n+=2000*step;
  postMessage({count:2000}); // delta per batch — main accumulates
 }
};`;
function spawnWorkers(){
 workers=[];
 const url=URL.createObjectURL(new Blob([WORKER_SRC],{type:'text/javascript'}));
 for(let i=0;i<thr;i++){
  const w=new Worker(url);
  w.onmessage=async ev=>{
   const d=ev.data;
   if(d.count!==undefined){nonces+=d.count;return;}
   if(d.found!==undefined&&work){
    const res=await submit(d.found);
    if(res.accepted){found++;document.getElementById('bf').textContent=found;
     document.getElementById('sess').innerHTML='<span class="pulse"></span>block '+res.height+'!';
     // restart workers with fresh template (old workers keep stale work)
     workers.forEach(w=>w.terminate());workers=[];
     await getWork();spawnWorkers();}
   }
  };
  w.postMessage({prefix:work.prefix,target:work.target,start:i,step:thr});
  workers.push(w);
 }
}
async function submit(n){
 const r=await fetch('/api/submitwork?workid='+work.id+'&nonce='+n);
 return r.json();
}