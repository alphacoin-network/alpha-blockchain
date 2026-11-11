// alphacrypto.js — self-contained crypto for Alpha Blockchain
// ported from website/wallet.html (sha256 / ripemd160 / base58 / secp256k1 / tx).
// No native deps — pure BigInt math. Import 'react-native-get-random-values'
// once at app start so crypto.getRandomValues exists.

/* ---------- sha256 ---------- */
const K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa4506ceb,0xbef9a3f7,0xc67178f2];
const H0=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
const rotr=(x,n)=>(x>>>n)|(x<<(32-n));
export function sha256(bytes){
  const l=bytes.length,pl=((l+9+63)>>6)<<6,b=new Uint8Array(pl);b.set(bytes);b[l]=0x80;
  const dv=new DataView(b.buffer);dv.setUint32(pl-4,l*8>>>0);
  const H=H0.slice(),w=new Uint32Array(64);
  for(let p=0;p<pl;p+=64){
    for(let j=0;j<16;j++)w[j]=dv.getUint32(p+j*4);
    for(let j=16;j<64;j++){
      const s0=rotr(w[j-15],7)^rotr(w[j-15],18)^(w[j-15]>>>3),s1=rotr(w[j-2],17)^rotr(w[j-2],19)^(w[j-2]>>>10);
      w[j]=(w[j-16]+s0+w[j-7]+s1)>>>0;}
    let[a,b2,c,d,e,f,g,h]=H;
    for(let j=0;j<64;j++){
      const t1=(h+(rotr(e,6)^rotr(e,11)^rotr(e,25))+((e&f)^(~e&g))+K[j]+w[j])>>>0;
      const t2=((rotr(a,2)^rotr(a,13)^rotr(a,22))+((a&b2)^(a&c)^(b2&c)))>>>0;
      h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b2;b2=a;a=(t1+t2)>>>0;}
    H[0]=(H[0]+a)>>>0;H[1]=(H[1]+b2)>>>0;H[2]=(H[2]+c)>>>0;H[3]=(H[3]+d)>>>0;
    H[4]=(H[4]+e)>>>0;H[5]=(H[5]+f)>>>0;H[6]=(H[6]+g)>>>0;H[7]=(H[7]+h)>>>0;}
  const o=new Uint8Array(32),od=new DataView(o.buffer);
  for(let i=0;i<8;i++)od.setUint32(i*4,H[i]);
  return o;
}
export const sha256d=b=>sha256(sha256(b));

/* ---------- ripemd160 ---------- */
const rl=[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13];
const rr=[5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11];
const sl=[11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
12,13,11,15,12,9,9,11,12,11,9,8,9,9,14,11,
9,12,11,12,9,13,15,12,11,13,11,12,7,13,9,9,
7,12,8,9,11,7,12,8,11,9,7,12,11,8,8,12,7,
13,11,9,13,15,14,8,13,6,15,14,11,11,11,12,9];
const sr=[8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11];
const rotl=(x,n)=>((x<<n)|(x>>>(32-n)))>>>0;
export function ripemd160(msg){
  const f=(j,x,y,z)=>j<16?(x^y^z):j<32?((x&y)|(~x&z)):j<48?((x|~y)^z):j<64?((x&z)|(y&~z)):(x^(y|~z));
  const kl=[0,0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xa953fd4e];
  const kr=[0x50a28be6,0x5c4dd124,0x6d703ef3,0x7a6d76e9,0];
  const l=msg.length,pl=((l+9+63)>>6)<<6;
  const b=new Uint8Array(pl);b.set(msg);b[l]=0x80;
  const dv=new DataView(b.buffer);dv.setUint32(pl-8,l*8>>>0,true);
  let h0=0x67452301,h1=0xefcdab89,h2=0x98badcfe,h3=0x10325476,h4=0xc3d2e1f0;
  for(let p=0;p<pl;p+=64){
    const X=new Uint32Array(16);
    for(let i=0;i<16;i++)X[i]=dv.getUint32(p+i*4,true);
    let al=h0,bl=h1,cl=h2,dl=h3,el=h4,ar=h0,br=h1,cr=h2,dr=h3,er=h4;
    for(let j=0;j<80;j++){
      const t=(rotl((al+f(j,bl,cl,dl)+X[rl[j]]+kl[j>>4])>>>0,sl[j])+el)>>>0;
      al=el;el=dl;dl=rotl(cl,10);cl=bl;bl=t;
      const t2=(rotl((ar+f(79-j,br,cr,dr)+X[rr[j]]+kr[j>>4])>>>0,sr[j])+er)>>>0;
      ar=er;er=dr;dr=rotl(cr,10);cr=br;br=t2;}
    const t=(h1+cl+dr)>>>0;
    h1=(h2+dl+er)>>>0;h2=(h3+el+ar)>>>0;h3=(h4+al+br)>>>0;
    h4=(h0+bl+cr)>>>0;h0=t;}
  const o=new Uint8Array(20),od=new DataView(o.buffer);
  [h0,h1,h2,h3,h4].forEach((x,i)=>od.setUint32(i*4,x,true));
  return o;
}
export const hash160=b=>ripemd160(sha256(b));

/* ---------- base58check ---------- */
const B58="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export function b58encCheck(payload){
  const data=new Uint8Array(payload.length+4);data.set(payload);
  data.set(sha256d(payload).slice(0,4),payload.length);
  let n=0n;for(const x of data)n=n*256n+BigInt(x);
  let s="";while(n>0n){s=B58[Number(n%58n)]+s;n/=58n;}
  for(const x of data){if(x===0)s="1"+s;else break;}return s;
}
export function b58decCheck(s){
  let n=0n;for(const ch of s)n=n*58n+BigInt(B58.indexOf(ch));
  const hex=n.toString(16);const a=[];
  for(let i=hex.length%2?-1:0;i<hex.length;i+=2)
    a.push(i<0?parseInt(hex[0],16):parseInt(hex.substr(i,2),16));
  for(const ch of s){if(ch==="1")a.unshift(0);else break;}
  const u=new Uint8Array(a);
  const chk=sha256d(u.slice(0,-4));
  for(let i=0;i<4;i++)if(chk[i]!==u[u.length-4+i])throw new Error("bad checksum");
  return u.slice(0,-4);
}

/* ---------- secp256k1 ---------- */
const P=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const Gx=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const Gy=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;
const mod=a=>((a%P)+P)%P, modN=a=>((a%N)+N)%N;
const _invm=(x,m)=>{let a=((x%m)+m)%m,b=m,u=1n,v=0n;while(b){const q=a/b;[a,b]=[b,a%b];[u,v]=[v,u-q*v];}return ((u%m)+m)%m;};
const inv=x=>_invm(x,P), invN=x=>_invm(x,N);
function padd(p,q){
  if(!p)return q;if(!q)return p;
  const[x1,y1]=p,[x2,y2]=q;
  if(x1===x2)return mod(y1+y2)===0n?null:pdouble(p);
  const m=mod(mod(y2-y1)*inv(x2-x1)),x3=mod(m*m-x1-x2);
  return[x3,mod(m*(x1-x3)-y1)];
}
function pdouble(p){
  if(!p)return null;const[x,y]=p;
  const m=mod(3n*x*x*inv(2n*y)),x3=mod(m*m-2n*x);
  return[x3,mod(m*(x-x3)-y)];
}
const pmult=(k,p=[Gx,Gy])=>{let r=null;while(k){if(k&1n)r=padd(r,p);p=pdouble(p);k>>=1n;}return r;};
export const b2hex=b=>[...b].map(x=>x.toString(16).padStart(2,"0")).join("");
export const hexToB=h=>{const a=new Uint8Array(h.length/2);for(let i=0;i<a.length;i++)a[i]=parseInt(h.substr(i*2,2),16);return a;};
const n2b=(n,len)=>{const a=new Uint8Array(len);for(let i=len-1;i>=0;i--){a[i]=Number(n&255n);n>>=8n;}return a;};
export const b2n=b=>{let n=0n;for(const x of b)n=(n<<8n)+BigInt(x);return n;};
export function privToPub(priv,compressed=true){
  const[x,y]=pmult(priv);
  if(!compressed)return Uint8Array.from([4,...n2b(x,32),...n2b(y,32)]);
  return Uint8Array.from([y&1n?3:2,...n2b(x,32)]);
}
export function ecdsaSign(z,priv){
  let k,r,s;
  do{
    const rb=crypto.getRandomValues(new Uint8Array(32));
    k=(b2n(rb)%(N-1n))+1n;[r]=pmult(k);r=r%N;
  }while(r===0n);
  s=(invN(k)*modN(b2n(z)+r*priv))%N;
  if(s>N/2n)s=N-s;
  const der=v=>{let b=n2b(v,32);let i=0;while(i<31&&b[i]===0&&!(b[i+1]&0x80))i++;b=b.slice(i);if(b[0]&0x80)b=Uint8Array.from([0,...b]);return b;};
  const dr=der(r),ds=der(s);
  return Uint8Array.from([0x30,4+dr.length+ds.length,2,dr.length,...dr,2,ds.length,...ds]);
}

/* ---------- keys / addresses / WIF ---------- */
export const randomPriv=()=>b2n(crypto.getRandomValues(new Uint8Array(32)))%(N-1n)+1n;
export const wifEncode=priv=>b58encCheck(Uint8Array.from([0x80,...n2b(priv,32),1]));
export function wifDecode(w){
  const d=b58decCheck(w);
  if(d[0]!==0x80)throw new Error("not a mainnet WIF");
  return b2n(d.slice(1,33));
}
export const addrFromPub=pub=>b58encCheck(Uint8Array.from([0,...hash160(pub)]));
export const spkP2pkh=pkh=>Uint8Array.from([0x76,0xa9,0x14,...pkh,0x88,0xac]);
export function addrToPkh(addr){
  const d=b58decCheck(addr);
  if(d.length!==21||d[0]!==0)throw new Error("legacy (1…) addresses only for now");
  return d.slice(1);
}

/* ---------- tx serialize / sign ---------- */
const varint=n=>{if(n<0xfd)return[n];if(n<=0xffff)return[0xfd,n&255,n>>8];
  if(n<=0xffffffff)return[0xfe,n&255,(n>>8)&255,(n>>16)&255,(n>>24)&255];
  throw new Error("varint too big");};
export const push=d=>varint(d.length).concat([...d]);
export const pushdata=d=>d.length<76?[d.length,...d]:
  d.length<256?[0x4c,d.length,...d]:[0x4d,d.length&255,(d.length>>8)&255,...d];
export const spkOpReturn=data=>Uint8Array.from([0x6a,...pushdata(data)]);

// serTx — opts: {sighashIdx, spk, seq, locktime}
export function serTx(ins,outs,opts={}){
  const {sighashIdx=-1,spk=null,seq=0xffffffff,locktime=0}=opts;
  const b=[2,0,0,0,...varint(ins.length)];
  for(let i=0;i<ins.length;i++){
    const x=ins[i];
    b.push(...x.txid.slice().reverse());
    b.push(x.vout&255,(x.vout>>8)&255,(x.vout>>16)&255,(x.vout>>24)&255);
    const ss=sighashIdx>=0?(i===sighashIdx?spk:[]):x.scriptSig;
    b.push(...varint(ss.length),...ss);
    const sq=x.seq!==undefined?x.seq:seq;
    b.push(sq&255,(sq>>8)&255,(sq>>16)&255,(sq>>24)&255);
  }
  b.push(...varint(outs.length));
  for(const o of outs){
    const v=BigInt(Math.round(o.value));
    for(let i=0;i<8;i++)b.push(Number((v>>BigInt(8*i))&255n));
    b.push(...varint(o.spk.length),...o.spk);
  }
  b.push(locktime&255,(locktime>>8)&255,(locktime>>16)&255,(locktime>>24)&255);
  if(sighashIdx>=0)b.push(1,0,0,0); // SIGHASH_ALL
  return new Uint8Array(b);
}
// sign each input as P2PKH (scriptSig = sig+pubkey); spkOf(i)=prevout script
export function signAll(ins,outs,key,spkOf,opts={}){
  const txins=ins.map(x=>({txid:x.txid,vout:x.vout,seq:x.seq,scriptSig:[]}));
  for(let i=0;i<txins.length;i++){
    const sighash=sha256d(serTx(txins,outs,{...opts,sighashIdx:i,spk:spkOf(i)}));
    const sig=Uint8Array.from([...ecdsaSign(sighash,key.priv),1]);
    txins[i].scriptSig=Uint8Array.from(push(sig).concat(push(key.pub)));
  }
  return b2hex(serTx(txins,outs,opts));
}
// simple send: pick largest-first P2PKH utxos, change back to self
export function buildSendTx(utxos,key,destPkh,sats,feeSats=1000){
  const myspk=b2hex(spkP2pkh(key.pkh));
  const mine=utxos.filter(u=>u.scriptPubKey===myspk);
  mine.sort((a,b)=>b.amount-a.amount);
  const ins=[];let sum=0;
  for(const u of mine){ins.push({txid:hexToB(u.txid),vout:u.vout});sum+=Math.round(u.amount*1e8);if(sum>=sats+feeSats)break;}
  if(sum<sats+feeSats)throw new Error("insufficient mature funds");
  const outs=[{value:sats,spk:spkP2pkh(destPkh)}];
  const change=sum-sats-feeSats;
  if(change>0)outs.push({value:change,spk:spkP2pkh(key.pkh)});
  return signAll(ins,outs,key,()=>spkP2pkh(key.pkh));
}

/* ---------- staking (STK + CLTV lock) ---------- */
// <unlock> CLTV DROP DUP HASH160 <pkh> EQUALVERIFY CHECKSIG
export function stakeSpk(unlock,pkh){
  const un=[];let u=unlock;
  while(u){un.push(u&255);u>>=8;}
  return Uint8Array.from([...pushdata(un),0xb1,0x75,0x76,0xa9,0x14,...pkh,0x88,0xac]);
}
export function encodeStake(unlock,pkh){
  return Uint8Array.from([0x53,0x54,0x4b,1,1,        // "STK" + ver + op
    unlock&255,(unlock>>8)&255,(unlock>>16)&255,(unlock>>24)&255,...pkh]);
}
export function buildStakeTx(utxos,key,unlock,sats,feeSats=1000){
  const myspk=b2hex(spkP2pkh(key.pkh));
  const mine=utxos.filter(u=>u.scriptPubKey===myspk);
  mine.sort((a,b)=>b.amount-a.amount);
  const ins=[];let sum=0;
  for(const u of mine){ins.push({txid:hexToB(u.txid),vout:u.vout});sum+=Math.round(u.amount*1e8);if(sum>=sats+feeSats)break;}
  if(sum<sats+feeSats)throw new Error("insufficient mature funds");
  const outs=[{value:sats,spk:stakeSpk(unlock,key.pkh)},
              {value:0,spk:spkOpReturn(encodeStake(unlock,key.pkh))}];
  const change=sum-sats-feeSats;
  if(change>0)outs.push({value:change,spk:spkP2pkh(key.pkh)});
  return signAll(ins,outs,key,()=>spkP2pkh(key.pkh));
}
// spend a matured CLTV stake output: seq=0xfffffffe, locktime=unlock
export function buildUnstakeTx(stakeUtxo,key,unlock,destPkh,feeSats=1000){
  const value=Math.round(stakeUtxo.amount*1e8);
  if(value<=feeSats)throw new Error("stake too small to spend");
  const ins=[{txid:hexToB(stakeUtxo.txid),vout:stakeUtxo.vout,seq:0xfffffffe}];
  const outs=[{value:value-feeSats,spk:spkP2pkh(destPkh)}];
  const lockspk=stakeSpk(unlock,key.pkh);
  return signAll(ins,outs,key,()=>lockspk,{seq:0xfffffffe,locktime:unlock});
}

/* ---------- mining helper ---------- */
export const hashAsLEint=h=>b2n(new Uint8Array([...h].reverse()));
