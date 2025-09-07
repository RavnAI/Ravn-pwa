// ====== Konfig ======
const OFFENTLIG_BASE = "https://quebec-thousands-webmasters-hiring.trycloudflare.com";

// ====== Helper ======
const $ = s => document.querySelector(s);
const ls = {
  get:(k,d)=>{ try{return JSON.parse(localStorage.getItem(k));}catch{return d;}},
  set:(k,v)=>localStorage.setItem(k, JSON.stringify(v))
};
if ('serviceWorker' in navigator) { navigator.serviceWorker.register('./sw.js'); }

// ====== Identitet + invite ======
function uid(){ return 'RAVN-' + Math.random().toString(36).slice(2,8).toUpperCase(); }
function ensureId(){
  let id = ls.get('ravn.id'); if(!id){ id = uid(); ls.set('ravn.id', id); }
  $('#myId').value = id;
  const payload = btoa(JSON.stringify({id}));
  const base = OFFENTLIG_BASE || (location.origin + location.pathname);
  const link = `${base}?invite=${encodeURIComponent(payload)}`;
  $('#inviteLink').value = link;
  return id;
}

// ====== Deling / SMS ======
async function shareLink(url, text='Installer Ravn PWA'){
  if(navigator.share){ try{ await navigator.share({title:'Ravn PWA', text, url}); return; }catch(e){} }
  await navigator.clipboard.writeText(url);
  alert('Lenke kopiert til utklippstavlen');
}
function normalizePhone(raw){ return (raw||'').replace(/[^\d+]/g,''); }
function smsInvite(number, link){
  const body = encodeURIComponent(`Hei! Bli med i Ravn. Åpne og installer: ${link}`);
  location.href = `sms:${encodeURIComponent(number)}?&body=${body}`;
}
function smsOpen(number, text){
  const body = encodeURIComponent(text || '');
  location.href = `sms:${encodeURIComponent(number)}?&body=${body}`;
}

// ====== Lokalt register ======
function loadRegistry(){ return ls.get('ravn.registry', {}) || {}; }
function saveRegistry(reg){ ls.set('ravn.registry', reg); renderRegistry(); }
function setRegistry(number, status){
  const n = normalizePhone(number); if(!n) return;
  const reg = loadRegistry(); reg[n] = { status, updated: Date.now() }; saveRegistry(reg);
}
function renderRegistry(){
  const box = $('#registry'); box.innerHTML='';
  const reg = loadRegistry();
  Object.keys(reg).sort((a,b)=>reg[b].updated - reg[a].updated).forEach(num=>{
    const div = document.createElement('div'); div.className='item';
    div.innerHTML = `<div><strong>${num}</strong><div class="small">${new Date(reg[num].updated).toLocaleString()}</div></div>
                     <span class="badge">${reg[num].status.toUpperCase()}</span>`;
    box.appendChild(div);
  });
}

// ====== Kontaktplukker ======
async function pickContact(){
  if(!('contacts' in navigator) || !('select' in navigator.contacts)){
    alert('Kontaktplukker støttes ikke i denne nettleseren. Skriv inn nummer manuelt.'); return;
  }
  try{
    const [c] = await navigator.contacts.select(['name','tel'], {multiple:false});
    if(c?.tel?.[0]) $('#phone').value = c.tel[0];
  }catch(e){}
}

// ====== Parser-SMS (Termux) ======
async function sendViaParser(to, text){
  to = normalizePhone(to);
  try{
    const res = await fetch('http://127.0.0.1:5000/sms', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({to, text})
    });
    const js = await res.json().catch(()=>({}));
    if(!res.ok || js.ok===false){ throw new Error(js.error || 'Ukjent parser-feil'); }
    alert('✅ SMS sendt via parser');
  }catch(e){
    alert('Parser ikke tilgjengelig. Åpner SMS-app i stedet.');
    smsOpen(to, text);
  }
}

// ====== WebRTC: DataChannel (kryptert) ======
const b64u = {
  enc: buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''),
  dec: str => Uint8Array.from(atob(str.replace(/-/g,'+').replace(/_/g,'/')), c=>c.charCodeAt(0))
};
let dcPC=null, dcChan=null, myKP=null, myPriv=null, aesKey=null;

async function ecEnsure(){
  let kp = ls.get('ravn.kp');
  if(!kp){
    const kk = await crypto.subtle.generateKey({name:'ECDH', namedCurve:'P-256'}, true, ['deriveKey','deriveBits']);
    const pub = await crypto.subtle.exportKey('jwk', kk.publicKey);
    const priv = await crypto.subtle.exportKey('jwk', kk.privateKey);
    kp = {pub, priv}; ls.set('ravn.kp', kp);
  }
  myKP = kp;
  myPriv = await crypto.subtle.importKey('jwk', kp.priv, {name:'ECDH', namedCurve:'P-256'}, true, ['deriveKey','deriveBits']);
}
async function deriveAES(friendPubJwk){
  const friendPub = await crypto.subtle.importKey('jwk', friendPubJwk, {name:'ECDH', namedCurve:'P-256'}, true, []);
  return await crypto.subtle.deriveKey({name:'ECDH', public: friendPub}, myPriv, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);
}
async function aesEnc(text){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, aesKey, new TextEncoder().encode(text));
  return {iv:b64u.enc(iv), ct:b64u.enc(ct)};
}
async function aesDec(payload){
  const iv=b64u.dec(payload.iv), ct=b64u.dec(payload.ct);
  const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv}, aesKey, ct);
  return new TextDecoder().decode(pt);
}
function pushMsg(t){ const box=$('#msgs'); const d=document.createElement('div'); d.className='msg'; d.textContent=t; box.appendChild(d); box.scrollTop=box.scrollHeight; }

function dcCreatePC(){
  dcPC = new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});
  dcPC.onicecandidate = e=>{ if(!e.candidate){ $('#sdpOut').value = JSON.stringify({sdp:dcPC.localDescription, pub: myKP.pub}); } };
  dcPC.ondatachannel = e=>{ dcChan=e.channel; bindDC(); };
}
function bindDC(){
  dcChan.onopen = ()=>{ pushMsg('[system] DataChannel åpen'); $('#e2eStatus').textContent='Venter på nøkkel…'; dcChan.send(JSON.stringify({type:'hello', pub: myKP.pub})); };
  dcChan.onmessage = async (e)=>{
    try{
      const m = JSON.parse(e.data);
      if(m.type==='hello' && m.pub){
        aesKey = await deriveAES(m.pub);
        $('#e2eStatus').textContent='🔒 E2E aktiv (AES-GCM-256)';
      }else if(m.type==='cipher' && aesKey){
        const t = await aesDec(m.payload); pushMsg('[peer] '+t);
      }else{
        pushMsg('[peer-raw] '+e.data);
      }
    }catch{ pushMsg('[peer] '+e.data); }
  };
}
async function startDC(){
  await ecEnsure(); dcCreatePC();
  dcChan = dcPC.createDataChannel('ravn'); bindDC();
  const offer = await dcPC.createOffer(); await dcPC.setLocalDescription(offer);
}
async function acceptOffer(){
  await ecEnsure(); dcCreatePC();
  const payload = JSON.parse($('#sdpIn').value.trim()); // {sdp, pub}
  await dcPC.setRemoteDescription(payload.sdp);
  const answer = await dcPC.createAnswer(); await dcPC.setLocalDescription(answer);
  $('#sdpOut').value = JSON.stringify({sdp: dcPC.localDescription, pub: myKP.pub});
  aesKey = await deriveAES(payload.pub);
  $('#e2eStatus').textContent='🔒 E2E aktiv (AES-GCM-256)';
}
async function applyAnswer(){
  const payload = JSON.parse($('#sdpIn').value.trim()); // {sdp, pub}
  await dcPC.setRemoteDescription(payload.sdp);
  aesKey = await deriveAES(payload.pub);
  $('#e2eStatus').textContent='🔒 E2E aktiv (AES-GCM-256)';
}
async function sendCipher(){
  const t = $('#msg').value.trim(); if(!t) return;
  if(!dcChan || dcChan.readyState!=='open'){ alert('DataChannel ikke åpen'); return; }
  if(!aesKey){ alert('E2E-nøkkel ikke etablert'); return; }
  const payload = await aesEnc(t);
  dcChan.send(JSON.stringify({type:'cipher', payload}));
  pushMsg('[meg] '+t); $('#msg').value='';
}

// ====== WebRTC A/V ======
let avPC=null, localStream=null;
function clog(s){ $('#callLog').textContent = s; }
function avCreatePC(){
  avPC = new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});
  avPC.onicecandidate = e=>{ if(!e.candidate){ $('#callOut').value = JSON.stringify({sdp:avPC.localDescription}); } };
  avPC.ontrack = (ev)=>{ $('#remoteVideo').srcObject = ev.streams[0]; };
}
async function startCall(){
  avCreatePC();
  try{
    localStream = await navigator.mediaDevices.getUserMedia({audio:true, video:true});
    $('#localVideo').srcObject = localStream;
    localStream.getTracks().forEach(t=>avPC.addTrack(t, localStream));
  }catch(e){ alert('Krever kamera/mikrofon-tilgang'); return; }
  const offer = await avPC.createOffer(); await avPC.setLocalDescription(offer);
  clog('Offer laget – del payload.');
}
async function answerCall(){
  avCreatePC();
  try{
    localStream = await navigator.mediaDevices.getUserMedia({audio:true, video:true});
    $('#localVideo').srcObject = localStream;
    localStream.getTracks().forEach(t=>avPC.addTrack(t, localStream));
  }catch(e){ alert('Krever kamera/mikrofon-tilgang'); return; }
  const payload = JSON.parse($('#callIn').value.trim()); // {sdp}
  await avPC.setRemoteDescription(payload.sdp);
  const answer = await avPC.createAnswer(); await avPC.setLocalDescription(answer);
  $('#callOut').value = JSON.stringify({sdp: avPC.localDescription});
  clog('Answer laget – send tilbake.');
}
async function finalizeCall(){
  const payload = JSON.parse($('#callIn').value.trim()); // {sdp}
  await avPC.setRemoteDescription(payload.sdp);
  clog('Forbindelse etablert.');
}

// ====== UI ======
document.addEventListener('DOMContentLoaded', ()=>{
  ensureId(); renderRegistry();

  $('#copyId').onclick = ()=> navigator.clipboard.writeText($('#myId').value);
  $('#copyInvite').onclick = ()=> navigator.clipboard.writeText($('#inviteLink').value);
  $('#shareInvite').onclick = ()=> shareLink($('#inviteLink').value);
  $('#shareAny').onclick = ()=> shareLink(OFFENTLIG_BASE || (location.origin + location.pathname));

  $('#pickContact').onclick = pickContact;
  $('#checkNumber').onclick = ()=>{
    const n = normalizePhone($('#phone').value); if(!n){ alert('Skriv inn nummer'); return; }
    const reg = loadRegistry();
    $('#result').textContent = reg[n]?.status
      ? (reg[n].status==='ravn' ? '✅ Har Ravn (lokalt markert)' : reg[n].status==='invited' ? '🟡 Invitert' : '❔ Ukjent')
      : '❔ Ikke kjent. Send invitasjon eller merk som Ravn.';
  };
  $('#inviteSMS').onclick = ()=>{
    const n = normalizePhone($('#phone').value); if(!n){ alert('Skriv inn nummer'); return; }
    setRegistry(n,'invited'); smsInvite(n, $('#inviteLink').value);
  };
  $('#markRavn').onclick = ()=>{
    const n = normalizePhone($('#phone').value); if(!n){ alert('Skriv inn nummer'); return; }
    setRegistry(n,'ravn'); $('#result').textContent = '✅ Markert som Ravn (lokalt)';
  };

  $('#openSmsApp').onclick = ()=>{
    const to = normalizePhone($('#smsTo').value || $('#phone').value); if(!to){ alert('Mangler nummer'); return; }
    smsOpen(to, ($('#smsBody').value||'').trim());
  };
  $('#sendViaParser').onclick = ()=>{
    const to = normalizePhone($('#smsTo').value || $('#phone').value); if(!to){ alert('Mangler nummer'); return; }
    sendViaParser(to, ($('#smsBody').value||'').trim());
  };

  $('#startDC').onclick = startDC;
  $('#acceptOffer').onclick = acceptOffer;
  $('#setAnswer').onclick = applyAnswer;
  $('#sendMsg').onclick = sendCipher;

  $('#startCall').onclick = startCall;
  $('#answerCall').onclick = answerCall;
  $('#finalizeCall').onclick = finalizeCall;
});
