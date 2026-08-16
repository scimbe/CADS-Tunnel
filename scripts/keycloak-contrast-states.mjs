// Interaktive Zustände messen: aufgeklapptes Sprachmenü, Fehlermeldung nach
// falschem Login, Feldvalidierung. Der bisherige Durchlauf hat sie nie gesehen —
// eine Prüfung, die einen Zustand nicht besucht, kann ihn auch nicht freisprechen.
import { chromium } from 'playwright';
const AUTH = 'https://auth.bunsenbrenner.org/realms/ct-demo/protocol/openid-connect/auth?client_id=ct-portal&redirect_uri=https%3A%2F%2Fbunsenbrenner.org%2Fportal%2Fcallback&response_type=code&scope=openid';
const rgb = s => (s||'').match(/\d+/g)?.slice(0,3).map(Number) ?? null;
const lum = c => { const f=c.map(v=>{v/=255;return v<=.03928?v/12.92:((v+.055)/1.055)**2.4;}); return .2126*f[0]+.7152*f[1]+.0722*f[2]; };
const ratio=(a,b)=>{const[x,y]=[lum(a),lum(b)].sort((p,q)=>q-p);return (x+.05)/(y+.05);};
const measure = async (page,label) => {
  const rows = await page.evaluate(() => {
    const out=[]; const opaque=v=>{const m=v.match(/rgba?\(([^)]+)\)/); if(!m)return false; const p=m[1].split(',').map(Number); return p.length<4||p[3]>=0.95;};
    document.querySelectorAll('body *').forEach(c=>{
      const t=(c.innerText||'').trim(); if(!t||t.length>70||c.children.length) return;
      const cs=getComputedStyle(c); if(cs.visibility==='hidden'||cs.display==='none'||parseFloat(cs.opacity)<.1) return;
      const r=c.getBoundingClientRect(); if(r.width===0||r.height===0) return;
      let bg='rgba(0, 0, 0, 0)',p=c; while(p&&!opaque(bg)){bg=getComputedStyle(p).backgroundColor;p=p.parentElement;}
      out.push({t:t.slice(0,38),fg:cs.color,bg,cls:(c.className||'').toString().slice(0,40),px:parseFloat(cs.fontSize),bold:parseInt(cs.fontWeight)>=700});
    });
    return out;
  });
  const seen=new Set(); const bad=[];
  for(const r of rows){const k=r.fg+r.bg+r.cls; if(seen.has(k))continue; seen.add(k);
    const f=rgb(r.fg),g=rgb(r.bg); if(!f||!g)continue; const c=ratio(f,g);
    const lim=(r.px>=24||(r.px>=18.66&&r.bold))?3:4.5;
    if(c<lim) bad.push(`${c.toFixed(2).padStart(6)}:1 (Grenze ${lim})  "${r.t}"  fg=${r.fg} bg=${r.bg} ${r.px}px  .${r.cls}`);}
  console.log(`\n### ${label} (${rows.length} sichtbare Textknoten)`);
  bad.length ? bad.forEach(b=>console.log('   '+b)) : console.log('   keine Beanstandung');
};
const b = await chromium.launch(); const page = await b.newPage({ ignoreHTTPSErrors:true, viewport:{width:1400,height:950} });

await page.goto(AUTH,{waitUntil:'networkidle'});
if (await page.locator('#kc-current-locale-link').count()) {
  await page.click('#kc-current-locale-link'); await page.waitForTimeout(600);
  await measure(page,'Sprachmenü aufgeklappt');
} else console.log('\n### Sprachmenü: Schalter nicht gefunden');

await page.goto(AUTH,{waitUntil:'networkidle'});
await page.fill('input[name="username"], #username','nicht-existent@example.org');
await page.fill('input[name="password"], #password','falschesPasswort123');
await page.click('input[type="submit"], #kc-login'); await page.waitForLoadState('networkidle');
await measure(page,'Fehlermeldung nach falschem Login');

await page.goto(AUTH,{waitUntil:'networkidle'});
await page.click('input[type="submit"], #kc-login').catch(()=>{}); await page.waitForTimeout(900);
await measure(page,'Leeres Formular abgeschickt');
await b.close();
