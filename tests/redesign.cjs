const {chromium}=require('playwright');
const assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch();const p=await browser.newPage({viewport:{width:1440,height:1080}});
 const errors=[];p.on('pageerror',e=>errors.push(e.message));p.on('response',r=>{if(r.status()>=400&&!r.url().endsWith('favicon.ico'))errors.push(`${r.status()} ${r.url()}`)});
 await p.goto('http://127.0.0.1:5000');await p.evaluate(()=>document.fonts.ready);
 await p.screenshot({path:'redesign/login.png',fullPage:true});
 await p.fill('#password',process.env.ADMIN_PASSWORD);await p.click('[type=submit]');
 await p.waitForFunction(()=>document.querySelector('#online-count')?.textContent==='5');await p.evaluate(()=>document.fonts.ready);
 await p.screenshot({path:'redesign/after.png',fullPage:true});
 const audit=await p.evaluate(()=>{
  const visible=[...document.querySelectorAll('body *')].filter(e=>e.getBoundingClientRect().width&&e.getBoundingClientRect().height);
  const leaves=visible.filter(e=>e.childElementCount===0&&e.textContent.trim());
  return {
   font: getComputedStyle(document.body).fontFamily,
   mono: getComputedStyle(document.querySelector('#clock')).fontFamily,
   sizes:[...new Set(leaves.map(e=>getComputedStyle(e).fontSize))],
   uppercase:visible.filter(e=>getComputedStyle(e).textTransform==='uppercase').length,
   dots:document.body.innerText.includes('·'),
   surfaces:visible.filter(e=>getComputedStyle(e).backgroundColor==='rgb(22, 27, 34)').map(e=>e.id||e.tagName),
   shadows:visible.filter(e=>getComputedStyle(e).boxShadow!=='none').length,
   border:getComputedStyle(document.querySelector('.event')).borderBottomColor,
   left:getComputedStyle(document.querySelector('.event')).borderLeftColor,
  };
 });
 assert.equal(audit.uppercase,0);assert.equal(audit.dots,false);assert.equal(audit.shadows,0);
 assert.deepEqual(audit.surfaces,['event-section']);assert.ok(audit.font.includes('IBM Plex Sans'));assert.ok(audit.mono.includes('IBM Plex Mono'));
 assert.ok(audit.sizes.every(s=>['14px','16px','24px','36px'].includes(s)));assert.equal(audit.border,'rgb(33, 38, 45)');
 await p.setViewportSize({width:390,height:844});await p.screenshot({path:'redesign/mobile.png',fullPage:true});
 assert.ok(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
 assert.deepEqual(errors,[]);console.log('Redesign audit passed',audit);await browser.close();
})().catch(e=>{console.error(e);process.exit(1)});
