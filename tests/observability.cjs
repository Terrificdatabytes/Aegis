const {chromium}=require('playwright');
const assert=require('node:assert/strict');
(async()=>{
 const b=await chromium.launch(),p=await b.newPage({viewport:{width:1440,height:1080}}),errors=[];
 p.on('pageerror',e=>errors.push(e.message));
 await p.goto('http://127.0.0.1:5000');await p.fill('#password',process.env.ADMIN_PASSWORD);await p.click('[type=submit]');
 await p.waitForFunction(()=>document.querySelector('#online-count')?.textContent==='5',null,{timeout:20000});
 await p.click('[data-view=observability]');
 await p.waitForFunction(()=>document.querySelector('#cpu-graph path[data-series]'),null,{timeout:30000});
 assert.equal(await p.locator('#process-table tbody tr').count(),5);
 const state=await p.evaluate(()=>fetch('/api/observability?seconds=300').then(r=>r.json()));
 assert.ok(state.samples['node-1'].length>=1);assert.ok(state.samples['node-5'].length>=1);
 await p.selectOption('#observe-node','node-3');
 assert.equal(await p.locator('#cpu-graph path[data-series]').getAttribute('data-series'),'node-3');
 await p.locator('#cpu-graph svg').focus();await p.keyboard.press('ArrowLeft');
 assert.ok((await p.locator('#cpu-readout').textContent()).includes('node-3'));
 for(const seconds of [60,900,1800,300]){
  const response=p.waitForResponse(r=>r.url().includes('/api/observability?seconds='+seconds)&&r.status()===200);
  await p.click(`[data-window="${seconds}"]`);await response;
 }
 // Dispatch the same authorized command while staying on the observation view.
 const existing=Number(await p.locator('#detected-count').textContent());
 const result=await p.evaluate(()=>fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':document.querySelector('meta[name=csrf-token]').content},body:JSON.stringify({node_id:'node-1',scenario:'virtualization_threat'})}).then(r=>r.json()));
 assert.ok(result.run_id);
 await p.waitForFunction(b=>Number(document.querySelector('#detected-count').textContent)>b,existing,{timeout:20000});
 await p.waitForFunction(()=>document.querySelector('#visual-detail').textContent.includes('HTTP 401'),null,{timeout:20000});
 assert.ok(await p.locator('#topology [data-attack-route]').count());
 await p.click('#replay-incident');
 await p.waitForFunction(()=>document.querySelector('#visual-mode').textContent.includes('Replay complete'),null,{timeout:10000});
 assert.ok((await p.locator('#attack-timeline').textContent()).includes('Prevented'));
 await p.selectOption('#observe-node','node-1');await p.evaluate(()=>document.fonts.ready);
 await p.screenshot({path:'redesign/observability.png',fullPage:true});
 await p.setViewportSize({width:390,height:844});await p.screenshot({path:'redesign/observability-mobile.png',fullPage:true});
 assert.ok(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'No page-level horizontal overflow');
 await p.emulateMedia({reducedMotion:'reduce'});await p.click('#replay-incident');
 assert.equal(await p.locator('[data-motion]').count(),0);
 // Isolated browser fixtures test gaps and stale/empty states; never posted to the master.
 await p.route('**/api/observability?*',async route=>{
  const now=Date.now(),sample={node_id:'node-1',scope:'runtime-host',cpu_percent:10,ram_percent:20,ram_used_bytes:200,ram_total_bytes:1000,process_cpu_percent:0,process_rss_bytes:10,cpu_count:1};
  await route.fulfill({json:{server_time:new Date(now).toISOString(),samples:{'node-1':[50,20].map(age=>({...sample,timestamp:new Date(now-age*1000).toISOString(),received_at:new Date(now-age*1000).toISOString()}))}}});
 });
 await p.click('[data-window="60"]');
 await p.waitForFunction(()=>document.querySelector('#cpu-current').textContent.includes('Stale sample'),null,{timeout:10000});
 const path=await p.locator('#cpu-graph [data-series]').getAttribute('d');
 assert.equal((path.match(/M/g)||[]).length,2,'Gap must split the line');
 await p.selectOption('#observe-node','node-5');
 assert.ok((await p.locator('#cpu-graph').textContent()).includes('Waiting for measurements'));
 assert.equal(await p.locator('#cpu-graph [data-series]').count(),0);
 assert.deepEqual(errors,[]);console.log('Observability PASS: live samples, node and time filters, keyboard chart inspection, peer evidence animation/replay, timeline, mobile and reduced motion.');await b.close();
})().catch(e=>{console.error(e);process.exit(1)});
