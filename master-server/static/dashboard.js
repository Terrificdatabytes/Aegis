'use strict';
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
let state={nodes:[],events:[],runs:[]},stage='all',sequence=false,selected='node-1',eventSignature='',lastOnline='';
const csrf=$('meta[name="csrf-token"]').content;
const names={data_breach:'Cloud data breach',identity_attack:'Identity attack',virtualization_threat:'Virtualization threat'};
const roles=['Synthetic data','Identity sandbox','Policy enforcement','Telemetry relay','Rehearsal standby'];
function text(tag,content,cls){const e=document.createElement(tag);e.textContent=content;if(cls)e.className=cls;return e;}
function toast(message,error=false){const t=$('#toast');t.textContent=message;t.className='fixed bottom-5 right-5 z-20 max-w-sm border border-console-muted bg-console-bg p-4 text-sm '+(error?'text-signal-amber':'text-console-text');clearTimeout(toast.timer);toast.timer=setTimeout(()=>t.classList.add('hidden'),5000);}
async function api(path,data){const r=await fetch(path,{method:data===undefined?'GET':'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:data===undefined?undefined:JSON.stringify(data)});if(r.status===401){location.reload();throw new Error('Session ended');}let result;try{result=await r.json();}catch{throw new Error('Unexpected server response');}if(!r.ok)throw new Error(result.error||'Request failed');return result;}
function renderNodes(){
 const online=state.nodes.filter(n=>n.online).length;
 $('#online-count').textContent=online;
 $('#node-summary').textContent=online===5?'All agents connected':`${online} of 5 agents connected`;
 const signature=state.nodes.map(n=>`${n.node_id}:${n.online}`).join('|');
 $('#nodes').replaceChildren(...state.nodes.map((n,i)=>{
  const row=text('div','','grid grid-cols-2 items-center gap-x-3 gap-y-2 border-b border-console-line py-3 md:grid-cols-node');
  row.setAttribute('role','listitem');
  const identity=text('div','','flex items-center gap-3');
  identity.append(text('span','','h-1.5 w-1.5 shrink-0 rounded-full '+(n.online?'bg-signal-cyan':'bg-console-muted')),text('span',n.node_id,'font-mono text-sm'));
  const role=text('span',roles[i],'hidden text-sm text-console-muted md:block');
  const boundary=text('div','','order-3 col-span-2 flex gap-3 text-sm md:order-none md:col-span-1 md:block');
  boundary.append(text('span',n.online?'Online':'Offline',n.online?'text-signal-cyan':'text-console-muted'));
  row.append(identity,role,boundary,text('span',n.age_seconds===null?'—':`${n.age_seconds}s ago`,'text-right font-mono text-sm text-console-muted'));
  return row;
 }));
 if(signature!==lastOnline){lastOnline=signature;$('#target-node').replaceChildren(...state.nodes.map(n=>{const opt=text('option',`${n.node_id}: ${n.online?'online':'offline'}`);opt.value=n.node_id;opt.disabled=!n.online;return opt;}));if(!state.nodes.some(n=>n.node_id===selected&&n.online))selected=state.nodes.find(n=>n.online)?.node_id||'node-1';$('#target-node').value=selected;}updateButtons();}
function updateButtons(){const busy=state.runs.some(r=>(r.node_id===selected||r.target_node===selected)&&r.status==='running'),connected=state.nodes.some(n=>n.node_id===selected&&n.online);$$('[data-scenario]').forEach(b=>b.disabled=sequence||busy||!connected);$('#run-all').disabled=sequence||busy||!connected;$('#reset').disabled=sequence||state.runs.some(r=>r.status==='running');$('#target-node').disabled=sequence;const peers=state.nodes.filter(n=>n.online).length; $('[data-scenario=virtualization_threat]').disabled ||= peers<2;$('#run-all').disabled ||= peers<2;}
function renderEvents(force=false){const severity=$('#severity-filter').value,filtered=[...state.events].sort((a,b)=>new Date(b.timestamp)-new Date(a.timestamp)||b.id-a.id).filter(e=>(stage==='all'||e.stage===stage)&&(severity==='all'||e.severity===severity));const signature=filtered.map(e=>e.id).join(',')+stage+severity;if(!force&&signature===eventSignature)return;eventSignature=signature;$('#event-total').textContent=`${filtered.length} displayed / ${state.events.length} recent events`;$('#nav-count').textContent=state.events.length;if(!filtered.length){
 const empty=text('div','','px-5 py-12');
 empty.append(text('h3',state.events.length?'No matching events.':'No incidents recorded.','text-base'),text('p',state.events.length?'Try another filter.':'Run a synthetic workload to inspect the enforcement evidence.','mt-2 text-sm text-console-muted'));
 $('#event-list').replaceChildren(empty);return;
 }
 const severityBorders={critical:'border-l-signal-red',high:'border-l-signal-amber',medium:'border-l-console-muted',low:'border-l-console-line'};
 const severityText={critical:'text-signal-red',high:'text-signal-amber',medium:'text-console-muted',low:'text-console-muted'};
 $('#event-list').replaceChildren(...filtered.map(e=>{
  const item=text('article','','event border-b border-console-line border-l-4 px-4 py-3 '+severityBorders[e.severity]);
  const header=text('div','','flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1');
  const value=text('div','','flex flex-wrap items-baseline gap-3');
  value.append(text('span',e.stage==='analyzing'?'Analysis':e.stage==='detected'?'Attack detected':'Attack prevented','text-sm font-medium '+(e.stage==='prevented'?'text-signal-cyan':'text-signal-amber')),text('span',e.severity,'font-mono text-sm '+severityText[e.severity]));
  header.append(value,text('time',new Date(e.timestamp).toLocaleTimeString('en-GB',{timeZone:'UTC'})+' UTC','font-mono text-sm text-console-muted'));
  const identity=text('div','','mt-2 flex flex-wrap gap-x-3 gap-y-1');
  identity.append(text('span',e.node_id,'font-mono text-sm'),text('span',names[e.event_type]||e.event_type,'text-sm text-console-muted'));
  const evidence=text('div','','mt-2 flex flex-wrap gap-x-2 text-sm');
  evidence.append(text('span','Control:','text-console-muted'),text('span',e.control_applied));
  item.append(header,identity,text('p',e.detail,'mt-2 break-words text-sm text-console-muted'),evidence);
  if(e.run_id){const run=text('div','','mt-2 flex min-w-0 gap-2 text-sm text-console-muted');run.append(text('span','Run'),text('span',e.run_id,'min-w-0 break-all font-mono text-sm'));item.append(run);}
  return item;
 }));}
async function poll(){try{state=await api('/api/state');$('#connection').replaceChildren(text('i','','h-1.5 w-1.5 rounded-full bg-signal-cyan'),document.createTextNode('Live updates'));renderNodes();$('#detected-count').textContent=state.metrics.detected;$('#prevented-count').textContent=state.metrics.prevented;$('#critical-count').textContent=state.metrics.critical;renderEvents();if(!sequence){const r=state.runs[0];$('#run-status').textContent=r?(r.status==='running'?`Running ${names[r.scenario]} on ${r.node_id}…`:r.status==='failed'?r.error:`Verified: ${names[r.scenario]} completed on ${r.node_id}`):'Select an online node and run a simulation.';}}catch(e){$('#connection').textContent='Connection interrupted';}finally{setTimeout(poll,1000);}}
async function runScenario(scenario){try{const r=await api('/api/run',{node_id:selected,scenario});state.runs.unshift(r);updateButtons();$('#run-status').textContent=`Running ${names[scenario]} on ${selected}…`;toast(`${names[scenario]} started on ${selected}`);return r.run_id;}catch(e){toast(e.message,true);throw e;}}
$$('[data-scenario]').forEach(b=>b.addEventListener('click',()=>runScenario(b.dataset.scenario).catch(()=>{})));
$('#target-node').addEventListener('change',e=>{selected=e.target.value;updateButtons();});
$$('[data-stage]').forEach(b=>b.addEventListener('click',()=>{stage=b.dataset.stage;$$('[data-stage]').forEach(x=>x.classList.toggle('active',x===b));renderEvents(true);}));
$('#severity-filter').addEventListener('change',()=>renderEvents(true));
$('#run-all').addEventListener('click',async()=>{sequence=true;updateButtons();try{for(const scenario of Object.keys(names)){const id=await runScenario(scenario);let complete=false;for(let i=0;i<60;i++){await new Promise(r=>setTimeout(r,1000));const latest=await api('/api/state'),run=latest.runs.find(r=>r.run_id===id);if(run?.status==='failed')throw new Error(run.error);if(run?.status==='completed'){complete=true;break;}}if(!complete)throw new Error('Scenario timed out. Check the node connection.');}toast('All three scenarios verified. Four incidents prevented.');}catch(e){toast(e.message,true);}finally{sequence=false;updateButtons();}});
$('#reset').addEventListener('click',async()=>{if(!confirm('Clear the incident log and reset connected agents?'))return;$('#reset').disabled=true;try{await api('/api/reset',{});eventSignature='';toast('Demo reset. All connected policies are ready.');}catch(e){toast(e.message,true);}finally{updateButtons();}});
$('#logout').addEventListener('click',async()=>{try{await api('/api/logout',{});location.reload();}catch(e){toast(e.message,true);}});
$('#export').addEventListener('click',()=>{const blob=new Blob([JSON.stringify(state.events,null,2)],{type:'application/json'}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='aegis-events.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
const configs={overview:['Security overview','Your distributed environment, protected in real time.'],events:['Event explorer','Inspect the latest 300 security events. Export the feed for review.'],nodes:['Infrastructure','Five isolated agents. Signed communication. Continuous health checks.'],controls:['Defense controls','Transparent, testable defensive policies — without production claims.']};
$$('[data-view]').forEach(b=>b.addEventListener('click',()=>{const view=b.dataset.view;$$('[data-view]').forEach(x=>x.classList.toggle('active',x===b));$('#view-title').textContent=configs[view][0];$('#current-view').textContent=configs[view][0];$('#view-subtitle').textContent=configs[view][1];$('#node-section').classList.toggle('hidden',!['overview','nodes'].includes(view));$('#lower-grid').classList.toggle('hidden',!['overview','events'].includes(view));$('#scenario-section').classList.toggle('hidden',view==='events');$('#controls-section').classList.toggle('hidden',view!=='controls');$('#lower-grid').classList.toggle('xl:grid-cols-operations',view!=='events');}));
function clock(){$('#clock').textContent=new Date().toLocaleTimeString('en-GB',{timeZone:'UTC'})+' UTC';}clock();setInterval(clock,1000);poll();
