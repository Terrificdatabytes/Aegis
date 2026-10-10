/* Real signed measurements and event-driven SVG. No synthetic resource curves. */
(() => {
 'use strict';
 const q=s=>document.querySelector(s), all=s=>[...document.querySelectorAll(s)];
 const NS='http://www.w3.org/2000/svg';
 let current={nodes:[],events:[],runs:[]}, data=null, visible=false, seconds=300, node='node-1';
 let pending=false, revision=0, nextFetch=0, serverOffset=0, visualId='', visualKey='', listKey='';
 let replaying=false, timers=[], animation=null, initialized=false, seen=new Set();
 const reduced=window.matchMedia('(prefers-reduced-motion: reduce)');
 const labels={data_breach:'Data breach',identity_attack:'Identity attack',virtualization_threat:'Peer boundary'};
 const color={detected:'text-signal-amber',analyzing:'text-signal-amber',prevented:'text-signal-cyan'};
 const stageName={detected:'Detected',analyzing:'Analysis',prevented:'Prevented'};
 const mono='font-mono text-sm', muted='text-console-muted';
 function el(tag,value='',cls=''){const e=document.createElement(tag);e.textContent=value;e.className=cls;return e;}
 function sv(tag,attrs={},parent){const e=document.createElementNS(NS,tag);for(const [k,v] of Object.entries(attrs))e.setAttribute(k,String(v));if(parent)parent.append(e);return e;}
 function st(parent,value,x,y,cls=mono+' fill-current text-console-muted',anchor='start'){
  const e=sv('text',{x,y,class:cls,'text-anchor':anchor},parent);e.textContent=value;return e;
 }
 const time=value=>new Date(value).toLocaleTimeString('en-GB',{timeZone:'UTC'});
 const epoch=s=>Date.parse(s.received_at||s.timestamp);
 const clock=()=>Date.now()+serverOffset;
 function bytes(value){return value>=1073741824?(value/1073741824).toFixed(2)+' GiB':(value/1048576).toFixed(1)+' MiB';}
 function age(sample){return sample?Math.max(0,Math.round((clock()-epoch(sample))/1000)):null;}
 function fresh(sample){return sample&&age(sample)<=8;}
 function nearest(series,t){let match=null,d=Infinity;for(const sample of series){const diff=Math.abs(epoch(sample)-t);if(diff<d){match=sample;d=diff;}}return d<=6000?match:null;}
 function groups(){
  const map=new Map();
  for(const event of current.events){
   if(!event.incident_id)continue;
   if(!map.has(event.incident_id))map.set(event.incident_id,{id:event.incident_id,events:[]});
   map.get(event.incident_id).events.push(event);
  }
  return [...map.values()].map(g=>{
   g.events.sort((a,b)=>['detected','analyzing','prevented'].indexOf(a.stage)-['detected','analyzing','prevented'].indexOf(b.stage)||a.id-b.id);
   const first=g.events.find(e=>e.stage==='detected')||g.events[0];
   g.source=first.source_node||first.node_id;g.type=first.event_type;g.run=first.run_id;
   g.target=current.runs.find(r=>r.run_id===g.run)?.target_node||g.events.find(e=>e.source_node&&e.node_id!==e.source_node)?.node_id;
   g.latest=Math.max(...g.events.map(epoch));return g;
  }).sort((a,b)=>b.latest-a.latest);
 }
 function chart(id,field,caption){
  const series=data?.samples[node]||[], end=clock(),start=end-seconds*1000;
  const width=580,height=250,left=48,right=15,top=16,bottom=40,w=width-left-right,h=height-top-bottom;
  const x=t=>left+(t-start)*w/(seconds*1000),y=v=>top+(100-v)*h/100;
  const root=sv('svg',{viewBox:`0 0 ${width} ${height}`,class:'block w-full',role:'img',tabindex:0,'aria-label':`${node} ${caption} over ${seconds/60} minutes. Arrow keys inspect samples.`, 'data-chart':field});
  [0,25,50,75,100].forEach(v=>{sv('line',{x1:left,x2:width-right,y1:y(v),y2:y(v),class:'stroke-current text-console-line'},root);st(root,String(v),left-10,y(v)+5,undefined,'end');});
  [0,.5,1].forEach(f=>st(root,time(start+seconds*1000*f),left+w*f,height-12,undefined,f===0?'start':f===1?'end':'middle'));
  let path='',previous=null;
  const shown=series.filter(s=>epoch(s)>=start&&epoch(s)<=end);
  shown.forEach(sample=>{
   const t=epoch(sample),value=sample[field];
   const verb=previous===null||t-previous>6000?'M':'L';
   path+=`${verb}${x(t).toFixed(2)},${y(value).toFixed(2)} `;previous=t;
  });
  if(shown.length){
   sv('path',{d:path,fill:'none',class:'stroke-current text-console-text','stroke-width':1.7,'data-series':node},root);
   const last=shown.at(-1);sv('circle',{cx:x(epoch(last)),cy:y(last[field]),r:3,class:'fill-current text-console-text'},root);
  }else st(root,'Waiting for measurements',left+12,top+h/2,'font-sans text-sm fill-current text-console-muted');
  // Incident receipt markers align with telemetry receipt times, not inferred CPU spikes.
  current.events.filter(e=>(e.node_id===node||e.source_node===node)&&epoch(e)>=start&&epoch(e)<=end).forEach(event=>{
   const px=x(epoch(event));sv('line',{x1:px,x2:px,y1:top,y2:top+h,class:`stroke-current ${color[event.stage]} opacity-40`,'stroke-dasharray':'3 4','data-incident-marker':event.incident_id||''},root);
  });
  const focus=sv('line',{x1:0,x2:0,y1:top,y2:top+h,class:'hidden stroke-current text-console-muted','stroke-dasharray':'2 3'},root);
  const readout=q(id==='cpu-graph'?'#cpu-readout':'#ram-readout');
  let index=Math.max(0,shown.length-1);
  function inspect(t){
   const sample=nearest(shown,t);focus.classList.remove('hidden');focus.setAttribute('x1',x(t));focus.setAttribute('x2',x(t));
   readout.textContent=sample?`${time(epoch(sample))} UTC  ${node}  ${sample[field].toFixed(1)}%${field==='ram_percent'?'  '+bytes(sample.ram_used_bytes)+' / '+bytes(sample.ram_total_bytes):''}`:`${time(t)} UTC  No sample within 6s`;
  }
  root.addEventListener('pointermove',ev=>{const rect=root.getBoundingClientRect(),px=(ev.clientX-rect.left)*width/rect.width;inspect(start+Math.max(0,Math.min(1,(px-left)/w))*seconds*1000);});
  root.addEventListener('focus',()=>{if(shown[index])inspect(epoch(shown[index]));});
  root.addEventListener('keydown',ev=>{if(!['ArrowLeft','ArrowRight'].includes(ev.key))return;ev.preventDefault();index=Math.max(0,Math.min(shown.length-1,index+(ev.key==='ArrowRight'?1:-1)));if(shown[index])inspect(epoch(shown[index]));});
  root.addEventListener('pointerleave',()=>focus.classList.add('hidden'));
  q('#'+id).replaceChildren(root);
  readout.textContent=shown.length?'Hover for a measurement. Dashed lines mark incident receipts.':'No history yet. Measurements appear as they arrive.';
 }
 function renderResources(){
  if(!data)return;
  const series=data.samples[node]||[], latest=series.at(-1);
  q('#cpu-current').replaceChildren(el('span',latest?latest.cpu_percent.toFixed(1)+'%':'—',mono+' text-2xl'),el('span',fresh(latest)?node:(latest?'Stale sample':'No sample'),'text-sm text-console-muted'));
  q('#ram-current').replaceChildren(el('span',latest?latest.ram_percent.toFixed(1)+'%':'—',mono+' text-2xl'),el('span',latest?bytes(latest.ram_used_bytes)+' / '+bytes(latest.ram_total_bytes):node,'text-sm font-mono text-console-muted'));
  chart('cpu-graph','cpu_percent','runtime CPU');chart('ram-graph','ram_percent','runtime RAM');
  const table=el('table','','w-full text-left text-sm');
  const thead=el('thead'),tr=el('tr','','border-b border-console-line');
  ['Node','Process CPU','Resident RAM','Host RAM','Sample age'].forEach(label=>tr.append(el('th',label,'py-3 pr-5 font-normal text-console-muted whitespace-nowrap')));thead.append(tr);table.append(thead);
  const tbody=el('tbody');
  current.nodes.forEach(n=>{
   const sample=(data.samples[n.node_id]||[]).at(-1),row=el('tr','','border-b border-console-line');
   [n.node_id,sample?sample.process_cpu_percent.toFixed(1)+'%':'—',sample?bytes(sample.process_rss_bytes):'—',sample?sample.ram_percent.toFixed(1)+'%':'—',sample?`${age(sample)}s${fresh(sample)?'':' / stale'}`:'No samples'].forEach(value=>row.append(el('td',value,'py-3 pr-5 whitespace-nowrap font-mono')));tbody.append(row);
  });table.append(tbody);q('#process-table').classList.add('overflow-x-auto');q('#process-table').replaceChildren(table);
  const received=Object.values(data.samples).flat().map(epoch),latestTime=received.length?Math.max(...received):null;
  q('#observability-updated').textContent=latestTime?`Latest signed sample: ${time(latestTime)} UTC. Age ${Math.max(0,Math.round((clock()-latestTime)/1000))}s. Window ${seconds/60}m.`:'No telemetry available in this window.';
 }
 function renderTimeline(){
  const host=q('#attack-timeline'), list=groups().slice(0,8);host.replaceChildren();
  if(!list.length){host.append(el('p','No incident evidence yet. Run a scenario from Overview.','py-5 text-sm text-console-muted'));return;}
  for(const group of list){
   const article=el('article','','border-t border-console-line py-4');
   const header=el('div','','flex flex-wrap items-center justify-between gap-3');
   const button=el('button',labels[group.type]||group.type,'text-base text-left hover:underline focus-visible:outline focus-visible:outline-console-text');
   button.addEventListener('click',()=>{visualId=group.id;stopReplay();renderVisual(true);q('#topology').scrollIntoView({behavior:reduced.matches?'auto':'smooth',block:'center'});});
   header.append(button,el('span',group.source+(group.target?' → '+group.target:''),mono+' text-console-muted'));article.append(header);
   const stages=el('div','','mt-3 grid gap-3 md:grid-cols-3');
   for(const stage of ['detected','analyzing','prevented']){
    const event=group.events.find(e=>e.stage===stage),part=el('div','','border-l-2 pl-3 '+(event?(stage==='prevented'?'border-signal-cyan':'border-signal-amber'):'border-console-line'));
    part.append(el('p',stageName[stage],event?color[stage]+' text-sm':'text-sm text-console-muted'));
    part.append(el('p',event?time(epoch(event))+' UTC':'Not observed',mono+' mt-1 text-console-muted'));
    if(event){
     part.append(el('p',event.node_id,mono+' mt-1'));
     const sample=nearest(data?.samples[event.node_id]||[],epoch(event));
     part.append(el('p',sample?`CPU ${sample.cpu_percent.toFixed(1)}% / RAM ${sample.ram_percent.toFixed(1)}%`:'No nearby resource sample',mono+' mt-1 text-console-muted'));
    }stages.append(part);
   }
   article.append(stages,el('p','Control: '+group.events.at(-1).control_applied,'mt-3 text-sm text-console-muted'));
   const run=el('p','','mt-2 flex flex-wrap gap-2 text-sm text-console-muted');run.append(el('span','Run'),el('span',group.run||'manual',mono+' break-all'));article.append(run);host.append(article);
  }
 }
 function stopReplay(){timers.forEach(clearTimeout);timers=[];if(animation)cancelAnimationFrame(animation);animation=null;replaying=false;}
 function drawTopology(group,event,motion=false){
  const width=900,height=310,root=sv('svg',{viewBox:`0 0 ${width} ${height}`,class:'min-w-topology w-full',role:'img','aria-label':'Master and five agents. '+(event?stageName[event.stage]+': '+event.detail:'No incident selected.')});
  const master={x:450,y:55},positions={};
  current.nodes.forEach((n,i)=>{positions[n.node_id]={x:90+i*180,y:185};});
  for(const n of current.nodes){const pt=positions[n.node_id];sv('path',{d:`M450 78 L${pt.x} 160`,class:'fill-none stroke-current '+(n.online?'text-console-muted':'text-console-line'),'stroke-dasharray':n.online?'none':'4 5'},root);}
  sv('rect',{x:390,y:30,width:120,height:48,class:'fill-none stroke-current text-console-muted'},root);
  st(root,'Master',450,60,'font-sans text-base fill-current text-console-text','middle');
  for(const n of current.nodes){const p=positions[n.node_id];
   sv('rect',{x:p.x-60,y:p.y-24,width:120,height:48,class:'fill-none stroke-current '+(n.online?'text-console-muted':'text-console-line')},root);
   sv('circle',{cx:p.x-42,cy:p.y,r:3,class:'fill-current '+(n.online?'text-signal-cyan':'text-console-muted')},root);
   st(root,n.node_id,p.x+4,p.y+5,mono+' fill-current text-console-text','middle');
   st(root,n.online?'Online':'Offline',p.x,p.y+49,'font-sans text-sm fill-current text-console-muted','middle');
  }
  st(root,'Management commands and signed telemetry',20,18,'font-sans text-sm fill-current text-console-muted');
  let route=null;
  if(group&&positions[group.source]){
   const from=positions[group.source],to=positions[group.target];
   const d=to?`M${from.x} 244 Q${(from.x+to.x)/2} 303 ${to.x} 244`:`M${from.x-36} 252 C${from.x-80} 305 ${from.x+80} 305 ${from.x+36} 252`;
   route=sv('path',{d,class:'fill-none stroke-current '+(event?color[event.stage]:'text-console-muted'),'stroke-width':2,'stroke-dasharray':event?.stage==='prevented'?'none':'5 4','data-attack-route':group.type},root);
   const label=to?`${group.source} → ${group.target}`:'Local sandbox request';st(root,label,to?(from.x+to.x)/2:from.x,305,mono+' fill-current text-console-muted','middle');
   if(event?.stage==='prevented'){
    const target=to||from;sv('line',{x1:target.x-12,y1:240,x2:target.x+12,y2:240,class:'stroke-current text-signal-cyan','stroke-width':3},root);
    const targetName=to?'Destination reports rejection':'Local request denied';st(root,targetName,450,115,'font-sans text-base fill-current text-signal-cyan','middle');
   }else if(event)st(root,'Observed '+stageName[event.stage].toLowerCase()+' event',450,115,'font-sans text-base fill-current text-signal-amber','middle');
  }
  q('#topology').replaceChildren(root);
  if(motion&&route&&!reduced.matches){
   const dot=sv('circle',{r:5,class:'fill-current '+(event?.stage==='prevented'?'text-signal-cyan':'text-signal-amber'),'data-motion':'evidence'},root),length=route.getTotalLength(),begin=performance.now();
   function tick(t){const progress=Math.min(1,(t-begin)/850),point=route.getPointAtLength(progress*length);dot.setAttribute('cx',point.x);dot.setAttribute('cy',point.y);if(progress<1)animation=requestAnimationFrame(tick);else{dot.remove();animation=null;}}
   animation=requestAnimationFrame(tick);
  }
  q('#visual-detail').textContent=event?`${stageName[event.stage]} at ${time(epoch(event))} UTC. Reporting node ${event.node_id}. ${event.detail}`:'Select an incident or run a scenario. This diagram never invents attack outcomes.';
 }
 function renderVisual(force=false){
  const list=groups(),signature=list.map(g=>g.id).join('|');
  if(signature!==listKey){listKey=signature;q('#visual-incident').replaceChildren(...list.map(g=>{const opt=el('option',`${labels[g.type]} / ${g.source} / ${time(g.latest)}`);opt.value=g.id;return opt;}));}
  if(!list.some(g=>g.id===visualId))visualId=list[0]?.id||'';
  q('#visual-incident').value=visualId;q('#replay-incident').disabled=!visualId||replaying;
  const group=list.find(g=>g.id===visualId),event=group?.events.at(-1);
  const key=visualId+(event?.id||'')+current.nodes.map(n=>n.online).join('');
  if(!replaying&&(force||key!==visualKey)){visualKey=key;drawTopology(group,event,false);q('#visual-mode').textContent=event?'Recorded evidence. Use replay to illustrate the observed stages.':'Waiting for signed incident evidence.';}
 }
 function replay(){
  const group=groups().find(g=>g.id===visualId);if(!group)return;stopReplay();replaying=true;q('#replay-incident').disabled=true;
  group.events.forEach((event,i)=>{timers.push(setTimeout(()=>{q('#visual-mode').textContent=`Replay of recorded evidence. Stage ${i+1} of ${group.events.length}. Animation is illustrative.`;drawTopology(group,event,true);},i*1250));});
  timers.push(setTimeout(()=>{replaying=false;q('#replay-incident').disabled=false;q('#visual-mode').textContent='Replay complete. No new attack was executed.';},group.events.length*1250));
 }
 async function fetchMetrics(){
  if(!visible||pending||Date.now()<nextFetch)return;
  pending=true;const requested=seconds,version=revision;
  try{
   const response=await fetch('/api/observability?seconds='+requested);if(!response.ok)throw Error('Telemetry unavailable');const next=await response.json();
   if(version!==revision)return;
   data=next;serverOffset=Date.parse(next.server_time)-Date.now();renderResources();renderTimeline();
  }catch(error){q('#observability-updated').textContent='Telemetry connection interrupted. Retained values are historical, not current.';}
  finally{pending=false;nextFetch=Date.now()+2000;if(version!==revision){nextFetch=0;fetchMetrics();}}
 }
 all('.obs-window').forEach(button=>button.addEventListener('click',()=>{seconds=Number(button.dataset.window);revision++;nextFetch=0;
  all('.obs-window').forEach(b=>{b.classList.toggle('border-console-text',b===button);b.classList.toggle('border-console-muted',b!==button);b.setAttribute('aria-pressed',String(b===button));});fetchMetrics();}));
 q('#observe-node').addEventListener('change',event=>{node=event.target.value;renderResources();});
 q('#visual-incident').addEventListener('change',event=>{visualId=event.target.value;stopReplay();renderVisual(true);});
 q('#replay-incident').addEventListener('click',replay);
 window.AegisObservability={
  onState(state){
   current=state;
   if(replaying&&!groups().some(g=>g.id===visualId))stopReplay();
   const freshEvents=initialized?state.events.filter(e=>!seen.has(e.id)):[];
   seen=new Set(state.events.map(e=>e.id));initialized=true;
   if(visible){
    renderVisual();fetchMetrics();
    const event=freshEvents.sort((a,b)=>a.id-b.id).at(-1);
    if(event?.incident_id&&!replaying&&Math.abs(clock()-epoch(event))<10000){
     visualId=event.incident_id;renderVisual(true);const group=groups().find(g=>g.id===visualId);
     if(animation)cancelAnimationFrame(animation);drawTopology(group,group.events.at(-1),true);q('#visual-mode').textContent='New signed evidence received. Showing the furthest observed stage; movement is illustrative.';
    }
   }
  },
  setVisible(value){visible=value;if(value){nextFetch=0;fetchMetrics();renderVisual(true);renderTimeline();}else stopReplay();},
  disconnected(){if(visible){q('#observability-updated').textContent='Master connection interrupted. Metrics and topology are last-known only.';q('#visual-mode').textContent='Disconnected. No live evidence is being inferred.';}}
 };
})();
