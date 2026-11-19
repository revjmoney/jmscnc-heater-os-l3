'use strict';
const $=id=>document.getElementById(id), endpoint='cgi-bin/l3lab.cgi', KEEP='__KEEP_PASSWORD__';
let settings=null,draft=null,last=null,staged=null,busy=false;
const historyKey='l3lab-history-v1:'+location.host;
let history=[];try{history=JSON.parse(localStorage.getItem(historyKey)||'[]');if(!Array.isArray(history))history=[]}catch{}
const fmt=(n,d=0)=>n===null||n===undefined||!Number.isFinite(Number(n))?'—':Number(n).toLocaleString(undefined,{maximumFractionDigits:d});
const node=(tag,txt,cls)=>{const n=document.createElement(tag);if(txt!==undefined)n.textContent=txt;if(cls)n.className=cls;return n};
function notify(message,error=false){const box=$(error?'error':'message');box.textContent=message;box.hidden=false;if(!error)setTimeout(()=>box.hidden=true,12000)}
async function api(action,data){const init={cache:'no-store'};if(data!==undefined){init.method='POST';init.headers={'X-L3-CSRF':settings?.csrf||''};if(data instanceof FormData)init.body=data;else{init.headers['Content-Type']='application/json';init.body=JSON.stringify(data)}}const r=await fetch(endpoint+'?action='+encodeURIComponent(action),init);if(!r.ok){let body;try{body=await r.json()}catch{}throw Error(body?.error||'Request failed ('+r.status+')')}return r}
async function request(action,data){return(await api(action,data)).json()}
function setTheme(theme){document.documentElement.dataset.theme=theme;$('theme').textContent=theme==='dark'?'☀':'☾';try{localStorage.setItem('l3lab-theme',theme)}catch{}drawCharts()}
let theme='dark';try{theme=localStorage.getItem('l3lab-theme')||'dark'}catch{}setTheme(theme);
$('theme').onclick=()=>setTheme(document.documentElement.dataset.theme==='dark'?'light':'dark');
document.querySelectorAll('nav button').forEach(b=>b.onclick=()=>{document.querySelectorAll('.page').forEach(p=>p.hidden=p.id!==b.dataset.page);document.querySelectorAll('nav button').forEach(n=>n.classList.toggle('active',n===b));$('page-title').textContent=b.textContent.substring(2).trim();if(b.dataset.page==='settings')$('config-json').value=JSON.stringify(draft,null,2);if(b.dataset.page==='firmware')action(loadUpdateState);if(b.dataset.page==='support')action(loadDevSupport);drawCharts()});
async function review(title,changes,note=''){const dialog=$('review');$('review-title').textContent=title;$('review-body').textContent=changes;$('review-note').textContent=note;return new Promise(resolve=>{dialog.addEventListener('close',()=>resolve(dialog.returnValue==='save'),{once:true});dialog.showModal()})}
async function action(fn){try{await fn()}catch(e){notify(e.message,true)}}
function highTemp(s){const values=s.boards.map(b=>b.chip_temperature).filter(v=>typeof v==='number');return values.length?Math.max(...values):null}
function chart(id,values,color,label){const target=$(id);target.replaceChildren();const points=values.filter(p=>p.value!==null&&Number.isFinite(p.value));if(points.length<2){target.append(node('div','Collecting live samples…','chart-empty'));return}const W=650,H=220,L=47,R=14,T=15,B=30;let lo=Math.min(...points.map(p=>p.value)),hi=Math.max(...points.map(p=>p.value));const pad=Math.max((hi-lo)*.18,hi*.02,1);lo=Math.max(0,lo-pad);hi+=pad;const first=values[0].time,end=values[values.length-1].time;const x=t=>L+(t-first)/Math.max(1,end-first)*(W-L-R),y=v=>H-B-(v-lo)/(hi-lo)*(H-T-B);const ns='http://www.w3.org/2000/svg',svg=document.createElementNS(ns,'svg');svg.setAttribute('viewBox',`0 0 ${W} ${H}`);svg.setAttribute('role','img');svg.setAttribute('aria-label',label);const add=(tag,attrs,text)=>{const n=document.createElementNS(ns,tag);for(const[k,v]of Object.entries(attrs))n.setAttribute(k,v);if(text)n.textContent=text;svg.append(n);return n};for(let i=0;i<4;i++){const v=lo+(hi-lo)*i/3,py=y(v);add('line',{x1:L,y1:py,x2:W-R,y2:py,stroke:'var(--line)','stroke-dasharray':'3 5'});add('text',{x:L-8,y:py+3,'text-anchor':'end'},fmt(v,1))}let path='',previous=null;for(const p of values){if(p.value===null||!Number.isFinite(p.value)){previous=null;continue}const connected=previous!==null&&p.time-previous<=40;path+=(connected?'L':'M')+x(p.time).toFixed(1)+','+y(p.value).toFixed(1)+' ';previous=p.time}add('path',{d:path,fill:'none',stroke:color,'stroke-width':2.5,'stroke-linecap':'round','stroke-linejoin':'round'});for(const[t,anchor]of[[first,'start'],[end,'end']])add('text',{x:x(t),y:H-7,'text-anchor':anchor},new Date(t*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}));target.append(svg)}
function drawCharts(){if(!$('hash-chart'))return;const minutes=Number($('range').value||60),now=Date.now()/1000,rows=history.filter(p=>p.time>=now-minutes*60);chart('hash-chart',rows.map(p=>({time:p.time,value:p.hashrate})),'var(--accent)','Live hashrate in MH/s');chart('temp-chart',rows.map(p=>({time:p.time,value:p.temperature})),'var(--amber)','Highest chip temperature in Celsius')}
$('range').onchange=drawCharts;
function renderStatus(s){last=s;$('connection').textContent='● MINING API LIVE';$('preview-banner').hidden=!s.preview;$('hashrate').textContent=fmt(s.hashrate,2)+' MH/s';$('average').textContent='Average '+fmt(s.average_hashrate,2)+' MH/s';$('accepted').textContent=fmt(s.accepted);$('rejected').textContent=fmt(s.rejected)+' rejected · '+fmt(s.rejected_percent,2)+'%';$('temperature').textContent=fmt(highTemp(s))+' °C';$('hardware-errors').textContent=fmt(s.hardware_errors);$('uptime').textContent=Math.floor(s.elapsed/3600)+'h '+Math.floor(s.elapsed%3600/60)+'m mining uptime';$('frequency').textContent=fmt(s.frequency)+' MHz';$('raw-stats').textContent=JSON.stringify(s.raw,null,2);$('updated').textContent='Updated '+new Date(s.time*1000).toLocaleTimeString();$('board-summary').replaceChildren();$('board-detail').replaceChildren();for(const b of s.boards){const card=node('div',undefined,'board'),head=node('div',undefined,'board-head');head.append(node('span','Chain '+b.id),node('span',b.state,'state '+b.state.split(' ')[0]));card.append(head,node('div',fmt(b.chip_temperature)+' °C','board-value'),node('small',b.chips+' / 72 ASICs · '+fmt(b.temperature)+' °C board'));$('board-summary').append(card);const detail=node('div',undefined,'board-detail');detail.append(head.cloneNode(true),node('p',`${b.chips} detected ASICs · board ${fmt(b.temperature)} °C · chip ${fmt(b.chip_temperature)} °C · ${fmt(b.hashrate,2)} MH/s · ${fmt(b.hardware_errors)} hardware errors`,'subtle'));const chips=node('div',undefined,'chip-map');const chars=b.chip_status.replace(/\s/g,'').split('');for(let i=0;i<72;i++){const c=chars[i],chip=node('span',undefined,'chip '+(c==='o'?'ok':c==='x'?'bad':''));chip.title='ASIC '+(i+1)+': '+(c==='o'?'responding':c==='x'?'error':'no reported status');chips.append(chip)}detail.append(chips);$('board-detail').append(detail)}$('fans').replaceChildren();s.fans.forEach((rpm,i)=>{const fan=node('div',undefined,'fan');fan.append(node('span','Fan '+(i+1)),node('strong',fmt(rpm)+' RPM'));$('fans').append(fan)});$('pool-live').replaceChildren();for(const p of s.pools){const row=node('tr');for(const v of[p.url,(p.active?'Active · ':'')+p.status,fmt(p.accepted)+' / '+fmt(p.rejected)+' rejected',p.worker])row.append(node('td',v));$('pool-live').append(row)}const active=s.pools.find(p=>p.active)||s.pools.find(p=>p.status==='Alive');$('active-pool').replaceChildren();if(active)$('active-pool').append(node('strong',active.status+' · Pool '+(active.id+1)),node('div',active.url),node('div',active.worker,'subtle'));else $('active-pool').textContent='No active pool reported';if(!history.length||s.time-history[history.length-1].time>=8){history.push({time:s.time,hashrate:s.hashrate,temperature:highTemp(s)});history=history.filter(p=>p.time>Date.now()/1000-24*3600).slice(-8640);try{localStorage.setItem(historyKey,JSON.stringify(history))}catch{}}drawCharts();if(s.warnings.length&&$('error').hidden)notify(s.warnings.join(' · '),true)}
async function poll(){if(busy)return;busy=true;try{renderStatus(await request('status'))}catch(e){$('connection').textContent='● API OFFLINE';notify(e.message,true)}finally{busy=false}}
$('refresh').onclick=poll;setInterval(()=>{if(!document.hidden)poll()},15000);
function renderPools(){const parent=$('pool-edit');parent.replaceChildren();(draft?.pools||[]).forEach((pool,i)=>{const wrap=node('div',undefined,'pool-form'),h=node('h3','Pool '+(i+1)),remove=node('button','Remove');remove.onclick=()=>{draft.pools.splice(i,1);renderPools()};remove.disabled=!!settings.preview;h.append(remove);wrap.append(h);const grid=node('div',undefined,'form-grid');for(const[k,label]of[['url','Pool server address'],['user','Pool worker name'],['pass','Pool password']]){const l=node('label',label),input=node('input');input.type=k==='pass'?'password':'text';input.autocomplete=k==='pass'?'new-password':'off';input.value=pool[k]===KEEP?'':pool[k]||'';if(pool[k]===KEEP)input.placeholder='Stored password · leave unchanged';input.oninput=()=>pool[k]=input.value;input.disabled=!!settings.preview;const help=node('small',{url:'Copy the full mining server address from your pool, including its port.',user:'The account and worker name your pool expects, often account.worker.',pass:'Pool login password; leave a stored password unchanged unless replacing it.'}[k],'field-help');l.append(input,help);grid.append(l)}wrap.append(grid);parent.append(wrap)})}
$('add-pool').onclick=()=>{if(draft.pools.length>=16)return;draft.pools.push({url:'stratum+tcp://',user:'',pass:''});renderPools()};
function renderOptions(){
 if(!settings)return;
 const search=$('option-search').value.toLowerCase(),group=$('option-group').value,show=$('show-unavailable').checked;
 const selected=settings.options.filter(o=>(o.available||show)&&(!group||o.group===group)&&[o.name,o.label,o.description].join(' ').toLowerCase().includes(search));
 $('option-count').textContent=settings.options.filter(o=>o.available).length+' DISCOVERED';
 const root=$('option-list');root.replaceChildren();
 for(const o of selected){
  const row=node('div',undefined,'option'),info=node('div'),label=node('label',o.label||o.name,'option-label'),description=node('p',o.description,'option-description');
  label.htmlFor='option-'+o.name;description.id='option-help-'+o.name;
  const detail=node('small',undefined,'option-meta');detail.append(node('code',o.name),node('span',' · '+o.group+(o.source==='existing configuration'?' · Saved legacy field; support unconfirmed':!o.available?' · Not available on this miner':'')+(o.read_only?' · Managed / read only':'')));
  info.append(label,description,detail);
  let input;
  if(o.kind==='boolean'){
   input=node('input');input.type='checkbox';input.checked=draft[o.name]===true;
   input.onchange=()=>{if(input.checked)draft[o.name]=true;else delete draft[o.name]};
  }else{
   input=node('input');input.type=o.name==='pass'||o.name==='userpass'?'password':'text';
   input.value=draft[o.name]===KEEP?'':draft[o.name]??'';
   input.placeholder=draft[o.name]===KEEP?'Stored password':'Miner default';input.oninput=()=>draft[o.name]=input.value;
  }
  input.id=label.htmlFor;input.disabled=!o.available||o.read_only||!!settings.preview;
  input.setAttribute('aria-label',o.label||o.name);input.setAttribute('aria-describedby',description.id);
  const set=node('label',undefined,'set'),check=node('input');check.type='checkbox';
  check.checked=Object.hasOwn(draft,o.name);check.disabled=input.disabled;
  check.setAttribute('aria-label','Use a custom value for '+(o.label||o.name));
  check.onchange=()=>{if(check.checked)draft[o.name]=o.kind==='boolean'?true:input.value;else delete draft[o.name];renderOptions()};
  set.append(check,node('span','Custom'));set.title='Checked: save this setting explicitly. Unchecked: use the miner default.';
  row.append(info,input,set);root.append(row);
 }
}
for(const id of['option-search','option-group','show-unavailable'])$(id).oninput=renderOptions;
function renderNetwork(){
 const root=$('network-fields');root.replaceChildren();
 const fields=[['hostname','Miner name','Name used to identify this miner on your network.'],['dhcp','IP address assignment','Automatic (DHCP) asks your router for an address. Manual uses the address fields below.'],['ipaddress','Miner IP address (manual)','The address used to open this miner, such as 192.168.1.50. Applies only in manual mode.'],['netmask','Subnet mask (manual)','Defines your local network, commonly 255.255.255.0. Use the value required by your router.'],['gateway','Router IP address (manual)','Address of the router used to reach mining pools and the internet.'],['dnsservers','DNS server addresses (manual)','Servers used to look up pool hostnames. Separate multiple IP addresses with spaces.']];
 for(const[k,label,help]of fields){
  const l=node('label',label);let input;
  if(k==='dhcp'){input=node('select');for(const[v,t]of[['true','Automatic (DHCP)'],['false','Manual (static IP)']]){const opt=node('option',t);opt.value=v;input.append(opt)}}else input=node('input');
  input.id='network-'+k;input.value=settings.network[k]||'';input.disabled=!!settings.preview;
  const description=node('small',help,'field-help');description.id='network-help-'+k;input.setAttribute('aria-describedby',description.id);
  l.append(input,description);root.append(l);
 }
}
async function loadSettings(){settings=await request('settings');draft=structuredClone(settings.config);$('preview-banner').hidden=!settings.preview;document.querySelectorAll('.write').forEach(b=>b.disabled=!!settings.preview);$('add-pool').disabled=!!settings.preview;renderPools();renderOptions();renderNetwork();$('ssh-status').textContent=settings.ssh_enabled?'Enabled · port 22':'Disabled';$('ssh-toggle').textContent=settings.ssh_enabled?'Disable SSH':'Enable SSH';$('config-json').value=JSON.stringify(draft,null,2);$('config-json').disabled=!!settings.preview;$('build-info').textContent=JSON.stringify(settings.build||{release:settings.release,mode:'Local preview',hardware_validation:'pending'},null,2)}
function changeText(candidate){const keys=new Set([...Object.keys(settings.config),...Object.keys(candidate)]),lines=[];for(const k of keys){const before=JSON.stringify(settings.config[k]),after=JSON.stringify(candidate[k]);if(before!==after){if(k==='pools')lines.push('pools: '+candidate.pools.length+' configured pools (passwords hidden)');else if(k==='pass'||k==='userpass')lines.push(k+': [hidden]');else lines.push((settings.options.find(o=>o.name===k)?.label||k)+': '+(before??'(unset)')+' → '+(after??'(unset)'))}}return lines.join('\n')||'No changes.'}
async function save(candidate){const changes=changeText(candidate);if(changes==='No changes.'){notify(changes);return}if(!await review('Save mining configuration',changes,'Saved settings take effect when you restart mining.'))return;await request('save',{revision:settings.revision,config:candidate});await loadSettings();notify('Configuration saved. Restart mining to apply.')}
$('save-settings').onclick=()=>action(()=>save(draft));$('save-pools').onclick=()=>action(()=>save(draft));$('save-json').onclick=()=>action(()=>save(JSON.parse($('config-json').value)));$('reload-settings').onclick=()=>action(loadSettings);
$('restart').onclick=()=>action(async()=>{if(await review('Restart mining','Stop and restart CGMiner?','Mining will pause briefly.')){await request('restart',{confirm:true});notify('Mining restarted.');setTimeout(poll,4000)}});
$('ssh-toggle').onclick=()=>action(async()=>{const enabled=!settings.ssh_enabled;if(await review(enabled?'Enable SSH':'Disable SSH',enabled?'Start Dropbear on port 22 using your current miner login.':'Stop Dropbear and disable SSH at boot.')){await request('ssh',{enabled});await loadSettings();notify('SSH setting saved.')}});
$('save-network').onclick=()=>action(async()=>{const network={};for(const k of['hostname','dhcp','ipaddress','netmask','gateway','dnsservers'])network[k]=$('network-'+k).value;if(await review('Save network configuration',JSON.stringify(network,null,2),'Apply by rebooting. A new address may change how you reach this page.')){await request('network',{network});notify('Network saved; reboot to apply.')}});
$('reboot').onclick=()=>action(async()=>{if(await review('Reboot miner','Restart the controller and mining process?')){await request('reboot',{confirm:true});notify('Reboot requested.')}});
$('backup').onclick=()=>action(async()=>{const r=await api('backup',{}),url=URL.createObjectURL(await r.blob()),a=node('a');a.href=url;a.download='l3lab-settings.tar';a.click();setTimeout(()=>URL.revokeObjectURL(url),10000)});
$('restore').onclick=()=>action(async()=>{const file=$('restore-file').files[0];if(!file)throw Error('Choose a settings backup.');if(!await review('Restore mining settings','Import cgminer.conf from '+file.name+'?','Login credentials and SSH keys will be preserved.'))return;const form=new FormData();form.append('backup',file);await request('restore',form);await loadSettings();notify('Mining settings restored; restart mining to apply.')});
$('get-logs').onclick=()=>action(async()=>{$('logs').textContent=(await request('logs')).text});
let updateTimer=null;
function renderUpdateState(state){
 const prior=staged?.manifest?.sha256;
 const ready=state.state==='staged'&&state.manifest&&state.backup_ready;
 $('update-state').hidden=false;
 $('update-state').textContent=state.message||state.state;
 $('update-review').hidden=!ready;
 if(ready){staged=state;$('manifest').textContent=JSON.stringify(state.manifest,null,2);if(prior!==state.manifest.sha256)$('backup-ack').checked=false}
 else staged=null;
 const active=['preparing','queued','stopping','flashing'].includes(state.state);
 $('apply-update').disabled=!ready||!!settings?.preview;
 $('stage-update').disabled=active||!!settings?.preview;
 $('firmware-file').disabled=active||!!settings?.preview;
 if(state.state==='failed')notify(state.message||'Update preparation failed.',true);
 if(state.state==='complete')$('update-state').textContent='Readback verified. Use System & SSH → Reboot to start the installed firmware.';
 return active;
}
async function loadUpdateState(){
 const active=renderUpdateState(await request('update-state'));
 if(active&&!updateTimer)updateTimer=setInterval(()=>action(loadUpdateState),3000);
 if(!active&&updateTimer){clearInterval(updateTimer);updateTimer=null}
}
$('stage-update').onclick=()=>action(async()=>{
 const file=$('firmware-file').files[0];if(!file)throw Error('Choose an L3 Lab update package.');
 const form=new FormData();form.append('firmware',file);
 renderUpdateState({state:'preparing',message:'Preparing the update and recovery image. Keep this page open.'});
 try{const update=await request('stage-update',form);renderUpdateState({...update,state:'staged'});notify('Ready. Download the recovery image below, then review installation.')}
 catch(e){renderUpdateState({state:'failed',message:e.message});throw e}
});
$('apply-update').onclick=()=>action(async()=>{
 if(!staged)throw Error('Validate an update first.');
 if(!$('backup-ack').checked)throw Error('Save the recovery image and check the acknowledgement.');
 if(!await review('Install firmware',staged.manifest.version+'\nSHA-256 '+staged.manifest.sha256,'Mining will stop. Keep power connected until readback verification finishes.'))return;
 await request('apply-update',{sha256:staged.manifest.sha256,backup_downloaded:true});
 await loadUpdateState();
});
async function loadSchedule(){const data=await request('schedule'),s=data.schedule;for(const k of['off','on','timezone'])$('schedule-'+k).value=s[k];$('schedule-enabled').checked=s.enabled;for(const k of['off','on','timezone','enabled'])$('schedule-'+k).disabled=!!settings?.preview;$('schedule-state').textContent=data.state?.message||(s.enabled?(data.pause_window_now?'Daily pause window is active':'Schedule enabled; outside pause window'):'Schedule disabled')}
$('save-schedule').onclick=()=>action(async()=>{const s={enabled:$('schedule-enabled').checked,off:$('schedule-off').value,on:$('schedule-on').value,timezone:$('schedule-timezone').value};if(await review('Save daily mining schedule',`${s.enabled?'Enabled':'Disabled'}\nOff: ${s.off}\nOn: ${s.on}\nTimezone: ${s.timezone}`,'Confirm fan operation and reduced ASIC power before using this unattended.')){await request('save-schedule',s);await loadSchedule();notify('Daily schedule saved.')}});
async function loadDevSupport(){const d=await request('dev-support'),s=d.dev_support;$('dev-enabled').checked=s.enabled;$('dev-range').value=s.percent;$('dev-range-out').textContent=Number(s.percent).toFixed(1)+'%';for(const id of['dev-range','dev-enabled','dev-off','save-dev'])$(id).disabled=!!settings?.preview;$('dev-slice').textContent=`At ${Number(s.percent).toFixed(1)}%, about ${d.slice_seconds}s of every ${Math.round(d.period_seconds/60)} minutes to the developer's pool. ${d.fallback}`;$('dev-state').textContent=d.state?.message||(s.enabled&&s.percent>0?(d.active_now?'Dev support slice is active right now.':'Dev support is on; waiting for this hour’s slice.'):'Dev support is off.')}
$('dev-range').oninput=()=>{$('dev-range-out').textContent=Number($('dev-range').value).toFixed(1)+'%';if(Number($('dev-range').value)>0)$('dev-enabled').checked=true};
$('dev-off').onclick=()=>action(async()=>{await request('save-dev-support',{enabled:false,percent:0});await loadDevSupport();notify('Developer support turned off.')});
$('save-dev').onclick=()=>action(async()=>{const percent=Number($('dev-range').value),enabled=$('dev-enabled').checked&&percent>0;await request('save-dev-support',{enabled,percent});await loadDevSupport();notify('Developer support saved. Thank you.')});
action(async()=>{await loadSettings();await loadSchedule();await loadDevSupport();await loadUpdateState()});poll();
