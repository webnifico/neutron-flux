"""Guided manual reproduction with independent, per-test browser state."""

REPORT_MANUAL = r"""
const manualState=new Map();
const manualSteps=['Prepare VMs and networks','Run the check','Compare the result','Restore and finish'];
function manualStateFor(t){
 if(!manualState.has(t.sequence)){const recipe=t.manual_reproduction?.recipe||{},values=Object.fromEntries((recipe.parameters||[]).map(p=>[p.name,p.recorded||'']));values.SOURCE_IP=values.SOURCE_IP||t.source?.ip||'';values.DESTINATION_IP=values.DESTINATION_IP||t.destination?.ip||'';if(Object.hasOwn(values,'TOKEN')&&!values.TOKEN&&typeof crypto!=='undefined'&&crypto.getRandomValues){const bytes=new Uint8Array(16);crypto.getRandomValues(bytes);values.TOKEN=[...bytes].map(value=>value.toString(16).padStart(2,'0')).join('');}manualState.set(t.sequence,{step:0,tab:'result',source:values.SOURCE_IP,target:values.DESTINATION_IP,values});}
 return manualState.get(t.sequence);
}
function manualFacts(t){
 let parsed={};try{parsed=JSON.parse(t.evidence?.parsed||'{}');}catch(e){}
 const path=pathById.get(t.path_id)||{},ev=t.evidence||{},guide=t.manual_reproduction||{};
 const commands=[...(guide.commands||[])];
 for(const id of t.related_evidence_ids||[]){const row=M.evidence_entries?.[id]||{};for(const c of row.manual_reproduction?.commands||[])commands.push({...c,sample:row.title});}
 const unique=[...new Map(commands.map(c=>[c.command,c])).values()];
 const primary=unique.find(c=>c.command===ev.command)||unique.find(c=>/^(ping|ping6)\s/.test(c.command));
 const changed=Boolean(guide.changes_state);
 const ping=Boolean(primary&&/^(ping|ping6)\s/.test(primary.command)&&!changed&&['same-subnet','cross-zone-connectivity','project-network-routing','provider-network-connectivity','project-provider-connectivity','egress','floating-ip'].includes(t.category));
 return{parsed,path,ev,guide,recipe:guide.recipe||{},commands:unique,primary,ping,route:parsed.endpoint_route||{},error:t.status==='ERROR'||t.status.startsWith('BLOCKED'),changed};
}
function manualCommand(t,command){
 const s=manualStateFor(t),slots=[];let value=String(command||'');
 for(const [from,to] of [[t.source?.ip,s.source],[t.destination?.ip,s.target]]){
  if(!from||!to||from===to)continue;
  const slot='__NF_ADDRESS_'+slots.length+'__',escaped=from.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
  value=value.replace(new RegExp('(^|[^0-9a-fA-F:.])'+escaped+'(?=$|[^0-9a-fA-F:.])','g'),(_,prefix)=>prefix+slot);slots.push([slot,to]);
 }
 for(const [slot,to] of slots)value=value.split(slot).join(to);
 return value;
}
function manualBlock(t,title,command,recipeIndex=null){return `<div class="manual-command" ${recipeIndex!==null?'data-manual-recipe="'+recipeIndex+'"':''}><div><span>${esc(title)}</span><button type="button" class="button" data-manual-copy="${t.sequence}" data-command="${esc(command)}">Copy command</button></div><pre><code>${esc(command)}</code></pre></div>`;}
function manualList(items){return '<ol class="manual-checklist">'+items.map(item=>'<li>'+esc(item)+'</li>').join('')+'</ol>';}
function manualShellQuote(value){return "'"+String(value).replace(/'/g,"'\\''")+"'";}
function manualRecipeCommand(t,step){
 const s=manualStateFor(t),values={...s.values,SOURCE_IP:s.source,DESTINATION_IP:s.target},names=step.parameters||[];
 const assignments=names.map(name=>'export '+name+'='+manualShellQuote(values[name]||''));
 const required=names.map(name=>': "${'+name+':?Enter current '+name+' in Prepare VMs and networks}"');
 return '(\nset -eu\n'+[...assignments,...required,step.command].join('\n')+'\n)';
}
function manualRecipeSteps(t,steps){const all=t.manual_reproduction?.recipe?.steps||[];return steps.map((step,index)=>`<section class="manual-recipe-step"><h4>${index+1}. ${esc(step.title)}</h4><p><strong>Run on: ${esc(step.role)}</strong></p>${manualBlock(t,'Current-parameter recipe',manualRecipeCommand(t,step),all.indexOf(step))}<p><strong>Required observation:</strong> ${esc(step.expected)}</p></section>`).join('');}
function manualHelper(t,f){return f.recipe.helper_required?'<div class="manual-notice"><strong>Matching responder and client helper</strong><p>Download this self-contained Python 3 file once and copy the identical file to the source and destination VMs. Set HELPER to its local path in each terminal. The helper starts only when you run its command; this report executes nothing.</p><button type="button" class="button" data-manual-helper>Download neutron-flux-manual.py</button></div>':'';}
function manualSetup(t,f){
 const s=manualStateFor(t),p=f.path,g=f.guide,config=D.configuration||{};
 const statusNote=t.status==='NOT_RUN_CANCELLED'?'This test was cancelled before it ran. Start a new check only after confirming the required setup.':['NOT_APPLICABLE','SKIP'].includes(t.status)?'This test did not apply to the original setup. Check whether it applies to your new setup before creating resources.':t.status==='UNVERIFIED'?'The saved result did not confirm the expected behavior. Review its stated limits before repeating it.':'';
 const addresses=[['Source network',p.source_addressing],['Destination network',p.destination_addressing]].filter(([,a])=>a);
 const facts=[['Region name',environment.region_name||'Not recorded'],['Availability zones',(t.zones||[]).join(' · ')||'Not recorded'],['Source',t.source?.label||'Not recorded'],['Destination',t.destination?.label||'Not recorded'],['Actual compute hosts',t.host_scope?.observed_pair||[p.source_host,p.destination_host].filter(Boolean).join(' → ')||'Not recorded'],['Requested compute hosts',t.host_scope?.requested_pair||'No host pair selected'],['Image / flavor / storage',[config.image,config.flavor,config.storage].filter(Boolean).join(' / ')||'Not recorded'],...addresses.map(([label,a])=>[label,[a.network_name||a.network_label,a.cidr,a.gateway_ip?'gateway '+a.gateway_ip:''].filter(Boolean).join(' · ')||'Not recorded'])];
 const parameters=f.recipe.parameters||[],inputs=parameters.map(param=>{const address=param.name==='SOURCE_IP'?'source':param.name==='DESTINATION_IP'?'target':null;const value=address?s[address]:s.values[param.name];return `<label>${esc(param.label)}<input data-manual-parameter="${esc(param.name)}" ${address?'data-manual-address="'+address+'"':''} data-sequence="${t.sequence}" data-kind="${esc(param.kind)}" value="${esc(value||'')}" spellcheck="false"><small>Saved value: ${esc(param.recorded||'not recorded; supply the current value')}</small></label>`;}).join('');
 const limits=f.recipe.incomplete||[];
 return `<div class="manual-notice"><strong>${D.cleanup?.complete?'Original test resources were cleaned up.':'Confirm whether the recorded resources still exist.'}</strong><p>Use disposable test resources with the same connections, policy and placement. Values below initially show historical evidence where available. Replace them with current values before copying commands. Changing fields updates only generated recipes; historical commands remain unchanged.</p></div><dl class="manual-facts">${facts.map(([label,value])=>`<div><dt>${esc(label)}</dt><dd>${esc(value)}</dd></div>`).join('')}</dl><h4>Before you run</h4>${statusNote?`<div class="manual-notice">${esc(statusNote)}</div>`:''}${manualList([...(g.setup||[]),...(f.recipe.notes||[])])}${f.error?`<div class="manual-notice"><strong>Resolve the recorded error first</strong><p>${esc(g.failure?.exception_message||t.observed||t.message||'Review the first unsuccessful operation.')}</p></div>`:''}${manualHelper(t,f)}<h4>Current disposable resources and settings</h4><div class="manual-addresses">${inputs||'<p>No endpoint parameters apply to this control result.</p>'}</div><p class="muted small">Use the same fresh token in the matching observer and client. Empty required values stop only the command subshell; they never close your terminal. A UUID shown above identifies the original resource, which may already have been deleted.</p>${limits.length?`<div class="manual-notice"><strong>Reproduction limits / missing prerequisites</strong>${manualList(limits)}</div>`:''}${manualRecipeSteps(t,(f.recipe.steps||[]).filter(step=>step.phase==='prepare'))}`;
}
function manualRun(t,f){
 if(f.guide.version>=2){
  let html=`<h4>Ordered procedure for this assertion</h4><p>Prepare the shared setup once per topology. Run each block in its named terminal, inspect its required observation, then continue. Shell blocks are generated from the current fields; they are not a claim that these commands ran historically.</p>`+manualRecipeSteps(t,(f.recipe.steps||[]).filter(step=>step.phase==='run'));
  if(!(f.recipe.steps||[]).some(step=>step.phase==='run'))html+='<div class="manual-notice">No executable traffic or state-changing procedure applies to this control result. Review the specific saved operation and prerequisites.</div>';
  html+=`<details><summary>Historical commands — original inputs, not a runnable sequence</summary><p>These immutable commands show what Flux recorded. They may reference removed resources, temporary files or earlier operation phases. They are not adapted when current parameters change.</p>${f.commands.map(c=>`<p>${esc(c.context)} · ${esc(c.location)}</p><pre><code>${esc(c.command)}</code></pre>`).join('')||'<p>No historical shell command was saved for this result.</p>'}</details>`;
  return html;
 }
 const g=f.guide,s=manualStateFor(t),adapted=s.source!==t.source?.ip||s.target!==t.destination?.ip;
 let html=`<h4>Procedure for this test</h4>${manualList(g.actions||['Use the saved test description and supporting attempts to identify the ordered operations.'])}`;
 if(!f.commands.length)return html+`<div class="manual-notice"><strong>No exact command was saved for this result.</strong><p>${t.status==='NOT_RUN_CANCELLED'?'The test was cancelled before running; no command was recorded for this result.':['NOT_APPLICABLE','SKIP'].includes(t.status)?'The test did not apply to the recorded setup. Confirm applicability before attempting a new check.':f.error?'The test failed to complete or a required step prevented it from running. Fix the first recorded error before evaluating the intended behavior.':'This result may describe an API operation or combine supporting probes. Review the saved operations and their inputs before attempting an exact replay.'}</p></div><button class="button" data-workspace-section="diagnostic">Inspect the diagnosis →</button>`;
 html+=`<div class="manual-execution"><strong>${f.ping?'Run the ping inside the recorded source guest or observer':'Use the execution location recorded for each operation'}</strong><span>${f.ping&&adapted?'Ping and route commands use your entered addresses':'Exact commands from the saved record'}</span></div>`;
 if(f.ping&&f.route.command&&!f.commands.some(c=>c.command===f.route.command))html+=manualBlock(t,'Check the selected route',manualCommand(t,f.route.command));
 html+=f.commands.map(c=>{const adapt=f.ping&&(/^(ping|ping6)\s/.test(c.command)||/^ip\s.*route get/.test(c.command));return `<p class="muted small">${esc(c.sample||c.context)} · ${esc(c.location)}</p>`+manualBlock(t,adapt?'Probe / route command':'Recorded command',adapt?manualCommand(t,c.command):c.command);}).join('');
 return html+`<p class="manual-notice">${f.ping?'Keep the recorded packet count, timeout and IP family. Bind to an address assigned to the source guest.':'Commands can depend on listeners, credentials, resource IDs or an earlier state change. Follow the procedure and verify those inputs before copying a command.'}</p>`;
}
function manualCompare(t,f){
 const loss=String(f.ev.stdout||'').match(/\d+ packets transmitted,.*packet loss[^\n]*/)?.[0];
 return `<div class="manual-compare"><div><span>Required behavior</span><h4>${esc(t.expected||'Expectation not recorded')}</h4><p>Use the same acceptance rule, protocol, direction and test phase. A new observation applies only to the topology and placement you reproduced.</p></div><div><span>Saved ${esc(t.reference)} result</span>${statusBadge(t.status,t.severity)}<p>${esc(loss||t.observed||t.message||'No observation recorded')}</p></div></div>${String(f.ev.stdout||'').includes('No route')?'<div class="manual-notice"><strong>If a no-route reply recurs</strong><p>Record the replying hop from the new output and compare the guest route with the saved output. The guest route alone cannot locate the cause of the forwarding failure.</p></div>':''}${f.error?'<p>Complete the required steps before evaluating the expected behavior. An error or blocked test does not confirm pass or fail.</p>':''}<h4>Keep with your manual result</h4><p>Save the command, stdout, stderr, exit status, timestamp, current resource IDs, endpoint addresses and actual host placement. Record any differences from the original setup.</p><button class="button" data-workspace-section="result">Compare with saved evidence →</button>`;
}
function manualFinish(t,f){return `<h4>${f.ping&&!f.changed?'The ping does not change persistent configuration.':'Restore the test environment'}</h4>${manualRecipeSteps(t,(f.recipe.steps||[]).filter(step=>step.phase==='restore'))}${manualList([...(f.guide.restore||['Restore any state changed during reproduction using the original values you saved. Remove only the disposable resources you created.']),'Stop the foreground temporary responder with Ctrl-C in its own terminal. Do not kill shared services or delete existing provider networks.','Attach the new observation to '+t.reference+' and record any setup or placement differences.'])}<div class="manual-notice"><strong>Keep the new result alongside the original</strong><p>Reviewing this report or running a manual check does not change the original verdict. If required inputs were missing, record the reproduction as incomplete.</p></div><button class="button" data-workspace-section="result">Return to result →</button>`;}
function manualContent(t){const s=manualStateFor(t),f=manualFacts(t);return `<div class="manual-title"><div><h3>Reproduce manually</h3><p>Prepare the same setup, repeat the test, compare the result and restore the environment.</p></div><button class="button" data-manual-guide="${t.sequence}">Copy full guide</button></div><div class="manual-layout"><div class="manual-step-panel" aria-live="polite"><div class="manual-step-heading"><span>Step ${s.step+1} of 4</span><h3>${manualSteps[s.step]}</h3></div>${[manualSetup,manualRun,manualCompare,manualFinish][s.step](t,f)}<div class="manual-step-footer"><button class="button" data-manual-step="${s.step-1}" ${s.step===0?'disabled':''}>← Previous</button>${s.step<3?`<button class="button primary" data-manual-step="${s.step+1}">${['Continue to commands','Compare the result','Restore and finish'][s.step]} →</button>`:'<span class="muted small">No commands run from this report</span>'}</div></div></div>`;}
const inspectionWithEvidence=testCard;
const renderTestsWithGroups=renderTests;
renderTests=function(){renderTestsWithGroups();document.body.classList.toggle('manual-focused',Boolean(focusedTest));if(focusedTest){const t=testBySequence.get(String(focusedTest));if(t)document.getElementById('testList').innerHTML=testCard(t);}};
function refreshManual(card,t){card.querySelector('[data-result-pane="manual"]').innerHTML=manualContent(t);}
function validManualAddress(value,family){
 if(!value||!/^[:.0-9a-fA-F]+$/.test(value))return false;
 if(value.includes(':')){if(family==='IPv4')return false;try{new URL('http://['+value+']/');return true;}catch(e){return false;}}
 return family!=='IPv6'&&value.split('.').length===4&&value.split('.').every(v=>/^\d{1,3}$/.test(v)&&Number(v)<=255);
}
document.body.addEventListener('input',event=>{
 const input=event.target.closest('[data-manual-parameter],[data-manual-address]');if(!input)return;
 const t=testBySequence.get(input.dataset.sequence),value=input.value.trim();
 if(value&&input.dataset.kind==='ip'&&!validManualAddress(value,t.family)){input.setCustomValidity('Enter a valid '+(t.family||'IP')+' address.');return;}
 if(value&&input.dataset.kind==='token'&&!/^[a-fA-F0-9]{32}$/.test(value)){input.setCustomValidity('Use 32 hexadecimal characters, shared by observer and client.');return;}
 if(value&&input.dataset.kind==='port'&&(!/^\d+$/.test(value)||Number(value)<1||Number(value)>65535)){input.setCustomValidity('Enter a port from 1 to 65535.');return;}
 input.setCustomValidity('');const state=manualStateFor(t);if(input.dataset.manualAddress)state[input.dataset.manualAddress]=value;if(input.dataset.manualParameter)state.values[input.dataset.manualParameter]=value;
 const card=input.closest('.modern-inspection');for(const node of card?.querySelectorAll('[data-manual-recipe]')||[]){const step=t.manual_reproduction.recipe.steps[Number(node.dataset.manualRecipe)],command=manualRecipeCommand(t,step);node.querySelector('code').textContent=command;node.querySelector('[data-manual-copy]').dataset.command=command;}
});
document.body.addEventListener('click',event=>{
 if(event.target.closest('[data-manual-helper]')){const source=D.manual_helper_source;if(!source)return;const blob=new Blob([source],{type:'text/x-python;charset=utf-8'}),url=URL.createObjectURL(blob),anchor=document.createElement('a');anchor.href=url;anchor.download='neutron-flux-manual.py';anchor.click();setTimeout(()=>URL.revokeObjectURL(url),1000);return;}
 const card=event.target.closest('.modern-inspection');if(!card)return;const t=testBySequence.get(card.dataset.testSequence);
 const step=event.target.closest('[data-manual-step]');if(step){workspaceStep(step.dataset.manualStep);return;}
 const copy=event.target.closest('[data-manual-copy]');if(copy){const invalid=card.querySelector('input:invalid');if(invalid){invalid.reportValidity();return;}const recipe=copy.closest('[data-manual-recipe]'),command=recipe?manualRecipeCommand(t,t.manual_reproduction.recipe.steps[Number(recipe.dataset.manualRecipe)]):copy.dataset.command;copyText(command,'Command copied');return;}
 if(event.target.closest('[data-manual-guide]')){
  const invalid=card.querySelector('input:invalid');if(invalid){invalid.reportValidity();return;}
  const f=manualFacts(t),s=manualStateFor(t),node=document.createElement('div');
  node.innerHTML=[manualSetup,manualRun,manualCompare,manualFinish].map((fn,i)=>`<section><h2>${i+1}. ${manualSteps[i]}</h2>${fn(t,f)}</section>`).join('');
  node.querySelectorAll('button,input').forEach(n=>n.remove());node.querySelectorAll('h2,h3,h4,p,li,dt,dd,pre').forEach(n=>n.appendChild(document.createTextNode('\n')));
  copyText(`${t.reference}: ${t.test_name}\nRecorded result: ${t.status}\nSource: ${s.source||'Not recorded'}\nDestination: ${s.target||'Not recorded'}\n\n${node.textContent}`,'Full manual guide copied');
 }
});
"""
