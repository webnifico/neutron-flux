"""Self-contained report presentation; no external runtime assets."""

REPORT_NAVIGATION = r"""
// A persistent report rail and contextual test workflow share one navigation surface.
let lastWorkspaceTest=null;
let reviewSequence=tests.map(t=>String(t.sequence));
let reviewLabel='All tests';
let navigationMoving=false;
const captureBeforeQueue=captureBrowse;
captureBrowse=function(){return{...captureBeforeQueue(),reviewSequence:[...reviewSequence],reviewLabel};};
const goBackBeforeQueue=goBack;
goBack=function(){if(!browseHistory.length){focusedTest=null;focusedPath=null;focusedFinding=null;activateView('tests');return;}const saved=browseHistory.at(-1);if(saved?.reviewSequence){reviewSequence=[...saved.reviewSequence];reviewLabel=saved.reviewLabel;}goBackBeforeQueue();};
function closeWorkspaceRail(){document.getElementById('sidebar').classList.remove('open');document.getElementById('menuButton').setAttribute('aria-expanded','false');}

function currentTest(){return testBySequence.get(String(focusedTest));}
function renderWorkspaceRail(){
 const node=document.getElementById('testWorkspace');
 const test=activeView==='tests'?currentTest():null;
 if(test)lastWorkspaceTest=String(test.sequence);
 document.body.classList.toggle('workspace-test-open',Boolean(test));
 document.getElementById('menuButton').setAttribute('aria-expanded',String(document.getElementById('sidebar').classList.contains('open')));
 document.querySelectorAll('.report-navigation [data-view-link]').forEach(link=>{if(link.dataset.viewLink===activeView)link.setAttribute('aria-current','page');else link.removeAttribute('aria-current');});
 if(!test){const last=testBySequence.get(lastWorkspaceTest);node.innerHTML=last?`<div class="rail-label">Continue working</div><button class="rail-resume" data-resume-test="${last.sequence}"><span>${esc(last.reference)} · ${esc(statusText(last.status))}</span><strong>${esc(last.test_name)}</strong><small>Resume where you left off →</small></button>`:'';return;}
 const state=manualStateFor(test);
 node.innerHTML=`<div class="rail-test-heading"><span class="rail-label">Selected test</span><strong>${esc(test.reference)}</strong>${resultBadges(test)}</div><div class="rail-test-links"><button data-workspace-section="result" aria-current="${state.tab==='result'?'page':'false'}"><span>Result & evidence</span></button><button data-workspace-section="diagnostic" aria-current="${state.tab==='diagnostic'?'page':'false'}"><span>${test.status==='ERROR'?'Diagnose the exception':'Diagnose'}</span></button><button data-workspace-section="manual" aria-current="${state.tab==='manual'?'page':'false'}"><span>Reproduce manually</span></button>${state.tab==='manual'?`<div class="rail-manual-steps">${manualSteps.map((label,i)=>`<button data-workspace-step="${i}" aria-current="${state.step===i?'step':'false'}"><span>${i+1}</span>${['Prepare topology','Run commands','Compare results','Restore & finish'][i]}</button>`).join('')}</div>`:''}</div>`;
}

function workspaceSection(section){const t=currentTest();if(!t)return;manualStateFor(t).tab=section;const card=document.getElementById('test-'+t.sequence);if(!card)return;card.querySelectorAll('[data-result-pane]').forEach(p=>p.hidden=p.dataset.resultPane!==section);renderWorkspaceRail();}
function workspaceStep(step){const t=currentTest();if(!t)return;const card=document.getElementById('test-'+t.sequence),invalid=card?.querySelector('input:invalid');if(invalid){invalid.reportValidity();return;}const s=manualStateFor(t);s.tab='manual';s.step=Math.max(0,Math.min(3,Number(step)));refreshManual(card,t);workspaceSection('manual');}

const contentWithInnerNavigation=manualContent;
manualContent=function(t){return contentWithInnerNavigation(t).replace(/<nav class="manual-steps"[\s\S]*?<\/nav>/,'');};
const refreshManualBeforeRail=refreshManual;
refreshManual=function(card,t){refreshManualBeforeRail(card,t);renderWorkspaceRail();};

function diagnosisContent(t){
 const e=t.evidence||{},story=t.operator_explanation||{},f=manualFacts(t),route=f.route;
 const noRoute=t.status==='FAIL'&&String(e.stdout||e.stderr||'').includes('No route'),error=t.status==='ERROR'||t.status.startsWith('BLOCKED'),pass=t.status==='PASS';
 const firstFailure=tests.find(row=>row.result_id===t.manual_reproduction?.failure?.root_setup_result_id);
 const snapshot=e.diagnostic_snapshot||{};
 const blocks=noRoute?[
 ['Establish what failed','Recorded source → destination','The recorded probe received a “Destination unreachable: No route” reply. This establishes the symptom; the faulty component is not identified.',e.stdout],
 ['Check the source route','Inside the source guest','Confirm the selected interface, source address and next hop. The captured guest route selected '+(route.device||'the test interface')+'. Compare it with the recreated topology.',route.stdout||'No route output recorded.'],
 ['Follow the replying hop','Network diagnostics','Inspect routing and forwarding policy for the recorded source and external target at the replying hop. Correlate the attempt with network-side evidence before assigning a cause.','']
 ]:error?[
 [t.status.startsWith('BLOCKED')?'Read the blocking prerequisite':'Start with the first exception','Recorded operation',t.blocked_reason||t.manual_reproduction?.failure?.exception_message||t.observed||t.message||'The operation did not complete.',e.stderr||e.stdout||''],
 ['Check the required step',t.manual_reproduction?.failure?.operation||t.manual_reproduction?.failure?.failure_phase||'Saved error context',story.next_check||'Inspect the failing operation, its inputs and access, and the state of its required resources. Use the saved diagnostic snapshot and supporting attempts to locate the first failure.',JSON.stringify(t.manual_reproduction?.failure||{},null,2)==='{}'?'':JSON.stringify(t.manual_reproduction.failure,null,2)],
 ['Retry setup, then the intended check','Independent reproduction','Once the required operation works, repeat the intended check and retain new evidence. An error or blocked result has not confirmed the expected behavior.','']
 ]:[
 [pass?'Confirm what passed':'Read the recorded outcome','Captured result',story.why_this_status||story.headline||t.observed||'Inspect the captured result.',e.stdout||e.stderr||''],
 ['Check the scope and limits','Interpretation',(story.limitations||[]).join(' ')||'This result applies to the source, destination, VM placement and configuration shown for this test. It does not establish what happened on other paths or at other times.',''],
 ['Verify independently','Manual reproduction',pass?'Use the same scope and probe to confirm the observed behavior.':story.next_check||'Reproduce the check with the recorded scope and compare the evidence.','']
 ];
 return `<div class="diagnosis-heading"><div><span class="workspace-eyebrow">${error?'Execution exception':pass?'Verification':'Diagnostic workflow'}</span><h3>${error?'Recover the prerequisite':pass?'Understand and verify this result':t.status==='FAIL'?'Trace the observed failure':'Review the recorded result'}</h3></div><button class="button" data-copy-test="${t.sequence}">Copy evidence summary</button></div><div class="diagnosis-flow">${blocks.map(([title,where,body,output],i)=>`<section><div class="diagnosis-number">${i+1}</div><div><span class="workspace-eyebrow">${esc(where)}</span><h4>${esc(title)}</h4><p>${esc(body)}</p>${output?`<details ${i===0?'open':''}><summary>${i===0?'Captured output':'Captured route'}</summary><pre>${esc(output)}</pre></details>`:''}${i===1&&route.command?manualBlock(t,'Captured route command',route.command):''}</div></section>`).join('')}</div>${firstFailure&&firstFailure.sequence!==t.sequence?`<button class="button" data-open-test="${firstFailure.sequence}">Open the first failed step →</button>`:''}${Object.keys(snapshot).length?`<details><summary>Saved diagnostic snapshot</summary><pre>${esc(JSON.stringify(snapshot,null,2))}</pre></details>`:''}<div class="workspace-next"><p>${error?'Continue when the required step succeeds.':'Repeat the check and compare the new observation.'}</p><button class="button primary" data-workspace-section="manual">Reproduce manually →</button></div>`;
}

testCard=function(t){
 const original=inspectionWithEvidence(t),end=original.indexOf('</header>')+9,state=manualStateFor(t);
 const holder=document.createElement('div');holder.innerHTML=original.slice(end,-10);
 const diagnostic=holder.querySelector('.modern-diagnostic');
 if(diagnostic?.children[1])diagnostic.children[1].remove();
 diagnostic?.classList.add('workspace-recorded-evidence');
 const result=holder.innerHTML;
 return original.slice(0,end)+`<div data-result-pane="result" ${state.tab==='result'?'':'hidden'}>${blockingContext(t)}${result}<div class="workspace-next">${t.status!=='PASS'?'<p>Review this result or reproduce the setup.</p>':''}<div class="action-row">${t.status!=='PASS'?'<button class="button" data-workspace-section="diagnostic">Diagnose →</button>':''}<button class="button primary" data-workspace-section="manual">Reproduce manually →</button></div></div></div><div data-result-pane="diagnostic" ${state.tab==='diagnostic'?'':'hidden'}>${diagnosisContent(t)}</div><div data-result-pane="manual" ${state.tab==='manual'?'':'hidden'}>${manualContent(t)}</div></article>`;
};

const renderTestsBeforeRail=renderTests;
renderTests=function(){renderTestsBeforeRail();renderWorkspaceRail();};
const activateBeforeRail=activateView;
activateView=function(view,options={}){activateBeforeRail(view,options);renderWorkspaceRail();};
const openBeforeQueue=openTest;
openTest=function(sequence){
 if(!focusedTest&&!navigationMoving){const rows=filteredTests();reviewSequence=rows.map(t=>String(t.sequence));const status=document.getElementById('testStatus').value;reviewLabel=focusedFinding?'Finding results':status==='FAIL'?'Failed checks':status==='ERROR'?'Execution errors':rows.length===tests.length?'All tests':'Filtered tests';}
 if(!reviewSequence.includes(String(sequence))){reviewSequence=tests.map(t=>String(t.sequence));reviewLabel='All tests';}
 openBeforeQueue(sequence);renderWorkspaceRail();
};

renderReturn=function(){const node=document.getElementById('modernReturn'),t=activeView==='tests'?currentTest():null,last=browseHistory.at(-1);if(!node)return;node.classList.toggle('hidden',!last&&!t);if(!t){node.innerHTML=last?`<button class="button" data-browse-back>← Back to ${esc(viewNames[last.view])}</button>`:'';return;}const index=reviewSequence.indexOf(String(t.sequence));node.innerHTML=`<div class="workspace-return"><button class="button" data-browse-back>← Back to ${esc(last?viewNames[last.view]:'Tests')}</button><span>${esc(reviewLabel)}</span></div><div class="workspace-traverse"><span>${index+1} of ${reviewSequence.length.toLocaleString()}</span><button class="button" data-review-move="-1" aria-label="Previous check" ${index<=0?'disabled':''}>← Previous</button><button class="button" data-review-move="1" aria-label="Next check" ${index<0||index>=reviewSequence.length-1?'disabled':''}>Next →</button></div>`;};

document.body.addEventListener('click',event=>{
 const section=event.target.closest('[data-workspace-section]');if(section){workspaceSection(section.dataset.workspaceSection);closeWorkspaceRail();return;}
 const step=event.target.closest('[data-workspace-step]');if(step){workspaceStep(step.dataset.workspaceStep);closeWorkspaceRail();return;}
 const move=event.target.closest('[data-review-move]');if(move){const i=reviewSequence.indexOf(String(focusedTest)),next=reviewSequence[i+Number(move.dataset.reviewMove)];if(next){manualStateFor(testBySequence.get(next)).tab=manualStateFor(currentTest()).tab;navigationMoving=true;originalOpenTest(next);navigationMoving=false;renderReturn();renderWorkspaceRail();}return;}
 const resume=event.target.closest('[data-resume-test]');if(resume){navigationMoving=true;openTest(resume.dataset.resumeTest);navigationMoving=false;closeWorkspaceRail();return;}
 if(event.target.closest('[data-manual-tab]'))renderWorkspaceRail();
 if(event.target.closest('[data-view-link], [data-resume-test], [data-close-sidebar]')){document.getElementById('sidebar').classList.remove('open');document.getElementById('menuButton').setAttribute('aria-expanded','false');}
 if(event.target.closest('#menuButton'))document.getElementById('menuButton').setAttribute('aria-expanded',String(document.getElementById('sidebar').classList.contains('open')));
});

const chromeBeforeRail=renderChrome;
renderChrome=function(){chromeBeforeRail();document.getElementById("sideStarted").textContent=dateText(D.run?.started_at);document.getElementById("sideVersion").textContent="Results recorded by "+(D.tool_version||"an unrecorded version");document.getElementById("navTests").textContent=tests.length;};

"""
