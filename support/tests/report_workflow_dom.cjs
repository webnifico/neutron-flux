// Real DOM interactions for the self-contained report; this does not test pixels.
const fs=require('node:fs'),assert=require('node:assert/strict');
const {JSDOM,VirtualConsole}=require('jsdom');
const errors=[],copied=[],vc=new VirtualConsole();
vc.on('jsdomError',e=>{if(e.type!=='css parsing')errors.push(e.message);});
const dom=new JSDOM(fs.readFileSync(process.argv[2],'utf8'),{runScripts:'dangerously',pretendToBeVisual:true,url:'https://report.invalid/report.html',virtualConsole:vc,beforeParse(w){w.scrollTo=()=>{};w.HTMLElement.prototype.scrollIntoView=()=>{};Object.defineProperty(w.navigator,'clipboard',{value:{writeText:async v=>copied.push(v)}});}});
const w=dom.window,d=w.document;
const evaluate=s=>w.eval(s),pause=()=>new Promise(r=>setTimeout(r,10));
function click(q){const el=d.querySelector(q);assert.ok(el,q);el.click();}
async function run(){
 await pause();assert.equal(d.body.dataset.reportReady,'true',errors.join('\n'));
 assert.equal(evaluate('activeView'),'overview');
 assert.ok(d.querySelector('#sidebar .report-navigation'));
 assert.ok(!d.querySelector('[data-manual-example]'));
 assert.ok(!d.body.textContent.includes('Preview examples'));
 assert.ok(d.querySelector('#coverageLimits').textContent.includes('Test statuses saved'));
 const tests=evaluate('tests'),original=evaluate('JSON.stringify(tests)');
 const p=tests.find(t=>evaluate(`manualFacts(testBySequence.get('${t.sequence}')).ping`));assert.ok(p,'A recorded ping should have a manual command');
 click('[data-view-link="tests"]');
 d.getElementById('testStatus').value='FAIL';d.getElementById('testStatus').dispatchEvent(new w.Event('change'));
 const failed=tests.filter(t=>t.status==='FAIL');
 if(failed.length){
  const group=d.querySelector('.named-test');group.open=true;await pause();
  click('[data-open-test]');
  assert.ok(d.querySelector('.workspace-traverse').textContent.includes('1 of '+failed.length));
  if(failed.length>1){click('[data-review-move="1"]');assert.ok(d.querySelector('.workspace-traverse').textContent.includes('2 of '+failed.length));click('[data-review-move="-1"]');}
  click('[data-browse-back]');assert.equal(d.getElementById('testStatus').value,'FAIL');assert.ok(d.querySelector('.named-test[open]'));
 }
 evaluate(`openTest(${p.sequence})`);await pause();
 assert.equal(d.querySelectorAll('.modern-inspection').length,1);
 const context=d.querySelector('[data-result-pane="result"] .human-test-context');
 assert.ok(context,'The selected test must show its context before any diagnosis or evidence is opened');
 assert.ok(context.textContent.includes(p.human_context.purpose));
 assert.ok(context.textContent.includes(p.human_context.placement));
 for(const endpoint of [p.human_context.source,p.human_context.destination]){
  for(const key of ['fixed_ip','floating_ip','compute_host','availability_zone'])if(endpoint[key])assert.ok(context.textContent.includes(endpoint[key]));
 }
 assert.ok(!d.querySelector('.modern-inspection header').textContent.includes('Baseline'));
 assert.ok(!d.getElementById('testPhase').textContent.includes('Cross-topology'));
 if(p.status==='PASS'&&!p.operator_explanation.attention&&!p.operator_explanation.interruption_observations?.length){
  const result=d.querySelector('[data-result-pane="result"]');
  assert.ok(!result.textContent.includes('Next check'));
  assert.ok(!result.textContent.includes('Confirm this result independently.'));
 }
 click('#testWorkspace [data-workspace-section="manual"]');
 assert.equal(d.querySelectorAll('[data-workspace-step]').length,4);
 const source=d.querySelector('[data-manual-address="source"]'),address=p.family==='IPv6'?'2001:db8::10':'192.0.2.10';
 source.value='999.1000.1.1';source.dispatchEvent(new w.Event('input',{bubbles:true}));click('[data-workspace-step="1"]');
 assert.equal(d.querySelector('[data-workspace-step][aria-current="step"]').dataset.workspaceStep,'0');
 source.value=address;source.dispatchEvent(new w.Event('input',{bubbles:true}));click('[data-workspace-step="1"]');
 assert.ok(d.querySelector('.manual-step-panel').textContent.includes(address));
 click('[data-result-pane="manual"] [data-manual-copy]');await pause();assert.ok(copied.at(-1).includes(address));
 click('[data-manual-guide]');await pause();assert.ok(copied.at(-1).includes('4. Restore and finish'));assert.ok(copied.at(-1).includes(address));
 click('[data-workspace-step="2"]');click('[data-workspace-step="3"]');
 click('#testWorkspace [data-workspace-section="diagnostic"]');assert.ok(!d.querySelector('[data-result-pane="diagnostic"]').hidden);
 assert.equal(d.querySelectorAll('.diagnosis-flow section').length,3);
 click('#testWorkspace [data-workspace-section="manual"]');assert.equal(d.querySelector('[data-workspace-step][aria-current="step"]').dataset.workspaceStep,'3');
 click('[data-view-link="run"]');assert.ok(d.getElementById('runIdentity').textContent.includes('Region name'));
 click(`[data-resume-test="${p.sequence}"]`);assert.equal(d.querySelector('[data-workspace-step][aria-current="step"]').dataset.workspaceStep,'3');
 click('[data-workspace-step="1"]');assert.ok(d.querySelector('.manual-step-panel').textContent.includes(address));
 click('#menuButton');assert.equal(d.getElementById('menuButton').getAttribute('aria-expanded'),'true');click('#testWorkspace [data-workspace-section="result"]');assert.equal(d.getElementById('menuButton').getAttribute('aria-expanded'),'false');
 for(const status of [...new Set(tests.map(t=>t.status))]){
  const t=tests.find(t=>t.status===status);evaluate(`openTest(${t.sequence})`);click('#testWorkspace [data-workspace-section="diagnostic"]');click('#testWorkspace [data-workspace-section="manual"]');
  click('[data-workspace-step="0"]');assert.ok(d.querySelector('.manual-step-panel').textContent.includes('Before you run'));
  if(status==='NOT_RUN_CANCELLED')assert.ok(d.querySelector('.manual-step-panel').textContent.includes('cancelled before it ran'));
  if(status==='NOT_APPLICABLE')assert.ok(d.querySelector('.manual-step-panel').textContent.includes('did not apply to the original setup'));
 }
 for(const t of tests.filter(t=>t.evidence?.stdout?.includes('No route'))){
  evaluate(`openTest(${t.sequence})`);click('#testWorkspace [data-workspace-section="diagnostic"]');
  const diagnosis=d.querySelector('.diagnosis-flow').textContent;
  if(t.status==='PASS'){
   assert.ok(diagnosis.includes(t.operator_explanation.why_this_status));
   assert.ok(t.operator_explanation.why_this_status.length);
   assert.ok(!diagnosis.includes('Establish what failed'));
  }else if(t.status==='FAIL')assert.ok(diagnosis.includes('Establish what failed'));
 }
 // Substitution must not rewrite a different address with a matching prefix.
 const escaped=p.source.ip;
 const testValue=evaluate(`manualCommand(testBySequence.get('${p.sequence}'),${JSON.stringify('ping '+escaped+'0')})`);
 assert.equal(testValue,'ping '+escaped+'0');
 for(const view of ['overview','findings','paths','tests','performance','run'])click(`[data-view-link="${view}"]`);
 assert.equal(evaluate('JSON.stringify(tests)'),original,'Interactions must never edit saved results');
 await pause();assert.deepEqual(errors,[]);
 console.log(JSON.stringify({passed:true,results:tests.length,statuses:[...new Set(tests.map(t=>t.status))],checks:['all views','left navigation','filter restoration','filtered previous/next','four manual steps','address validation and substitution','copy command and guide','diagnosis','resume','mobile navigation state','recorded data unchanged']}));
 dom.window.close();
}
run().catch(e=>{console.error(e);dom.window.close();process.exitCode=1;});
