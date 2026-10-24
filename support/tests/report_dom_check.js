// Execute the standalone report script without a graphical browser.
const fs = require("node:fs");
const vm = require("node:vm");
const assert = require("node:assert/strict");
const html = fs.readFileSync(process.argv[2], "utf8");
const data = html.match(/<script id="run-data" type="application\/json">([\s\S]*?)<\/script>/)[1];
const script = html.match(/<script>\n([\s\S]*?)<\/script>/)[1];
const elements = new Map();
const listeners = {};
for (const match of html.matchAll(/id="([^"]+)"/g)) {
  const id = match[1];
  elements.set(id, {
    value: /Search$/.test(id) ? "" : "all", textContent: id === "run-data" ? data : "",
    innerHTML: "", dataset: {}, style: {}, classList: {add(){},remove(){},toggle(){},contains(){return false;}},
    addEventListener(){}, setAttribute(){}, scrollIntoView(){},
  });
}
const document = {
  getElementById(id) { assert(elements.has(id), `Unknown element ${id}`); return elements.get(id); },
  querySelectorAll() { return []; }, addEventListener(name, callback){listeners[name] = callback;},
  createElement() { return {innerHTML:"",querySelector(){return null;},querySelectorAll(){return [];}}; },
  body: {dataset:{},classList:{toggle(){},contains(){return false;}},addEventListener(name, callback) { listeners[name] = callback; }},
};
class HTMLDetailsElement {
  constructor(key) {
    this.open=true;this.dataset={namedGroup:key};this.body={innerHTML:""};
    this.classList={contains:name=>name==="named-test"};
  }
  querySelector(selector) {assert.equal(selector,'.group-executions');return this.body;}
}
const context = vm.createContext({document, HTMLDetailsElement, console, URLSearchParams, location:{hash:"",href:"file:///report.html"}, history:{replaceState(){},pushState(){}}, window:{scrollTo(){},addEventListener(){}}, setTimeout(){},clearTimeout(){}, navigator:{clipboard:{writeText:async()=>{}}}});
vm.runInContext(script, context);
assert.equal(vm.runInContext("activeView", context), "overview");
assert.match(html, /<section class="view active" data-view="overview">/);
vm.runInContext("renderTests()",context);
assert.ok(elements.get("testRunSummary").innerHTML.includes("saved tests"));
for (const view of ["overview", "findings", "paths", "tests", "performance", "run"]) {
  vm.runInContext(`activateView(${JSON.stringify(view)},{hash:false,scroll:false})`, context);
}
const expected = JSON.parse(data).dashboard;
assert.ok(expected.results.every(test=>typeof test.test_name === "string" && test.test_name.length));
assert.ok(expected.results.every(test=>test.human_context?.purpose && test.human_context?.path));
assert.ok(expected.results.every(test=>Array.isArray(test.context_lines)));
assert.ok(!elements.get('testPhase').innerHTML.includes('Baseline'));
assert.ok(!elements.get('testPhase').innerHTML.includes('Cross-topology'));
for(const test of expected.results){
  const card=vm.runInContext(`testCard(testBySequence.get(${JSON.stringify(String(test.sequence))}))`,context);
  assert.ok(card.includes('human-test-context'),`${test.reference}: context must be visible in the result`);
  assert.ok(card.includes('Why this'),`${test.reference}: outcome needs a reason`);
  assert.ok(card.includes('Actual result'));
  for(const endpoint of [test.human_context.source,test.human_context.destination]){
    if(endpoint?.compute_host)assert.ok(card.includes(endpoint.compute_host));
    if(endpoint?.fixed_ip)assert.ok(card.includes(endpoint.fixed_ip));
    if(endpoint?.floating_ip)assert.ok(card.includes(endpoint.floating_ip));
  }
}
for(const moment of new Set(expected.results.map(test=>[test.human_context?.timing||test.timing,test.human_context?.action||test.action].filter(Boolean).join(' · ')||'Timing and configuration state not recorded'))){
  elements.get('testPhase').value=moment;
  assert.deepEqual(Array.from(vm.runInContext('filteredTests().map(test=>test.result_id)',context)),expected.results.filter(test=>[test.human_context?.timing||test.timing,test.human_context?.action||test.action].filter(Boolean).join(' · ')===moment||(!test.human_context?.timing&&!test.timing&&!test.human_context?.action&&!test.action&&moment==='Timing and configuration state not recorded')).map(test=>test.result_id));
}
elements.get('testPhase').value='all';
vm.runInContext("renderTests()",context);
assert.equal((elements.get("testList").innerHTML.match(/data-test-sequence=/g)||[]).length,0);
assert.ok(!expected.results.length || elements.get("testList").innerHTML.includes("named-test-heading"));
const groupCount = new Set(expected.results.map(test=>JSON.stringify([test.suite,test.test_name]))).size;
assert.equal(Number(elements.get("navTests").textContent),expected.results.length);
assert.equal(Number(elements.get("navPerformance").textContent),new Set(expected.results.filter(test=>test.category==="network-performance").map(test=>test.test_name)).size);
assert.ok(process.argv[3], "Expected renderer version must be supplied");
assert.equal(JSON.parse(data).report_renderer_version,process.argv[3]);
assert.equal((elements.get("testList").innerHTML.match(/class="named-test"/g)||[]).length,groupCount);
assert.ok(!elements.get("testList").innerHTML.includes('class="named-test" open'));
// Direct navigation must not inherit a filter that hides its target.
if(expected.paths.length){
  const path=expected.paths[0];
  const mismatch=['general','targeted','post-migration','control'].find(code=>!(path.host_scopes||[]).some(scope=>scope.code===code));
  elements.get('pathScope').value=mismatch||'all';
  vm.runInContext(`openPath(${JSON.stringify(path.path_id)})`,context);
  assert.ok(vm.runInContext('filteredPaths().some(path=>path.path_id===focusedPath)',context));
  vm.runInContext('focusedPath=null;renderTests()',context);
}
if(expected.findings.length){
  const finding=expected.findings[0];
  elements.get('findingSearch').value='unmatched search';
  elements.get('findingSeverity').value='unmatched severity';
  vm.runInContext(`openFinding(${JSON.stringify(finding.finding_id)})`,context);
  assert.ok(elements.get('findingList').innerHTML.includes('id="finding-'+finding.finding_id+'"'));
  if(expected.paths.length){
    const path=expected.paths[0];
    vm.runInContext(`showPathTests(${JSON.stringify(path.path_id)})`,context);
    assert.deepEqual(Array.from(vm.runInContext('filteredTests().map(test=>test.result_id).sort()',context)),[...path.result_ids].sort());
  }
  const unrelated=expected.results.find(test=>!finding.result_ids.includes(test.result_id));
  if(unrelated){
    vm.runInContext(`focusedFinding=${JSON.stringify(finding.finding_id)};openTest(${JSON.stringify(unrelated.sequence)})`,context);
    assert.equal(vm.runInContext('filteredTests().length',context),1);
  }
  vm.runInContext('focusedFinding=null;focusedPath=null;focusedTest=null;renderTests()',context);
}
const withoutPath=expected.results.find(test=>!test.path_id);
if(withoutPath&&expected.paths.length){
  vm.runInContext(`focusedPath=${JSON.stringify(expected.paths[0].path_id)};openTest(${JSON.stringify(withoutPath.sequence)})`,context);
  assert.equal(vm.runInContext('filteredTests().length',context),1);
  vm.runInContext('focusedFinding=null;focusedPath=null;focusedTest=null;renderTests()',context);
}
for(const test of expected.results.filter(test=>test.operator_explanation?.interruption_observations?.length)){
  const badges=vm.runInContext(`resultBadges(testBySequence.get(${JSON.stringify(String(test.sequence))}))`,context);
  assert.ok(badges.includes('Passed'));
  assert.ok(badges.includes('OBSERVATION'));
  assert.ok(!badges.includes('PASS WITH ADVISORY'));
  const card=vm.runInContext(`testCard(testBySequence.get(${JSON.stringify(String(test.sequence))}))`,context);
  assert.ok(card.includes('[OBSERVATION] Above tolerance'));
  for(const reason of test.operator_explanation.interruption_observations)assert.ok(card.includes(reason));
  assert.ok(card.includes(test.operator_explanation.interruption_tolerance_note));
  assert.equal(test.status,'PASS');
  assert.equal(test.severity,'warning');
  console.log('migration observation checks passed');
}
// Pagination must never hide entire test types behind the first execution page.
vm.runInContext("renderTests()",context);
assert.equal((elements.get("testList").innerHTML.match(/data-test-sequence=/g)||[]).length,0);
vm.runInContext("renderPerformance()",context);
assert.equal((elements.get("performancePaths").innerHTML.match(/data-test-sequence=/g)||[]).length,0);
// All executions remain accessible, and rerendering one view preserves the other.
function expandGroups(id) {
  const sequences=[];
  for(const match of elements.get(id).innerHTML.matchAll(/data-named-group="([^"]+)"/g)) {
    const card=new HTMLDetailsElement(match[1]);
    card.open=false;listeners.toggle({target:card});assert.equal(card.body.innerHTML,"");
    card.open=true;listeners.toggle({target:card});
    const first=card.body.innerHTML;
    assert.ok(first.includes('execution-table'));
    sequences.push(...[...first.matchAll(/data-test-sequence="([^"]+)"/g)].map(row=>row[1]));
    card.open=false;listeners.toggle({target:card});card.open=true;listeners.toggle({target:card});
    assert.equal(card.body.innerHTML,first);
  }
  return sequences.sort();
}
assert.deepEqual(expandGroups("testList"),expected.results.map(test=>String(test.sequence)).sort());
vm.runInContext("renderTests()",context);
assert.deepEqual(expandGroups("performancePaths"),expected.results.filter(test=>test.category==="network-performance").map(test=>String(test.sequence)).sort());
assert.equal(vm.runInContext("namedGroupRows.size",context),groupCount+new Set(expected.results.filter(test=>test.category==="network-performance").map(test=>JSON.stringify([test.suite,test.test_name]))).size);
if(expected.results.length){
  const test=expected.results[0];
  vm.runInContext(`openTest(${JSON.stringify(test.sequence)})`,context);
  assert.equal(vm.runInContext("filteredTests().length",context),1);
  assert.ok(elements.get("testList").innerHTML.includes('class="modern-inspection"'));
  vm.runInContext("focusedFinding=null;focusedPath=null;focusedTest=null;renderTests()",context);
}
for (const group of expected.operator_overview.groups) {
  elements.get("testReason").value = group.kind;
  const actual = vm.runInContext("filteredTests().map(test=>test.result_id)", context);
  assert.deepEqual(Array.from(actual), group.result_ids);
  vm.runInContext("renderTests()",context);
  assert.deepEqual(expandGroups("testList"),expected.results.filter(test=>group.result_ids.includes(test.result_id)).map(test=>String(test.sequence)).sort());
}
elements.get("testReason").value = "all";
assert.equal(vm.runInContext("filteredTests().length", context), expected.results.length);
if (expected.operator_overview.groups.length) {
  const group = expected.operator_overview.groups[0];
  listeners.click({target:{closest(selector) {return selector === "[data-review-kind]" ? {dataset:{reviewKind:group.kind}} : null;}}});
  assert.equal(vm.runInContext("filteredTests().length", context), group.count);
}
assert.match(vm.runInContext('explanationHtml({headline:"<script>alert(1)</script>",what_happened:"<b>x</b>",location:[],facts:[]})',context), /&lt;script&gt;/);
assert.ok(!vm.runInContext('explanationHtml({headline:"<script>alert(1)</script>"})',context).includes("<script>"));
if (expected.findings.length) {
  const handoff = vm.runInContext("findingHandoff(findings[0])", context);
  assert.match(handoff, /Next check:/);
}
console.log("report checks passed");
