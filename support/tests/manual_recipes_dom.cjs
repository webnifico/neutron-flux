const fs=require('node:fs'),assert=require('node:assert/strict');
const {JSDOM,VirtualConsole}=require('jsdom'),copied=[],errors=[],vc=new VirtualConsole();
vc.on('jsdomError',error=>{if(error.type!=='css parsing')errors.push(error.message);});
const dom=new JSDOM(fs.readFileSync(process.argv[2],'utf8'),{runScripts:'dangerously',pretendToBeVisual:true,url:'https://report.invalid/',virtualConsole:vc,beforeParse(w){w.scrollTo=()=>{};w.HTMLElement.prototype.scrollIntoView=()=>{};Object.defineProperty(w.navigator,'clipboard',{value:{writeText:async value=>copied.push(value)}});}});
const w=dom.window,d=w.document;
async function main(){
 const original=w.eval('JSON.stringify(tests)');w.eval('openTest(tests[0].sequence)');d.querySelector('[data-workspace-section="manual"]').click();
 function edit(name,value){const input=d.querySelector('[data-manual-parameter="'+name+'"]');assert.ok(input,name);input.value=value;input.dispatchEvent(new w.Event('input',{bubbles:true}));}
 edit('DESTINATION_FIXED_IP','192.0.2.99');edit('DESTINATION_SERVER_ID',"new-id'quoted");edit('PROBE_PORT','19080');
 const responder=[...d.querySelectorAll('[data-manual-recipe]')].find(node=>node.textContent.includes('probe-server'));assert.ok(responder);
 assert.ok(responder.textContent.includes('192.0.2.99'));responder.querySelector('[data-manual-copy]').click();await new Promise(resolve=>setTimeout(resolve,10));
 assert.ok(copied.at(-1).includes("export PROBE_PORT='19080'"));assert.ok(copied.at(-1).includes("export DESTINATION_SERVER_ID='new-id'\\''quoted'"));
 d.querySelector('[data-workspace-step="1"]').click();assert.ok(d.querySelector('[data-result-pane="manual"]').textContent.includes('Historical commands — original inputs, not a runnable sequence'));
 assert.ok(d.querySelector('[data-result-pane="manual"]').textContent.includes('python3 saved-original.py'));
 assert.equal(w.eval('JSON.stringify(tests)'),original);assert.deepEqual(errors,[]);console.log(JSON.stringify({passed:true,checks:['same-page parameter copy','shell quoting','history immutability']}));dom.window.close();
}
main().catch(error=>{console.error(error);dom.window.close();process.exitCode=1;});
