const API = "";
const $ = id => document.getElementById(id);
let activity = [];

function toast(message) {
  const el = $("toast"); el.textContent = message; el.classList.add("show");
  setTimeout(() => el.classList.remove("show"), 2600);
}
function clock() { $("clock").textContent = new Date().toLocaleTimeString("en-GB"); }
setInterval(clock, 1000); clock();

async function api(path, options={}) {
  const response = await fetch(API + path, {headers:{"Content-Type":"application/json"}, ...options});
  const data = await response.json().catch(()=>({}));
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}
async function loadRules() {
  try {
    const data = await api("/api/rules");
    $("rulesStat").textContent = data.rules.length;
    $("ruleCount").textContent = String(data.rules.length).padStart(2,"0");
    $("rulesBody").innerHTML = data.rules.map(r => `<tr>
      <td><b>${escapeHtml(r.name)}</b></td><td><span class="protocol-pill">${escapeHtml(r.protocol)}</span></td>
      <td>${r.port === 0 ? "ANY" : r.port}</td><td><span class="decision ${r.action.toLowerCase()}">${r.action}</span></td>
      <td><span class="status-pill">${r.enabled ? "● ACTIVE" : "○ DISABLED"}</span></td>
      <td><button class="delete-btn" title="Delete rule" data-delete="${r.id}">×</button></td></tr>`).join("");
  } catch(e) { toast("Cannot connect to C backend. Start server.exe first."); }
}
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
async function loadStats() {
  try {
    const s = await api("/api/stats");
    $("totalStat").textContent=s.total; $("allowedStat").textContent=s.allowed; $("blockedStat").textContent=s.blocked;
  } catch(e) {}
}
function addActivity(packet, verdict) {
  activity.unshift({time:new Date().toLocaleTimeString("en-GB"),...packet,verdict});
  activity=activity.slice(0,12);
  $("activityBody").innerHTML=activity.map(a=>`<tr><td>${a.time}</td><td>${escapeHtml(a.sourceIp)}</td><td>${escapeHtml(a.destinationIp)}</td><td><span class="protocol-pill">${a.protocol}</span></td><td>${a.port}</td><td><span class="decision ${a.verdict.toLowerCase()}">${a.verdict}</span></td></tr>`).join("");
}
$("packetForm").addEventListener("submit", async e => {
  e.preventDefault();
  const packet={protocol:$("protocol").value,port:Number($("port").value),sourceIp:$("sourceIp").value.trim(),destinationIp:$("destinationIp").value.trim()};
  if(packet.port<0 || packet.port>65535) return toast("Port must be between 0 and 65535.");
  const box=$("resultBox"); box.className="result-box"; box.querySelector("b").textContent="INSPECTING PACKET...";
  box.querySelector("small").textContent="Sending packet details to the C filtering engine.";
  try {
    const result=await api("/api/evaluate",{method:"POST",body:JSON.stringify(packet)});
    const allow=result.action==="ALLOW"; box.className="result-box "+(allow?"allow":"block");
    box.querySelector(".result-symbol").textContent=allow?"✓":"⊘";
    box.querySelector("b").textContent=allow?"PACKET ALLOWED":"PACKET BLOCKED";
    box.querySelector("small").textContent=result.message;
    box.querySelector(".result-id").textContent=result.matched?"RULE #"+result.ruleId:"DEFAULT DENY";
    addActivity(packet,result.action); await loadStats();
  } catch(err) {
    box.querySelector("b").textContent="BACKEND CONNECTION ERROR";
    box.querySelector("small").textContent="Run the C server and keep its terminal open.";
    toast("C backend is not running.");
  }
});
$("addRuleBtn").addEventListener("click",()=>$("modal").classList.add("open"));
$("closeModal").addEventListener("click",()=>$("modal").classList.remove("open"));
$("modal").addEventListener("click",e=>{if(e.target===$("modal"))$("modal").classList.remove("open")});
$("ruleForm").addEventListener("submit",async e=>{
  e.preventDefault();
  const rule={name:$("ruleName").value.trim(),protocol:$("ruleProtocol").value,port:Number($("rulePort").value),action:$("ruleAction").value};
  if(rule.port<0||rule.port>65535)return toast("Enter a valid port number.");
  try {
    await api("/api/rules",{method:"POST",body:JSON.stringify(rule)});
    $("modal").classList.remove("open"); $("ruleForm").reset(); await loadRules(); toast("Firewall rule added to C engine.");
  } catch(err){toast(err.message);}
});
$("rulesBody").addEventListener("click",async e=>{
  const id=e.target.dataset.delete; if(!id)return;
  if(!confirm("Delete this firewall rule?"))return;
  try{await api("/api/rules/"+id,{method:"DELETE"});await loadRules();toast("Rule deleted.");}
  catch(err){toast(err.message);}
});
$("clearActivity").addEventListener("click",()=>{
  activity=[];$("activityBody").innerHTML='<tr><td colspan="6" class="empty">Activity log cleared. Run another packet simulation to begin.</td></tr>';
});
document.querySelectorAll(".nav").forEach(link=>link.addEventListener("click",()=>{
  document.querySelectorAll(".nav").forEach(n=>n.classList.remove("active"));link.classList.add("active");
}));
loadRules();loadStats();
setInterval(loadStats,5000);
