import { useState, useEffect } from "react";
const API = "http://127.0.0.1:8000";
function Bar({ value, max, color }) {
  const pct = max > 0 ? (value / max) * 100 : 0;
  return <div style={{background:"#0f172a",borderRadius:6,height:8,overflow:"hidden",flex:1}}><div style={{width:`${pct}%`,height:"100%",background:color,borderRadius:6,transition:"width 0.6s ease"}}/></div>;
}
function VerdictBadge({ verdict }) {
  const s = {Phishing:{color:"#ef4444",background:"rgba(239,68,68,0.1)",border:"1px solid rgba(239,68,68,0.3)"},Suspicious:{color:"#f59e0b",background:"rgba(245,158,11,0.1)",border:"1px solid rgba(245,158,11,0.3)"},Safe:{color:"#10b981",background:"rgba(16,185,129,0.1)",border:"1px solid rgba(16,185,129,0.3)"}}[verdict]||{};
  return <span style={{...s,fontSize:11,fontWeight:700,padding:"2px 10px",borderRadius:999,fontFamily:"monospace"}}>{verdict}</span>;
}
function StatCard({ label, value, sub, color }) {
  return <div style={{background:"#0c1220",border:"1px solid #1e2d45",borderRadius:16,padding:"20px 24px"}}><div style={{fontSize:11,color:"#64748b",textTransform:"uppercase",letterSpacing:1,marginBottom:10,fontFamily:"monospace"}}>{label}</div><div style={{fontSize:36,fontWeight:800,color:color||"#e2e8f0",lineHeight:1}}>{value}</div>{sub&&<div style={{fontSize:12,color:"#64748b",marginTop:6}}>{sub}</div>}</div>;
}
export default function Dashboard() {
  const [history,setHistory]=useState([]);
  const [loading,setLoading]=useState(true);
  const [error,setError]=useState(null);
  const [url,setUrl]=useState("");
  const [scanning,setScanning]=useState(false);
  const fetchHistory=async()=>{try{const res=await fetch(`${API}/history`);const data=await res.json();setHistory(data.items||[]);setError(null);}catch{setError("Backend not running.");}finally{setLoading(false);}};
  useEffect(()=>{fetchHistory();const i=setInterval(fetchHistory,10000);return()=>clearInterval(i);},[]);
  const quickScan=async()=>{if(!url.trim())return;setScanning(true);try{await fetch(`${API}/scan-url`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url})});setUrl("");await fetchHistory();}catch{}setScanning(false);};
  const total=history.length,phishing=history.filter(r=>r.verdict==="Phishing").length,suspicious=history.filter(r=>r.verdict==="Suspicious").length,safe=history.filter(r=>r.verdict==="Safe").length;
  const avgScore=total>0?Math.round(history.reduce((s,r)=>s+r.risk_score,0)/total):0;
  const gsbHits=history.filter(r=>r.gsb_flagged).length,vtHits=history.filter(r=>r.vt_flagged).length;
  const threatRate=total>0?Math.round(((phishing+suspicious)/total)*100):0;
  const domainMap={};history.forEach(r=>{if(!domainMap[r.domain])domainMap[r.domain]={count:0,verdict:r.verdict,score:r.risk_score};domainMap[r.domain].count++;});
  const topDomains=Object.entries(domainMap).sort((a,b)=>b[1].score-a[1].score).slice(0,6);
  return(
    <div style={{minHeight:"100vh",background:"#04060f",color:"#e2e8f0",fontFamily:"system-ui,sans-serif",padding:"32px 28px"}}>
      <div style={{maxWidth:1160,margin:"0 auto"}}>
        <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:32}}>
          <div><h1 style={{fontSize:28,fontWeight:800,letterSpacing:-1,marginBottom:4}}>Security Dashboard</h1><p style={{fontSize:13,color:"#64748b",fontFamily:"monospace"}}>Real-time threat intelligence · {total} scans</p></div>
          <div style={{display:"flex",alignItems:"center",gap:8,fontSize:12,color:"#10b981",fontFamily:"monospace"}}><span style={{width:6,height:6,borderRadius:"50%",background:"#10b981",display:"inline-block"}}/>Live · 10s refresh</div>
        </div>
        <div style={{display:"flex",gap:10,marginBottom:28,background:"#0c1220",border:"1px solid #1e2d45",borderRadius:16,padding:"8px 8px 8px 20px"}}>
          <input value={url} onChange={e=>setUrl(e.target.value)} onKeyDown={e=>e.key==="Enter"&&quickScan()} placeholder="Quick scan — paste any URL" style={{flex:1,background:"transparent",border:"none",outline:"none",color:"#e2e8f0",fontSize:14,fontFamily:"monospace"}}/>
          <button onClick={quickScan} disabled={scanning} style={{background:"linear-gradient(135deg,#1d4ed8,#0e7490)",border:"none",color:"#fff",padding:"12px 24px",borderRadius:12,fontWeight:800,fontSize:13,cursor:"pointer",opacity:scanning?0.6:1}}>{scanning?"Scanning...":"Scan"}</button>
        </div>
        {error&&<div style={{background:"rgba(239,68,68,0.08)",border:"1px solid rgba(239,68,68,0.3)",borderRadius:12,padding:"12px 16px",color:"#fca5a5",fontSize:13,marginBottom:24}}>⚠ {error}</div>}
        <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:16,marginBottom:16}}>
          <StatCard label="Total Scans" value={total} sub="all time" color="#e2e8f0"/>
          <StatCard label="Phishing" value={phishing} sub={`${threatRate}% threat rate`} color="#ef4444"/>
          <StatCard label="Suspicious" value={suspicious} sub="flagged for review" color="#f59e0b"/>
          <StatCard label="Avg Risk Score" value={avgScore} sub="out of 100" color={avgScore>60?"#ef4444":avgScore>30?"#f59e0b":"#10b981"}/>
        </div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:16,marginBottom:24}}>
          <StatCard label="Safe URLs" value={safe} sub="no threats" color="#10b981"/>
          <StatCard label="Safe Browsing Hits" value={gsbHits} sub="Google confirmed" color="#3b82f6"/>
          <StatCard label="VirusTotal Hits" value={vtHits} sub="engine detections" color="#8b5cf6"/>
        </div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 2fr",gap:20,marginBottom:24}}>
          <div style={{background:"#0c1220",border:"1px solid #1e2d45",borderRadius:16,padding:24}}>
            <div style={{fontSize:11,color:"#64748b",textTransform:"uppercase",letterSpacing:1,marginBottom:20,fontFamily:"monospace"}}>Threat Breakdown</div>
            {[{label:"Phishing",count:phishing,color:"#ef4444"},{label:"Suspicious",count:suspicious,color:"#f59e0b"},{label:"Safe",count:safe,color:"#10b981"}].map(({label,count,color})=>(
              <div key={label} style={{marginBottom:14}}>
                <div style={{display:"flex",justifyContent:"space-between",fontSize:13,marginBottom:6}}><span style={{color:"#94a3b8"}}>{label}</span><span style={{color,fontWeight:700}}>{count}</span></div>
                <Bar value={count} max={total||1} color={color}/>
              </div>
            ))}
            <div style={{marginTop:20,paddingTop:16,borderTop:"1px solid #1e2d45"}}>
              <div style={{fontSize:11,color:"#64748b",marginBottom:8,fontFamily:"monospace",textTransform:"uppercase",letterSpacing:1}}>Intelligence Sources</div>
              {["Rule Engine","ML Ensemble","Safe Browsing","VirusTotal","WHOIS"].map(name=>(
                <div key={name} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"7px 0",borderBottom:"1px solid rgba(30,45,69,0.4)"}}>
                  <span style={{fontSize:12,color:"#94a3b8"}}>{name}</span>
                  <span style={{fontSize:10,color:"#10b981",background:"rgba(16,185,129,0.1)",border:"1px solid rgba(16,185,129,0.3)",padding:"2px 8px",borderRadius:999,fontFamily:"monospace"}}>Active</span>
                </div>
              ))}
            </div>
          </div>
          <div style={{background:"#0c1220",border:"1px solid #1e2d45",borderRadius:16,padding:24}}>
            <div style={{fontSize:11,color:"#64748b",textTransform:"uppercase",letterSpacing:1,marginBottom:20,fontFamily:"monospace"}}>Recent Scans</div>
            {loading?<div style={{color:"#64748b",fontSize:13}}>Loading...</div>:history.length===0?<div style={{color:"#64748b",fontSize:13}}>No scans yet. Scan a URL above.</div>:(
              <div style={{display:"flex",flexDirection:"column",gap:8,maxHeight:380,overflowY:"auto"}}>
                {history.slice(0,15).map((item,i)=>(
                  <div key={i} style={{display:"flex",alignItems:"center",gap:12,padding:"10px 14px",background:"#080d1a",borderRadius:12,border:"1px solid #1e2d45"}}>
                    <div style={{width:42,height:42,borderRadius:10,background:item.verdict==="Phishing"?"rgba(239,68,68,0.1)":item.verdict==="Suspicious"?"rgba(245,158,11,0.1)":"rgba(16,185,129,0.1)",border:`1px solid ${item.verdict==="Phishing"?"rgba(239,68,68,0.3)":item.verdict==="Suspicious"?"rgba(245,158,11,0.3)":"rgba(16,185,129,0.3)"}`,display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0,fontSize:18}}>
                      {item.verdict==="Phishing"?"⚠":item.verdict==="Suspicious"?"⚡":"✓"}
                    </div>
                    <div style={{flex:1,minWidth:0}}>
                      <div style={{fontSize:13,fontWeight:700,fontFamily:"monospace",whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis",color:"#e2e8f0"}}>{item.domain}</div>
                      <div style={{fontSize:11,color:"#64748b",marginTop:2}}>{item.reasons?.[0]||"No signals"}</div>
                    </div>
                    <div style={{display:"flex",flexDirection:"column",alignItems:"flex-end",gap:4,flexShrink:0}}>
                      <VerdictBadge verdict={item.verdict}/>
                      <span style={{fontSize:11,color:"#64748b",fontFamily:"monospace"}}>{item.risk_score}/100</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
        {topDomains.length>0&&(
          <div style={{background:"#0c1220",border:"1px solid #1e2d45",borderRadius:16,padding:24}}>
            <div style={{fontSize:11,color:"#64748b",textTransform:"uppercase",letterSpacing:1,marginBottom:20,fontFamily:"monospace"}}>Top Scanned Domains</div>
            <div style={{display:"grid",gap:8}}>
              {topDomains.map(([domain,data],i)=>(
                <div key={domain} style={{display:"flex",alignItems:"center",gap:16,padding:"12px 16px",background:"#080d1a",borderRadius:12,border:"1px solid #1e2d45"}}>
                  <span style={{fontSize:12,color:"#334155",fontFamily:"monospace",width:20}}>#{i+1}</span>
                  <span style={{flex:1,fontSize:13,fontFamily:"monospace",color:"#94a3b8"}}>{domain}</span>
                  <div style={{display:"flex",alignItems:"center",gap:12}}>
                    <span style={{fontSize:11,color:"#64748b"}}>{data.count} scan{data.count>1?"s":""}</span>
                    <div style={{width:120}}><Bar value={data.score} max={100} color={data.verdict==="Phishing"?"#ef4444":data.verdict==="Suspicious"?"#f59e0b":"#10b981"}/></div>
                    <span style={{fontSize:12,fontFamily:"monospace",color:data.verdict==="Phishing"?"#ef4444":data.verdict==="Suspicious"?"#f59e0b":"#10b981",width:30,textAlign:"right"}}>{data.score}</span>
                    <VerdictBadge verdict={data.verdict}/>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
