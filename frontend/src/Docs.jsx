export default function Docs() {
  const endpoints = [
    { method:"GET",  path:"/",            desc:"Health check — returns API status and version." },
    { method:"POST", path:"/scan-url",    desc:"Scan a URL. Body: { url: string }. Returns full threat analysis." },
    { method:"POST", path:"/scan-text",   desc:"Scan email or message text for phishing language. Body: { text: string }." },
    { method:"GET",  path:"/history",     desc:"Returns last 20 scanned URLs with full results." },
    { method:"POST", path:"/explain",     desc:"Get a human-readable explanation of why a URL was flagged." },
  ];
  const fields = [
    { field:"url",            type:"string",  desc:"Normalized URL that was scanned" },
    { field:"domain",         type:"string",  desc:"Extracted domain name" },
    { field:"verdict",        type:"string",  desc:"Safe | Suspicious | Phishing" },
    { field:"severity",       type:"string",  desc:"Low | Medium | Critical" },
    { field:"risk_score",     type:"integer", desc:"0 to 100 combined risk score" },
    { field:"rule_score",     type:"integer", desc:"Score from rule engine only" },
    { field:"ml_score",       type:"integer", desc:"Score from ML ensemble" },
    { field:"reasons",        type:"array",   desc:"List of human-readable threat signals" },
    { field:"gsb_flagged",    type:"boolean", desc:"Whether Google Safe Browsing flagged it" },
    { field:"vt_malicious",   type:"integer", desc:"Number of VirusTotal engines that flagged it" },
    { field:"whois_age_days", type:"integer", desc:"Domain age in days" },
    { field:"whois_created",  type:"string",  desc:"Domain registration date" },
    { field:"whois_registrar",type:"string",  desc:"Domain registrar name" },
  ];
  const mc = {GET:"#10b981", POST:"#3b82f6"};
  return (
    <div style={{minHeight:"100vh",background:"#04060f",color:"#e2e8f0",fontFamily:"system-ui,sans-serif",padding:"60px 28px"}}>
      <div style={{maxWidth:900,margin:"0 auto"}}>
        <div style={{marginBottom:48}}>
          <div style={{display:"inline-flex",alignItems:"center",gap:8,background:"rgba(59,130,246,0.08)",border:"1px solid rgba(59,130,246,0.2)",color:"#93c5fd",padding:"6px 14px",borderRadius:999,fontSize:12,fontWeight:700,letterSpacing:"0.8px",textTransform:"uppercase",marginBottom:20}}><span style={{width:6,height:6,borderRadius:"50%",background:"#3b82f6",display:"inline-block"}}/>API Documentation</div>
          <h1 style={{fontSize:48,fontWeight:800,letterSpacing:-2,marginBottom:16}}>PhishGuard API</h1>
          <p style={{fontSize:16,color:"#64748b",lineHeight:1.8}}>Base URL: <code style={{background:"#0c1220",padding:"2px 8px",borderRadius:6,fontFamily:"monospace",color:"#60a5fa"}}>http://127.0.0.1:8000</code></p>
        </div>
        <div style={{background:"#0c1220",border:"1px solid #1e2d45",borderRadius:20,padding:28,marginBottom:24}}>
          <h2 style={{fontSize:20,fontWeight:800,marginBottom:20}}>Endpoints</h2>
          <div style={{display:"flex",flexDirection:"column",gap:12}}>
            {endpoints.map(e=>(<div key={e.path} style={{display:"flex",alignItems:"flex-start",gap:14,padding:"14px 16px",background:"#080d1a",borderRadius:12,border:"1px solid #1e2d45"}}>
              <span style={{fontSize:11,fontWeight:800,fontFamily:"monospace",padding:"3px 10px",borderRadius:999,background:`${mc[e.method]}20`,border:`1px solid ${mc[e.method]}40`,color:mc[e.method],flexShrink:0,marginTop:1}}>{e.method}</span>
              <div><code style={{fontSize:14,fontFamily:"monospace",color:"#e2e8f0",display:"block",marginBottom:4}}>{e.path}</code><p style={{fontSize:13,color:"#64748b",margin:0}}>{e.desc}</p></div>
            </div>))}
          </div>
        </div>
        <div style={{background:"#0c1220",border:"1px solid #1e2d45",borderRadius:20,padding:28,marginBottom:24}}>
          <h2 style={{fontSize:20,fontWeight:800,marginBottom:8}}>Example Request</h2>
          <p style={{fontSize:13,color:"#64748b",marginBottom:16}}>POST /scan-url</p>
          <pre style={{background:"#080d1a",border:"1px solid #1e2d45",borderRadius:12,padding:20,fontSize:13,fontFamily:"monospace",color:"#94a3b8",overflow:"auto",whiteSpace:"pre-wrap"}}>{"curl -X POST http://127.0.0.1:8000/scan-url -H \"Content-Type: application/json\" -d '{\"url\": \"https://paypal-secure-login.xyz\"}'"}
          </pre>
        </div>
        <div style={{background:"#0c1220",border:"1px solid #1e2d45",borderRadius:20,padding:28,marginBottom:24}}>
          <h2 style={{fontSize:20,fontWeight:800,marginBottom:20}}>Response Fields</h2>
          <div style={{display:"flex",flexDirection:"column",gap:8}}>
            {fields.map(r=>(<div key={r.field} style={{display:"grid",gridTemplateColumns:"180px 80px 1fr",gap:12,padding:"10px 14px",background:"#080d1a",borderRadius:10,border:"1px solid #1e2d45",alignItems:"center"}}>
              <code style={{fontSize:13,fontFamily:"monospace",color:"#60a5fa"}}>{r.field}</code>
              <span style={{fontSize:11,fontFamily:"monospace",color:"#f59e0b"}}>{r.type}</span>
              <span style={{fontSize:13,color:"#64748b"}}>{r.desc}</span>
            </div>))}
          </div>
        </div>
        <div style={{background:"#0c1220",border:"1px solid #1e2d45",borderRadius:20,padding:28}}>
          <h2 style={{fontSize:20,fontWeight:800,marginBottom:16}}>Quick Start</h2>
          <div style={{display:"flex",flexDirection:"column",gap:10}}>
            {[
              "pip install fastapi uvicorn scikit-learn xgboost numpy pandas httpx python-whois",
              "cd backend && uvicorn main:app --reload",
              "cd frontend && npm install && npm run dev",
              "# Open http://localhost:5173"
            ].map((cmd,i)=>(<div key={i} style={{display:"flex",gap:12,alignItems:"center",padding:"12px 16px",background:"#080d1a",borderRadius:10,border:"1px solid #1e2d45"}}>
              <span style={{fontSize:11,color:"#334155",fontFamily:"monospace",flexShrink:0}}>{String(i+1).padStart(2,"0")}</span>
              <code style={{fontSize:13,fontFamily:"monospace",color:cmd.startsWith("#")?"#64748b":"#94a3b8"}}>{cmd}</code>
            </div>))}
          </div>
        </div>
      </div>
    </div>
  );
}