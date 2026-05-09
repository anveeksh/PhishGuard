export default function Extension() {
  const steps = [
    { num:"01", title:"Download the Extension", desc:"Clone the PhishGuard GitHub repo or download the extension folder directly from github.com/anveeksh/PhishGuard." },
    { num:"02", title:"Open Chrome Extensions", desc:'Go to chrome://extensions in your browser and enable Developer Mode in the top right corner.' },
    { num:"03", title:"Load Unpacked", desc:'Click Load unpacked and select the /extension folder from the PhishGuard project directory.' },
    { num:"04", title:"Start Backend", desc:"Run uvicorn main:app --reload in your backend folder. The extension connects to http://127.0.0.1:8000." },
    { num:"05", title:"Pin and Use", desc:"Pin PhishGuard to your toolbar. Click the icon to scan any page, or let it auto-scan links in the background." },
  ];
  const features = [
    { icon:"search", title:"Popup Scanner",      desc:"Click the extension icon to instantly scan the current page you are visiting." },
    { icon:"link",   title:"Auto Link Scan",     desc:"Automatically scans up to 50 links on every webpage and highlights dangerous ones." },
    { icon:"warn",   title:"Click Interception", desc:"Intercepts clicks on suspicious links and shows a full warning dialog before navigation." },
    { icon:"mail",   title:"Gmail Scanner",      desc:"Scans all links inside Gmail emails and adds risk badges next to dangerous ones." },
    { icon:"lock",   title:"Login Protection",   desc:"Detects password fields on suspicious pages and warns before you enter credentials." },
    { icon:"check",  title:"Trusted Domains",    desc:"Never flags Apple, Google, GitHub and 30+ trusted domains — zero false positives." },
  ];
  const svgs = {
    search: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>,
    link:   <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>,
    warn:   <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
    mail:   <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>,
    lock:   <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>,
    check:  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>,
  };
  return (
    <div style={{minHeight:"100vh",background:"#04060f",color:"#e2e8f0",fontFamily:"system-ui,sans-serif",padding:"60px 28px"}}>
      <div style={{maxWidth:1160,margin:"0 auto"}}>
        <div style={{textAlign:"center",marginBottom:56}}>
          <div style={{display:"inline-flex",alignItems:"center",gap:8,background:"rgba(59,130,246,0.08)",border:"1px solid rgba(59,130,246,0.2)",color:"#93c5fd",padding:"6px 14px",borderRadius:999,fontSize:12,fontWeight:700,letterSpacing:"0.8px",textTransform:"uppercase",marginBottom:20}}><span style={{width:6,height:6,borderRadius:"50%",background:"#3b82f6",display:"inline-block"}}/>Chrome Extension</div>
          <h1 style={{fontSize:48,fontWeight:800,letterSpacing:-2,marginBottom:16}}>Real-time browser protection</h1>
          <p style={{fontSize:16,color:"#64748b",maxWidth:560,margin:"0 auto",lineHeight:1.8,marginBottom:24}}>PhishGuard works silently in the background, scanning every link before you click it.</p>
          <a href="https://github.com/anveeksh/PhishGuard/releases/latest" target="_blank" rel="noreferrer" style={{display:"inline-flex",alignItems:"center",gap:8,background:"linear-gradient(135deg,#1d4ed8,#0e7490)",color:"#fff",padding:"13px 28px",borderRadius:12,fontWeight:800,fontSize:14,textDecoration:"none"}}>Download from GitHub</a>
        </div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:16,marginBottom:48}}>
          {features.map(f=>(<div key={f.title} style={{background:"#0c1220",border:"1px solid #1e2d45",borderRadius:18,padding:24}}>
            <div style={{width:40,height:40,borderRadius:10,background:"rgba(59,130,246,0.08)",border:"1px solid rgba(59,130,246,0.2)",display:"flex",alignItems:"center",justifyContent:"center",marginBottom:14}}>{svgs[f.icon]}</div>
            <h3 style={{fontSize:16,fontWeight:800,marginBottom:8}}>{f.title}</h3>
            <p style={{fontSize:13,color:"#64748b",lineHeight:1.7}}>{f.desc}</p>
          </div>))}
        </div>
        <div style={{background:"#0c1220",border:"1px solid #1e2d45",borderRadius:20,padding:40}}>
          <h2 style={{fontSize:24,fontWeight:800,marginBottom:32,textAlign:"center"}}>How to install</h2>
          <div style={{display:"flex",flexDirection:"column",gap:12}}>
            {steps.map(s=>(<div key={s.num} style={{display:"flex",gap:20,alignItems:"flex-start",padding:"16px 20px",background:"#080d1a",borderRadius:14,border:"1px solid #1e2d45"}}>
              <div style={{width:36,height:36,borderRadius:10,background:"linear-gradient(135deg,#1d4ed8,#0e7490)",display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0,fontSize:12,fontWeight:800,fontFamily:"monospace",color:"#fff"}}>{s.num}</div>
              <div><h4 style={{fontSize:15,fontWeight:800,marginBottom:4}}>{s.title}</h4><p style={{fontSize:13,color:"#64748b",lineHeight:1.6,margin:0}}>{s.desc}</p></div>
            </div>))}
          </div>
        </div>
      </div>
    </div>
  );
}