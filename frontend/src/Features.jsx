export default function Features() {
  const cards = [
    { num:"01", icon:"search", title:"URL Intelligence", desc:"45 hand-engineered features including URL entropy, domain length, digit ratio, subdomain depth, hyphen count, and path analysis.", tags:["Entropy","Typosquatting","Homoglyphs","DGA Detection"] },
    { num:"02", icon:"brain",  title:"ML Ensemble",      desc:"Three models vote together — Random Forest, XGBoost, and Neural Network — for maximum accuracy with soft-voting probability blending.", tags:["Random Forest","XGBoost","Neural Network","Soft Voting"] },
    { num:"03", icon:"shield", title:"Google Safe Browsing", desc:"Every URL is cross-checked against Google's live threat database covering malware, phishing, and unwanted software.", tags:["Malware","Phishing","Real-Time","Google API"] },
    { num:"04", icon:"virus",  title:"VirusTotal",       desc:"Domains are scanned across 70+ antivirus and security engines simultaneously for comprehensive threat coverage.", tags:["70+ Engines","Multi-AV","Domain Scan","Threat Intel"] },
    { num:"05", icon:"calendar", title:"WHOIS Intelligence", desc:"Domain registration age analysis — newly registered domains under 30 days are a massive phishing signal and scored heavily.", tags:["Domain Age","Registrar","DNS","New Domains"] },
    { num:"06", icon:"target", title:"Brand Impersonation", desc:"Detects when phishing sites impersonate PayPal, Apple, Google, Microsoft and 15+ major brands using homoglyph and typosquat analysis.", tags:["Brand Protection","Homoglyphs","Typosquatting","15+ Brands"] },
    { num:"07", icon:"mail",   title:"Gmail Protection", desc:"Real-time scanning of links inside Gmail emails. Dangerous links get red badges, suspicious ones get amber badges automatically.", tags:["Gmail","Email Links","Auto Scan","Real-Time"] },
    { num:"08", icon:"lock",   title:"Login Form Detection", desc:"Detects password fields on suspicious pages and shows a warning banner before you enter your credentials on a fake login page.", tags:["Password Fields","Fake Logins","Warning Banner","Browser"] },
    { num:"09", icon:"zap",    title:"Explainable AI",   desc:"Every verdict comes with human-readable reasons — not just a score. You always know exactly why a URL was flagged.", tags:["Explainable","Transparent","Reasons","Human-Centered"] },
  ];
  const svgs = {
    search:   <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>,
    brain:    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2"><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96-.46 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.44-4.14Z"/><path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96-.46 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.44-4.14Z"/></svg>,
    shield:   <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2"><path d="M12 3l9 4.5v5C21 17.25 17 21.5 12 23c-5-1.5-9-5.75-9-10.5v-5L12 3z"/></svg>,
    virus:    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>,
    calendar: <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>,
    target:   <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>,
    mail:     <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>,
    lock:     <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>,
    zap:      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>,
  };
  return (
    <div style={{minHeight:"100vh",background:"#04060f",color:"#e2e8f0",fontFamily:"system-ui,sans-serif",padding:"60px 28px"}}>
      <div style={{maxWidth:1160,margin:"0 auto"}}>
        <div style={{textAlign:"center",marginBottom:56}}>
          <div style={{display:"inline-flex",alignItems:"center",gap:8,background:"rgba(59,130,246,0.08)",border:"1px solid rgba(59,130,246,0.2)",color:"#93c5fd",padding:"6px 14px",borderRadius:999,fontSize:12,fontWeight:700,letterSpacing:"0.8px",textTransform:"uppercase",marginBottom:20}}><span style={{width:6,height:6,borderRadius:"50%",background:"#3b82f6",display:"inline-block"}}/>Full Feature Set</div>
          <h1 style={{fontSize:48,fontWeight:800,letterSpacing:-2,marginBottom:16}}>Everything PhishGuard detects</h1>
          <p style={{fontSize:16,color:"#64748b",maxWidth:560,margin:"0 auto",lineHeight:1.8}}>9 detection layers working together to protect you from phishing attacks before they happen.</p>
        </div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:20}}>
          {cards.map(c=>(
            <div key={c.num} style={{background:"#0c1220",border:"1px solid #1e2d45",borderRadius:20,padding:28,position:"relative",overflow:"hidden"}}>
              <div style={{position:"absolute",top:0,left:0,right:0,height:2,background:"linear-gradient(90deg,#1d4ed8,#0e7490)"}}/>
              <div style={{fontSize:11,color:"#64748b",fontFamily:"monospace",letterSpacing:1,marginBottom:14}}>{c.num}</div>
              <div style={{width:44,height:44,borderRadius:12,background:"rgba(59,130,246,0.08)",border:"1px solid rgba(59,130,246,0.2)",display:"flex",alignItems:"center",justifyContent:"center",marginBottom:16}}>{svgs[c.icon]}</div>
              <h3 style={{fontSize:18,fontWeight:800,marginBottom:10}}>{c.title}</h3>
              <p style={{fontSize:13,color:"#64748b",lineHeight:1.7,marginBottom:16}}>{c.desc}</p>
              <div style={{display:"flex",flexWrap:"wrap",gap:6}}>{c.tags.map(t=>(<span key={t} style={{fontSize:10,fontFamily:"monospace",padding:"2px 8px",borderRadius:999,background:"rgba(59,130,246,0.08)",border:"1px solid rgba(59,130,246,0.2)",color:"#60a5fa"}}>{t}</span>))}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}