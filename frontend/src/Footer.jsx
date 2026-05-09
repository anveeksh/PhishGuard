export default function Footer() {
  const year = new Date().getFullYear();
  const githubIcon = (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/></svg>);
  const linkedinIcon = (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M16 8a6 6 0 0 1 6 6v7h-4v-7a2 2 0 0 0-2-2 2 2 0 0 0-2 2v7h-4v-7a6 6 0 0 1 6-6z"/><rect x="2" y="9" width="4" height="12"/><circle cx="4" cy="4" r="2"/></svg>);
  const instagramIcon = (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="2" width="20" height="20" rx="5" ry="5"/><path d="M16 11.37A4 4 0 1 1 12.63 8 4 4 0 0 1 16 11.37z"/><line x1="17.5" y1="6.5" x2="17.51" y2="6.5"/></svg>);
  const globeIcon = (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>);
  const shieldIcon = (<svg viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2.5" strokeLinejoin="round"><path d="M12 3l9 4.5v5C21 17.25 17 21.5 12 23c-5-1.5-9-5.75-9-10.5v-5L12 3z"/><path d="M9 12l2 2 4-4" stroke="#fff" strokeWidth="2" strokeLinecap="round"/></svg>);
  return (
    <footer className="pg-footer-section">
      <div className="pg-footer-top">
        <div className="pg-footer-brand">
          <div className="logo"><div className="logo-icon">{shieldIcon}</div>PhishGuard</div>
          <p className="pg-footer-bio">PhishGuard is built by Anveeksh Mahesh Rao, an MS cybersecurity researcher specializing in phishing detection, explainable AI, human-centered security, and usable security systems for designing defenses that people can understand and trust.</p>
          <div className="pg-footer-socials">
            <a href="https://www.anveekshmrao.com" target="_blank" rel="noreferrer" className="pg-social-btn" title="Website">{globeIcon}</a>
            <a href="https://www.linkedin.com/in/anveekshmrao/" target="_blank" rel="noreferrer" className="pg-social-btn" title="LinkedIn">{linkedinIcon}</a>
            <a href="https://www.instagram.com/anveekshrao/" target="_blank" rel="noreferrer" className="pg-social-btn" title="Instagram">{instagramIcon}</a>
            <a href="https://github.com/anveeksh" target="_blank" rel="noreferrer" className="pg-social-btn" title="GitHub">{githubIcon}</a>
          </div>
          <div className="pg-footer-status"><span className="status-dot"/>All systems operational</div>
        </div>
        <div className="pg-footer-col">
          <h5>Product</h5>
          <ul>
            <li><a href="#">URL Scanner</a></li>
            <li><a href="#">Security Dashboard</a></li>
            <li><a href="#">Chrome Extension</a></li>
            <li><a href="#">Gmail Protection</a></li>
            <li><a href="#">Login Form Detection</a></li>
            <li><a href="#">API Access</a></li>
          </ul>
        </div>
        <div className="pg-footer-col">
          <h5>Intelligence</h5>
          <ul>
            <li><a href="#">ML Ensemble</a></li>
            <li><a href="#">Rule Engine</a></li>
            <li><a href="#">Google Safe Browsing</a></li>
            <li><a href="#">VirusTotal</a></li>
            <li><a href="#">WHOIS Analysis</a></li>
            <li><a href="#">Threat Database</a></li>
          </ul>
        </div>
        <div className="pg-footer-col">
          <h5>Research</h5>
          <ul>
            <li><a href="https://github.com/anveeksh/PhishGuard" target="_blank" rel="noreferrer">GitHub Repo</a></li>
            <li><a href="https://www.anveekshmrao.com" target="_blank" rel="noreferrer">Portfolio</a></li>
            <li><a href="https://www.linkedin.com/in/anveekshmrao/" target="_blank" rel="noreferrer">LinkedIn</a></li>
            <li><a href="#">Documentation</a></li>
            <li><a href="#">Phishing Dataset</a></li>
            <li><a href="#">Research Paper</a></li>
          </ul>
        </div>
      </div>
      <div className="pg-footer-bottom">
        <div className="pg-footer-copy">© {year} PhishGuard · <a href="https://www.anveekshmrao.com" target="_blank" rel="noreferrer">Anveeksh Mahesh Rao</a> · All rights reserved</div>
        <div className="pg-footer-badges"><span className="pg-footer-badge">ML-POWERED</span><span className="pg-footer-badge">OPEN SOURCE</span><span className="pg-footer-badge">v2.0</span></div>
        <div className="pg-footer-made">Built with <span className="pg-footer-heart">♥</span> by <a href="https://www.anveekshmrao.com" target="_blank" rel="noreferrer">Anveeksh</a></div>
      </div>
    </footer>
  );
}
