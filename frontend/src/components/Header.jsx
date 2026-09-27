import React from 'react';
import { Server } from 'lucide-react';
import logo from '../assets/logo.png';

export default function Header({ systemHealth }) {
  const isOnline = systemHealth && systemHealth.status === 'ok';

  return (
    <header className="header">
      <div className="brand">
        <div className="brand-icon" title="AI-Powered Phishing & Threat Detection System">
          <img src={logo} alt="AI-Powered Phishing & Threat Detection System Logo" className="brand-logo-img" />
        </div>
        <div>
          <h1 className="brand-title">AI-Powered Phishing & Threat Detection System</h1>
          <p className="brand-subtitle">Defensive Cyber Threat Intelligence & ML Analysis</p>
        </div>
      </div>

      <div className={`status-badge ${isOnline ? 'online' : 'offline'}`} title="System Connection Status">
        <Server size={14} className="status-icon" />
        <span className={`status-dot ${isOnline ? 'online' : 'offline'}`} />
        <span className="status-text">{isOnline ? 'API Online' : 'API Offline'}</span>
      </div>
    </header>
  );
}
