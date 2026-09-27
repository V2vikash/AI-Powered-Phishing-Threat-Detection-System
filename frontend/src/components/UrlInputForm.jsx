import React from 'react';
import { Search, Loader2, ShieldCheck, AlertTriangle } from 'lucide-react';

export default function UrlInputForm({ url, setUrl, onAnalyze, loading, error }) {
  const handleSubmit = (e) => {
    e.preventDefault();
    if (url.trim()) {
      onAnalyze(url.trim());
    }
  };

  const handlePreset = (presetUrl) => {
    setUrl(presetUrl);
    onAnalyze(presetUrl);
  };

  return (
    <div className="glass-card hero-panel">
      <div className="hero-header">
        <h2 className="hero-title">Analyze Any URL For Phishing & Cyber Threats</h2>
        <p className="hero-description">
          Extract defensive lexical, structural, and statistical features powered by machine learning algorithms 
          and heuristic threat rules for real-time risk assessment.
        </p>
      </div>

      <form onSubmit={handleSubmit} className="url-form">
        <div className="input-wrapper">
          <Search size={18} className="input-icon" />
          <input
            type="text"
            className="url-input"
            placeholder="Enter target URL (e.g. https://example.com or 192.168.1.1/login)"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={loading}
            maxLength={2048}
            required
            aria-label="Target URL Input"
          />
        </div>

        <button type="submit" className="btn-analyze" disabled={loading || !url.trim()}>
          {loading ? (
            <>
              <Loader2 size={18} className="animate-spin" />
              <span>Analyzing...</span>
            </>
          ) : (
            <>
              <ShieldCheck size={18} />
              <span>Analyze Threat</span>
            </>
          )}
        </button>
      </form>

      {error && (
        <div className="error-banner">
          <AlertTriangle size={16} />
          <span>{error}</span>
        </div>
      )}

      <div className="presets-bar">
        <span className="preset-label">Test Samples:</span>
        <button
          type="button"
          className="preset-chip chip-safe"
          onClick={() => handlePreset('https://www.wikipedia.org/wiki/Main_Page')}
          disabled={loading}
        >
          <span className="chip-dot safe" />
          Safe URL
        </button>
        <button
          type="button"
          className="preset-chip chip-suspicious"
          onClick={() => handlePreset('http://paypal.com.verify-billing.account-update.xyz/login/confirm')}
          disabled={loading}
        >
          <span className="chip-dot suspicious" />
          Suspicious Keywords
        </button>
        <button
          type="button"
          className="preset-chip chip-highrisk"
          onClick={() => handlePreset('http://185.220.101.5/login-paypal-verify/account.php')}
          disabled={loading}
        >
          <span className="chip-dot highrisk" />
          IP-Based Phish
        </button>
        <button
          type="button"
          className="preset-chip chip-warning"
          onClick={() => handlePreset('http://www.google.com.security-auth-check.info/login')}
          disabled={loading}
        >
          <span className="chip-dot warning" />
          TLD Spoofing
        </button>
      </div>
    </div>
  );
}
