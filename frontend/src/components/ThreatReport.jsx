import React, { useState } from 'react';
import { AlertCircle, FileText, CheckCircle2, ChevronDown, ChevronUp, Cpu, Info } from 'lucide-react';

export default function ThreatReport({ result }) {
  const [showFeatures, setShowFeatures] = useState(false);

  if (!result) return null;

  const { url, indicators, explanation, recommendation, features } = result;

  return (
    <div className="report-section">
      {/* Target URL Header */}
      <div className="glass-card" style={{ padding: '16px 20px' }}>
        <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Analyzed Target Destination
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.95rem', color: 'var(--accent-cyan)', wordBreak: 'break-all', marginTop: '4px' }}>
          {url}
        </div>
      </div>

      {/* Detected Threat Indicators */}
      <div className="glass-card">
        <h3 className="section-title">
          <AlertCircle size={18} className="text-amber" />
          <span>Detected Threat Indicators ({indicators.length})</span>
        </h3>

        {indicators.length === 0 ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '12px 16px', background: 'var(--safe-bg)', border: '1px solid var(--safe-border)', borderRadius: '8px', color: 'var(--safe-green)', fontSize: '0.88rem' }}>
            <CheckCircle2 size={18} />
            <span>No explicit rule-based threat indicators were detected.</span>
          </div>
        ) : (
          <div className="indicators-grid">
            {indicators.map((ind, idx) => (
              <div key={idx} className="indicator-card">
                <span className={`severity-pill ${ind.severity}`}>
                  {ind.severity}
                </span>
                <div className="indicator-content">
                  <div className="indicator-header">
                    <span className="indicator-category">{ind.category}</span>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                      +{ind.penalty} pts
                    </span>
                  </div>
                  <p className="indicator-msg">{ind.message}</p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Explanation & Recommendation */}
      <div className="info-grid">
        <div className="info-card explanation">
          <div className="info-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <FileText size={16} color="var(--accent-cyan)" />
            <span>System Explanation</span>
          </div>
          <p className="info-text">{explanation}</p>
        </div>

        <div className="info-card recommendation">
          <div className="info-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Info size={16} color="var(--accent-purple)" />
            <span>Analyst Recommendation</span>
          </div>
          <p className="info-text">{recommendation}</p>
        </div>
      </div>

      {/* Extracted ML Features Inspector */}
      {features && (
        <div className="glass-card">
          <button
            onClick={() => setShowFeatures(!showFeatures)}
            style={{
              width: '100%',
              background: 'none',
              border: 'none',
              color: 'var(--text-main)',
              cursor: 'pointer',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              fontSize: '0.9rem',
              fontWeight: '600'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Cpu size={16} color="var(--accent-cyan)" />
              <span>Inspect Raw Extracted ML Features ({Object.keys(features).length})</span>
            </div>
            {showFeatures ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
          </button>

          {showFeatures && (
            <div className="features-grid">
              {Object.entries(features).map(([key, val]) => (
                <div key={key} className="feature-box">
                  <div className="feature-key">{key}</div>
                  <div className="feature-val">{String(val)}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
