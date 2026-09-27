import React from 'react';
import { ShieldCheck, AlertTriangle, ShieldAlert } from 'lucide-react';

export default function RiskScoreVisualizer({ result }) {
  if (!result) return null;

  const { verdict, risk_score, confidence, ml_probability } = result;

  // Gauge geometry calculation
  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  const progressOffset = circumference - (risk_score / 100) * circumference;

  let gaugeColor = '#10b981'; // Green
  if (risk_score >= 70) gaugeColor = '#ef4444'; // Red
  else if (risk_score >= 31) gaugeColor = '#f59e0b'; // Amber

  const verdictClass = verdict.replace(' ', '-');

  const renderIcon = () => {
    if (verdict === 'HIGH RISK') return <ShieldAlert size={18} />;
    if (verdict === 'SUSPICIOUS') return <AlertTriangle size={18} />;
    return <ShieldCheck size={18} />;
  };

  return (
    <div className="glass-card risk-card">
      <h3 style={{ fontSize: '0.9rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
        Threat Risk Score
      </h3>

      <div className="score-gauge">
        <svg className="gauge-svg" viewBox="0 0 160 160">
          <circle
            className="gauge-bg"
            cx="80"
            cy="80"
            r={radius}
          />
          <circle
            className="gauge-progress"
            cx="80"
            cy="80"
            r={radius}
            stroke={gaugeColor}
            strokeDasharray={circumference}
            strokeDashoffset={progressOffset}
          />
        </svg>
        <div className="score-center">
          <span className="score-number" style={{ color: gaugeColor }}>
            {risk_score}
          </span>
          <span className="score-max">/ 100</span>
        </div>
      </div>

      <div className={`verdict-badge ${verdictClass}`}>
        {renderIcon()}
        <span>{verdict}</span>
      </div>

      <div className="confidence-rate">
        Confidence Rating: <strong>{(confidence * 100).toFixed(0)}%</strong>
        <span style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '4px' }}>
          ML Probability: {(ml_probability * 100).toFixed(1)}%
        </span>
      </div>
    </div>
  );
}
