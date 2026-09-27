import React from 'react';
import { History, ExternalLink } from 'lucide-react';

export default function HistoryPanel({ history, onSelectHistory }) {
  if (!history || history.length === 0) return null;

  return (
    <div className="glass-card history-section">
      <h3 className="section-title">
        <History size={18} color="var(--accent-cyan)" />
        <span>Recent Analysis History ({history.length})</span>
      </h3>

      <div style={{ display: 'flex', flexDirection: 'column' }}>
        {history.map((item) => {
          const vClass = item.verdict.replace(' ', '-');
          return (
            <div
              key={item.id}
              className="history-item"
              onClick={() => onSelectHistory(item)}
              title="Click to view detailed analysis"
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <span className={`verdict-badge ${vClass}`} style={{ padding: '2px 10px', fontSize: '0.72rem' }}>
                  {item.verdict}
                </span>
                <span className="history-url">{item.url}</span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem', color: 'var(--text-dim)' }}>
                  Score: {item.risk_score}/100
                </span>
                <ExternalLink size={14} color="var(--text-muted)" />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
