import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, Activity } from 'lucide-react';

export default function StatsCards({ stats }) {
  if (!stats) return null;

  const { total_analyzed = 0, breakdown = {} } = stats;

  return (
    <div className="stats-row">
      <div className="stat-card">
        <div className="stat-icon total">
          <Activity size={20} />
        </div>
        <div className="stat-content">
          <div className="stat-val">{total_analyzed}</div>
          <div className="stat-lbl">Total URLs Scanned</div>
        </div>
      </div>

      <div className="stat-card">
        <div className="stat-icon highrisk">
          <ShieldAlert size={20} />
        </div>
        <div className="stat-content">
          <div className="stat-val highrisk">
            {breakdown['HIGH RISK'] || 0}
          </div>
          <div className="stat-lbl">High Risk Threats</div>
        </div>
      </div>

      <div className="stat-card">
        <div className="stat-icon suspicious">
          <AlertTriangle size={20} />
        </div>
        <div className="stat-content">
          <div className="stat-val suspicious">
            {breakdown['SUSPICIOUS'] || 0}
          </div>
          <div className="stat-lbl">Suspicious Anomalies</div>
        </div>
      </div>

      <div className="stat-card">
        <div className="stat-icon safe">
          <ShieldCheck size={20} />
        </div>
        <div className="stat-content">
          <div className="stat-val safe">
            {breakdown['SAFE'] || 0}
          </div>
          <div className="stat-lbl">Safe Domains Verified</div>
        </div>
      </div>
    </div>
  );
}
