import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import StatsCards from './components/StatsCards';
import UrlInputForm from './components/UrlInputForm';
import RiskScoreVisualizer from './components/RiskScoreVisualizer';
import ThreatReport from './components/ThreatReport';
import HistoryPanel from './components/HistoryPanel';
import { checkHealth, analyzeUrl, getHistory, getStats } from './services/api';
import { AlertCircle } from 'lucide-react';

export default function App() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const [systemHealth, setSystemHealth] = useState(null);
  const [history, setHistory] = useState([]);
  const [stats, setStats] = useState(null);

  // Load initial system stats & history and poll system health
  useEffect(() => {
    async function loadData() {
      const health = await checkHealth();
      setSystemHealth(health);

      const histData = await getHistory(10);
      setHistory(histData);

      const statsData = await getStats();
      setStats(statsData);
    }
    loadData();

    const healthInterval = setInterval(async () => {
      const health = await checkHealth();
      setSystemHealth(health);
    }, 5000);

    return () => clearInterval(healthInterval);
  }, []);

  const handleAnalyze = async (targetUrl) => {
    setLoading(true);
    setError(null);
    try {
      const res = await analyzeUrl(targetUrl);
      setResult(res);

      // Refresh history and stats after new analysis
      const updatedHistory = await getHistory(10);
      setHistory(updatedHistory);

      const updatedStats = await getStats();
      setStats(updatedStats);
    } catch (err) {
      setError(err.message || 'An unexpected error occurred during analysis.');
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  const handleSelectHistoryItem = (item) => {
    setUrl(item.url);
    setResult(item);
    window.scrollTo({ top: 300, behavior: 'smooth' });
  };

  return (
    <div className="app-container">
      <Header systemHealth={systemHealth} />

      <StatsCards stats={stats} />

      <UrlInputForm
        url={url}
        setUrl={setUrl}
        onAnalyze={handleAnalyze}
        loading={loading}
        error={error}
      />

      {result && (
        <div className="dashboard-grid">
          <RiskScoreVisualizer result={result} />
          <ThreatReport result={result} />
        </div>
      )}

      {/* Security Disclaimer Banner */}
      <div className="disclaimer-banner">
        <AlertCircle size={20} />
        <div>
          <strong>Educational & Defensive Security Disclaimer:</strong> Static URL analysis provides a risk assessment based on structural patterns, lexical features, and machine learning heuristics. <em>Performance on the development dataset does not guarantee real-world phishing detection accuracy.</em> No security tool can guarantee that a URL is safe. Always verify domain authenticity independently.
        </div>
      </div>

      <HistoryPanel history={history} onSelectHistory={handleSelectHistoryItem} />
    </div>
  );
}
