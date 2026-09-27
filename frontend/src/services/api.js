/**
 * API Service Client for Backend Integration
 */

const API_BASE = '/api';

export async function checkHealth() {
  try {
    const res = await fetch(`${API_BASE}/health`);
    if (!res.ok) throw new Error('Health check failed');
    return await res.json();
  } catch (err) {
    return { status: 'offline', error: err.message };
  }
}

export async function analyzeUrl(url) {
  const res = await fetch(`${API_BASE}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.detail || 'Failed to analyze URL');
  }
  return data;
}

export async function getHistory(limit = 15) {
  try {
    const res = await fetch(`${API_BASE}/history?limit=${limit}`);
    if (!res.ok) throw new Error('Failed to fetch history');
    return await res.json();
  } catch (err) {
    console.error('History fetch error:', err);
    return [];
  }
}

export async function getStats() {
  try {
    const res = await fetch(`${API_BASE}/stats`);
    if (!res.ok) throw new Error('Failed to fetch statistics');
    return await res.json();
  } catch (err) {
    console.error('Stats fetch error:', err);
    return { total_analyzed: 0, breakdown: { SAFE: 0, SUSPICIOUS: 0, 'HIGH RISK': 0 } };
  }
}
