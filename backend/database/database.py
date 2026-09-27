"""
SQLite Database Storage Layer

Provides persistence for URL analysis history and analytics using SQLite3.
"""

import os
import json
import sqlite3
from typing import List, Dict, Any

DB_PATH = os.path.join(os.path.dirname(__file__), "phishing_analysis.db")


def get_connection():
    """Establishes and returns a database connection."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes schema and tables if they do not exist."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                verdict TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                confidence REAL NOT NULL,
                ml_probability REAL NOT NULL,
                indicators_json TEXT NOT NULL,
                explanation TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()


# Ensure DB is ready on import
init_db()


def save_analysis(result: Dict[str, Any]) -> int:
    """Saves analysis output record to database and returns record ID."""
    indicators_json = json.dumps(result.get("indicators", []))
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO analysis_history 
            (url, verdict, risk_score, confidence, ml_probability, indicators_json, explanation, recommendation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result["url"],
            result["verdict"],
            result["risk_score"],
            result["confidence"],
            result["ml_probability"],
            indicators_json,
            result["explanation"],
            result["recommendation"]
        ))
        conn.commit()
        return cursor.lastrowid


def get_recent_analyses(limit: int = 20) -> List[Dict[str, Any]]:
    """Retrieves recent analysis records sorted by creation timestamp."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, url, verdict, risk_score, confidence, ml_probability, 
                   indicators_json, explanation, recommendation, created_at
            FROM analysis_history
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        
        results = []
        for row in rows:
            record = dict(row)
            try:
                record["indicators"] = json.loads(record["indicators_json"])
            except Exception:
                record["indicators"] = []
            del record["indicators_json"]
            results.append(record)
        return results


def get_analysis_stats() -> Dict[str, Any]:
    """Returns aggregated threat detection metrics."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as total FROM analysis_history")
        total = cursor.fetchone()["total"]

        cursor.execute("SELECT verdict, COUNT(*) as count FROM analysis_history GROUP BY verdict")
        rows = cursor.fetchall()
        
        breakdown = {"SAFE": 0, "SUSPICIOUS": 0, "HIGH RISK": 0}
        for row in rows:
            if row["verdict"] in breakdown:
                breakdown[row["verdict"]] = row["count"]

        return {
            "total_analyzed": total,
            "breakdown": breakdown
        }
