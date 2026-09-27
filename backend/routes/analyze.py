"""
FastAPI Route Handlers for Threat Analysis API

Implements endpoints for URL security analysis, threat history, and system metrics.
"""

import re
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from backend.services.url_analyzer import analyze_url
from backend.database.database import save_analysis, get_recent_analyses, get_analysis_stats

router = APIRouter(prefix="/api", tags=["Analysis"])


class AnalyzeRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=3,
        max_length=2048,
        description="Target URL string to be analyzed for threat indicators.",
        json_schema_extra={"example": "https://login.paypal.com.verify-account.top/auth"}
    )


class IndicatorModel(BaseModel):
    id: str
    severity: str
    category: str
    message: str
    penalty: int


class AnalyzeResponse(BaseModel):
    url: str
    verdict: str
    risk_score: int
    confidence: float
    ml_probability: float
    indicators: List[IndicatorModel]
    explanation: str
    recommendation: str
    features: Optional[Dict[str, Any]] = None


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze URL for Phishing & Malicious Threat Indicators"
)
def analyze_target_url(payload: AnalyzeRequest):
    raw_url = payload.url.strip()

    if not raw_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL input cannot be empty."
        )

    # Basic URL format verification (must contain at least a domain or IP)
    url_pattern = r"^(https?://)?[a-zA-Z0-9.-]+(\.[a-zA-Z]{2,}|:\d+)?(/.*)?$"
    if not re.match(url_pattern, raw_url) and not re.match(r"^(https?://)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", raw_url):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Malformed URL format. Please enter a valid domain or IP address."
        )

    try:
        result = analyze_url(raw_url)
        # Save to database
        save_analysis(result)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error performing URL analysis: {str(e)}"
        )


@router.get(
    "/history",
    summary="Retrieve Recent Analysis Records"
)
def fetch_analysis_history(limit: int = Query(20, ge=1, le=100)):
    try:
        return get_recent_analyses(limit=limit)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch history: {str(e)}"
        )


@router.get(
    "/stats",
    summary="Retrieve Threat System Metrics & Statistics"
)
def fetch_system_stats():
    try:
        return get_analysis_stats()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch stats: {str(e)}"
        )
