#!/usr/bin/env python3
"""
Anchor MCP Server Process
A standalone MCP server for AI scam protection context enrichment.
Runs on localhost:8000 and provides scam detection tools and context.
"""

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta

from enrichmcp import EnrichMCP
from pydantic import BaseModel
from fastapi import FastAPI
import uvicorn

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ScamContext(BaseModel):
    """Model for scam detection context"""
    risk_score: float
    risk_factors: List[str]
    threat_type: Optional[str] = None
    confidence: float
    recommendations: List[str]
    analysis_timestamp: datetime

class URLAnalysis(BaseModel):
    """Model for URL analysis results"""
    url: str
    is_suspicious: bool
    domain_age: Optional[int] = None
    ssl_valid: bool
    blacklisted: bool
    phishing_indicators: List[str]
    reputation_score: float

class MessageAnalysis(BaseModel):
    """Model for message/text analysis"""
    text: str
    urgency_score: float
    emotional_manipulation: float
    financial_request: bool
    suspicious_patterns: List[str]
    language_analysis: Dict[str, Any]

# Mock databases for demonstration
KNOWN_SCAM_DOMAINS = {
    "fake-bank-login.com",
    "urgent-security-alert.net", 
    "your-account-suspended.org",
    "claim-your-prize-now.co",
    "verify-payment-info.biz"
}

SCAM_KEYWORDS = [
    "urgent", "immediate action", "limited time", "act now", "suspended account",
    "verify your account", "click here immediately", "congratulations you won",
    "tax refund", "inheritance", "lottery winner", "suspicious activity",
    "frozen account", "update payment", "confirm identity"
]

FINANCIAL_KEYWORDS = [
    "wire transfer", "bitcoin", "cryptocurrency", "gift card", "prepaid card",
    "western union", "moneygram", "bank account", "routing number", 
    "social security", "ssn", "credit card", "payment details"
]

def analyze_url_reputation(url: str) -> URLAnalysis:
    """Analyze URL for scam indicators"""
    domain = url.split("//")[-1].split("/")[0].lower()
    
    is_suspicious = domain in KNOWN_SCAM_DOMAINS
    blacklisted = domain in KNOWN_SCAM_DOMAINS
    
    phishing_indicators = []
    if any(keyword in domain for keyword in ["secure", "login", "verify", "update"]):
        phishing_indicators.append("Suspicious keywords in domain")
    
    if domain.count("-") > 2:
        phishing_indicators.append("Excessive hyphens in domain")
    
    if any(tld in domain for tld in [".tk", ".ml", ".ga", ".cf"]):
        phishing_indicators.append("Suspicious top-level domain")
    
    reputation_score = 0.9 if not is_suspicious else 0.1
    
    return URLAnalysis(
        url=url,
        is_suspicious=is_suspicious,
        domain_age=None,
        ssl_valid=not is_suspicious,
        blacklisted=blacklisted,
        phishing_indicators=phishing_indicators,
        reputation_score=reputation_score
    )

def analyze_message_content(text: str) -> MessageAnalysis:
    """Analyze message content for scam patterns"""
    text_lower = text.lower()
    
    # Calculate urgency score
    urgency_keywords = ["urgent", "immediate", "asap", "right now", "expires today"]
    urgency_score = sum(1 for keyword in urgency_keywords if keyword in text_lower) / len(urgency_keywords)
    
    # Calculate emotional manipulation score
    emotional_keywords = ["congratulations", "winner", "selected", "exclusive", "limited time", "act fast"]
    emotional_manipulation = sum(1 for keyword in emotional_keywords if keyword in text_lower) / len(emotional_keywords)
    
    # Check for financial requests
    financial_request = any(keyword in text_lower for keyword in FINANCIAL_KEYWORDS)
    
    # Identify suspicious patterns
    suspicious_patterns = []
    for pattern in SCAM_KEYWORDS:
        if pattern in text_lower:
            suspicious_patterns.append(f"Contains scam keyword: {pattern}")
    
    if text.count("!") > 3:
        suspicious_patterns.append("Excessive exclamation marks")
    
    if "click here" in text_lower or "click link" in text_lower:
        suspicious_patterns.append("Suspicious link requests")
    
    language_analysis = {
        "word_count": len(text.split()),
        "exclamation_count": text.count("!"),
        "question_count": text.count("?"),
        "capital_ratio": sum(1 for c in text if c.isupper()) / len(text) if text else 0
    }
    
    return MessageAnalysis(
        text=text,
        urgency_score=urgency_score,
        emotional_manipulation=emotional_manipulation,
        financial_request=financial_request,
        suspicious_patterns=suspicious_patterns,
        language_analysis=language_analysis
    )

def calculate_scam_risk(message_analysis: MessageAnalysis, url_analysis: Optional[URLAnalysis] = None) -> ScamContext:
    """Calculate overall scam risk based on various factors"""
    risk_factors = []
    risk_score = 0.0
    
    # Message-based risk factors
    if message_analysis.urgency_score > 0.3:
        risk_factors.append("High urgency language detected")
        risk_score += 0.3
    
    if message_analysis.emotional_manipulation > 0.2:
        risk_factors.append("Emotional manipulation tactics detected")
        risk_score += 0.25
    
    if message_analysis.financial_request:
        risk_factors.append("Financial information requested")
        risk_score += 0.4
    
    if len(message_analysis.suspicious_patterns) > 0:
        risk_factors.append(f"Suspicious patterns found: {len(message_analysis.suspicious_patterns)}")
        risk_score += min(0.3, len(message_analysis.suspicious_patterns) * 0.1)
    
    # URL-based risk factors
    if url_analysis:
        if url_analysis.is_suspicious:
            risk_factors.append("Suspicious URL detected")
            risk_score += 0.5
        
        if url_analysis.blacklisted:
            risk_factors.append("URL is blacklisted")
            risk_score += 0.6
        
        if len(url_analysis.phishing_indicators) > 0:
            risk_factors.append("Phishing indicators in URL")
            risk_score += 0.3
    
    # Determine threat type
    threat_type = None
    if risk_score > 0.7:
        threat_type = "High-risk scam"
    elif risk_score > 0.4:
        threat_type = "Potential scam"
    elif risk_score > 0.2:
        threat_type = "Suspicious activity"
    
    # Generate recommendations
    recommendations = []
    if risk_score > 0.5:
        recommendations.extend([
            "Do not click any links in this message",
            "Do not provide personal or financial information",
            "Report this message as spam/phishing"
        ])
    elif risk_score > 0.3:
        recommendations.extend([
            "Exercise caution with this message",
            "Verify sender through alternative means",
            "Avoid sharing sensitive information"
        ])
    else:
        recommendations.append("Message appears safe, but always remain vigilant")
    
    confidence = min(0.95, 0.5 + (abs(risk_score - 0.5) * 1.0))
    
    return ScamContext(
        risk_score=min(1.0, risk_score),
        risk_factors=risk_factors,
        threat_type=threat_type,
        confidence=confidence,
        recommendations=recommendations,
        analysis_timestamp=datetime.now()
    )

# Initialize FastAPI app 
app = FastAPI(title="Anchor MCP Server", version="1.0.0")

@app.post("/tools/analyze_message")
def analyze_message_endpoint(request: Dict[str, Any]) -> Dict[str, Any]:
    """HTTP endpoint for analyze_message tool"""
    text = request.get("text", "")
    return analyze_message_impl(text)

def analyze_message_impl(text: str) -> Dict[str, Any]:
    """
    Analyze a message for scam indicators
    
    Args:
        text: The message text to analyze
        
    Returns:
        Analysis results including risk score and recommendations
    """
    try:
        message_analysis = analyze_message_content(text)
        scam_context = calculate_scam_risk(message_analysis)
        
        return {
            "success": True,
            "message_analysis": message_analysis.model_dump(),
            "scam_context": scam_context.model_dump(),
            "analysis_type": "message_only"
        }
    except Exception as e:
        logger.error(f"Error analyzing message: {e}")
        return {"success": False, "error": str(e)}

@app.post("/tools/analyze_url")  
def analyze_url_endpoint(request: Dict[str, Any]) -> Dict[str, Any]:
    """HTTP endpoint for analyze_url tool"""
    url = request.get("url", "")
    return analyze_url_impl(url)

def analyze_url_impl(url: str) -> Dict[str, Any]:
    """
    Analyze a URL for malicious indicators
    
    Args:
        url: The URL to analyze
        
    Returns:
        URL analysis results including reputation score
    """
    try:
        url_analysis = analyze_url_reputation(url)
        
        return {
            "success": True,
            "url_analysis": url_analysis.model_dump(),
            "analysis_type": "url_only"
        }
    except Exception as e:
        logger.error(f"Error analyzing URL: {e}")
        return {"success": False, "error": str(e)}

@app.post("/tools/comprehensive_analysis")
def comprehensive_analysis_endpoint(request: Dict[str, Any]) -> Dict[str, Any]:
    """HTTP endpoint for comprehensive_analysis tool"""
    text = request.get("text", "")
    urls = request.get("urls", None)
    return comprehensive_analysis_impl(text, urls)

def comprehensive_analysis_impl(text: str, urls: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Perform comprehensive scam analysis on message and URLs
    
    Args:
        text: The message text to analyze
        urls: Optional list of URLs found in the message
        
    Returns:
        Comprehensive analysis results
    """
    try:
        message_analysis = analyze_message_content(text)
        
        url_analyses = []
        combined_url_analysis = None
        
        if urls:
            for url in urls:
                url_analysis = analyze_url_reputation(url)
                url_analyses.append(url_analysis)
            
            # Use the most suspicious URL for risk calculation
            if url_analyses:
                combined_url_analysis = max(url_analyses, key=lambda x: 1.0 - x.reputation_score)
        
        scam_context = calculate_scam_risk(message_analysis, combined_url_analysis)
        
        return {
            "success": True,
            "message_analysis": message_analysis.model_dump(),
            "url_analyses": [ua.model_dump() for ua in url_analyses],
            "scam_context": scam_context.model_dump(),
            "analysis_type": "comprehensive"
        }
    except Exception as e:
        logger.error(f"Error in comprehensive analysis: {e}")
        return {"success": False, "error": str(e)}

@app.get("/tools/get_threat_intelligence")
def get_threat_intelligence_endpoint() -> Dict[str, Any]:
    """HTTP endpoint for get_threat_intelligence tool"""
    return get_threat_intelligence_impl()

def get_threat_intelligence_impl() -> Dict[str, Any]:
    """
    Get current threat intelligence data
    
    Returns:
        Current threat intelligence including known scam domains and patterns
    """
    try:
        return {
            "success": True,
            "threat_intelligence": {
                "known_scam_domains": list(KNOWN_SCAM_DOMAINS),
                "scam_keywords": SCAM_KEYWORDS[:10],  # Limited for brevity
                "financial_keywords": FINANCIAL_KEYWORDS[:10],
                "last_updated": datetime.now().isoformat(),
                "total_threats": len(KNOWN_SCAM_DOMAINS)
            }
        }
    except Exception as e:
        logger.error(f"Error getting threat intelligence: {e}")
        return {"success": False, "error": str(e)}

@app.post("/tools/update_threat_database") 
def update_threat_database_endpoint(request: Dict[str, Any]) -> Dict[str, Any]:
    """HTTP endpoint for update_threat_database tool"""
    domain = request.get("domain", "")
    threat_type = request.get("threat_type", "scam")
    return update_threat_database_impl(domain, threat_type)

def update_threat_database_impl(domain: str, threat_type: str = "scam") -> Dict[str, Any]:
    """
    Update threat database with new threat information
    
    Args:
        domain: Domain to add to threat database
        threat_type: Type of threat (default: scam)
        
    Returns:
        Update confirmation
    """
    try:
        KNOWN_SCAM_DOMAINS.add(domain.lower())
        
        return {
            "success": True,
            "message": f"Added {domain} to threat database as {threat_type}",
            "updated_count": len(KNOWN_SCAM_DOMAINS)
        }
    except Exception as e:
        logger.error(f"Error updating threat database: {e}")
        return {"success": False, "error": str(e)}

# Add a root endpoint for the MCP server
@app.get("/")
def root():
    return {"service": "Anchor MCP Server", "status": "running", "port": 8000}

# MCP server is now running as pure FastAPI

def run_server():
    """Run the MCP server on localhost:8000"""
    try:
        logger.info("Starting Anchor MCP Server on localhost:8000")
        uvicorn.run(
            app,
            host="127.0.0.1",
            port=8000,
            log_level="info"
        )
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        raise

if __name__ == "__main__":
    run_server()