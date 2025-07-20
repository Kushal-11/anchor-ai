"""
Anchor Agent Module
Core AI agent logic for scam detection and decision making.
Acts as the intelligence layer between the FastAPI app and MCP server.
"""

import asyncio
import re
import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from enum import Enum
import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    """Threat level classifications"""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ActionRecommendation(Enum):
    """Recommended actions for users"""
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"
    QUARANTINE = "quarantine"

class AnalysisRequest(BaseModel):
    """Request model for agent analysis"""
    message: str
    sender: Optional[str] = None
    subject: Optional[str] = None
    urls: Optional[List[str]] = None
    attachments: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None

class AgentDecision(BaseModel):
    """Agent's final decision and recommendations"""
    threat_level: ThreatLevel
    action: ActionRecommendation
    confidence: float = Field(ge=0.0, le=1.0)
    risk_score: float = Field(ge=0.0, le=1.0)
    reasons: List[str]
    user_message: str
    technical_details: Dict[str, Any]
    analysis_timestamp: datetime

class AnchorAgent:
    """
    Main AI agent for scam detection and decision making.
    Coordinates with MCP server and applies business logic.
    """
    
    def __init__(self, mcp_server_url: str = "http://127.0.0.1:8000"):
        self.mcp_server_url = mcp_server_url
        self.client = httpx.AsyncClient(timeout=30.0)
        self.decision_thresholds = {
            "block_threshold": 0.8,
            "warn_threshold": 0.4,
            "confidence_threshold": 0.7
        }
        
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()
    
    def extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text using regex"""
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, text)
        
        # Also check for domain-only patterns that might be suspicious
        domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
        potential_domains = re.findall(domain_pattern, text)
        
        # Add http:// prefix to domains that look suspicious
        for domain in potential_domains:
            if any(suspicious in domain.lower() for suspicious in ['login', 'secure', 'verify', 'update']):
                full_url = f"http://{domain}"
                if full_url not in urls:
                    urls.append(full_url)
        
        return urls
    
    async def call_mcp_tool(self, tool_name: str, **kwargs) -> Dict[str, Any]:
        """Make HTTP request to MCP server tool"""
        try:
            endpoint = f"{self.mcp_server_url}/tools/{tool_name}"
            
            # Use GET for get_threat_intelligence, POST for others
            if tool_name == "get_threat_intelligence":
                response = await self.client.get(endpoint)
            else:
                response = await self.client.post(endpoint, json=kwargs)
            
            response.raise_for_status()
            return response.json()
        except httpx.RequestError as e:
            logger.error(f"Request error calling MCP tool {tool_name}: {e}")
            return {"success": False, "error": f"Connection error: {str(e)}"}
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error calling MCP tool {tool_name}: {e}")
            return {"success": False, "error": f"HTTP {e.response.status_code}: {str(e)}"}
        except Exception as e:
            logger.error(f"Unexpected error calling MCP tool {tool_name}: {e}")
            return {"success": False, "error": str(e)}
    
    def determine_threat_level(self, risk_score: float, confidence: float) -> ThreatLevel:
        """Determine threat level based on risk score and confidence"""
        if confidence < self.decision_thresholds["confidence_threshold"]:
            # Lower threat level if confidence is low
            risk_score *= 0.8
        
        if risk_score >= 0.9:
            return ThreatLevel.CRITICAL
        elif risk_score >= 0.7:
            return ThreatLevel.HIGH
        elif risk_score >= 0.4:
            return ThreatLevel.MEDIUM
        elif risk_score >= 0.2:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.SAFE
    
    def determine_action(self, threat_level: ThreatLevel, risk_score: float) -> ActionRecommendation:
        """Determine recommended action based on threat level"""
        if threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
            return ActionRecommendation.BLOCK
        elif threat_level == ThreatLevel.MEDIUM:
            return ActionRecommendation.WARN if risk_score < 0.6 else ActionRecommendation.BLOCK
        elif threat_level == ThreatLevel.LOW:
            return ActionRecommendation.WARN
        else:
            return ActionRecommendation.ALLOW
    
    def generate_user_message(self, threat_level: ThreatLevel, action: ActionRecommendation, 
                            risk_factors: List[str], recommendations: List[str]) -> str:
        """Generate user-friendly message based on analysis"""
        if threat_level == ThreatLevel.SAFE:
            return "✅ This message appears safe. No threats detected."
        
        if threat_level == ThreatLevel.LOW:
            return f"⚠️ Low risk detected. Be cautious: {', '.join(risk_factors[:2])}"
        
        if threat_level == ThreatLevel.MEDIUM:
            return f"⚠️ Moderate scam risk detected. Reasons: {', '.join(risk_factors[:3])}. Recommendation: {recommendations[0] if recommendations else 'Exercise caution'}"
        
        if threat_level == ThreatLevel.HIGH:
            return f"🚨 High scam risk! This appears to be a scam. Key indicators: {', '.join(risk_factors[:3])}. Do not respond or click any links."
        
        if threat_level == ThreatLevel.CRITICAL:
            return f"🚨 CRITICAL THREAT! This is very likely a dangerous scam. Multiple red flags detected: {', '.join(risk_factors[:4])}. Block immediately and report."
        
        return "Unable to determine threat level. Please exercise caution."
    
    async def analyze_request(self, request: AnalysisRequest) -> AgentDecision:
        """
        Main analysis method that coordinates with MCP server and makes decisions
        """
        try:
            # Extract URLs if not provided
            if not request.urls:
                request.urls = self.extract_urls(request.message)
            
            # Combine message content for analysis
            full_text = request.message
            if request.subject:
                full_text = f"Subject: {request.subject}\n\n{full_text}"
            
            # Call MCP server for comprehensive analysis
            mcp_result = await self.call_mcp_tool(
                "comprehensive_analysis",
                text=full_text,
                urls=request.urls
            )
            
            if not mcp_result.get("success", False):
                # Fallback to basic analysis if MCP call fails
                logger.warning(f"MCP analysis failed: {mcp_result.get('error', 'Unknown error')}")
                return self._create_fallback_decision(request, mcp_result.get('error', 'Analysis service unavailable'))
            
            # Extract analysis results
            scam_context = mcp_result.get("scam_context", {})
            message_analysis = mcp_result.get("message_analysis", {})
            url_analyses = mcp_result.get("url_analyses", [])
            
            risk_score = scam_context.get("risk_score", 0.0)
            confidence = scam_context.get("confidence", 0.5)
            risk_factors = scam_context.get("risk_factors", [])
            recommendations = scam_context.get("recommendations", [])
            
            # Apply agent business logic
            threat_level = self.determine_threat_level(risk_score, confidence)
            action = self.determine_action(threat_level, risk_score)
            
            # Generate user-friendly message
            user_message = self.generate_user_message(threat_level, action, risk_factors, recommendations)
            
            # Compile reasons for decision
            reasons = []
            if risk_factors:
                reasons.extend(risk_factors)
            
            # Add URL-specific reasons
            for url_analysis in url_analyses:
                if url_analysis.get("is_suspicious", False):
                    reasons.append(f"Suspicious URL detected: {url_analysis.get('url', 'Unknown')}")
                if url_analysis.get("phishing_indicators"):
                    reasons.extend([f"URL: {indicator}" for indicator in url_analysis["phishing_indicators"][:2]])
            
            # Add message-specific reasons
            if message_analysis.get("financial_request", False):
                reasons.append("Financial information requested")
            if message_analysis.get("urgency_score", 0) > 0.5:
                reasons.append("High urgency language detected")
            
            technical_details = {
                "mcp_analysis": mcp_result,
                "extracted_urls": request.urls,
                "decision_thresholds": self.decision_thresholds,
                "processing_time": datetime.now().isoformat()
            }
            
            return AgentDecision(
                threat_level=threat_level,
                action=action,
                confidence=confidence,
                risk_score=risk_score,
                reasons=reasons[:5],  # Limit to top 5 reasons
                user_message=user_message,
                technical_details=technical_details,
                analysis_timestamp=datetime.now()
            )
            
        except Exception as e:
            logger.error(f"Error in agent analysis: {e}")
            return self._create_fallback_decision(request, f"Analysis error: {str(e)}")
    
    def _create_fallback_decision(self, request: AnalysisRequest, error_msg: str) -> AgentDecision:
        """Create a conservative fallback decision when analysis fails"""
        # Basic keyword-based fallback analysis
        message_lower = request.message.lower()
        
        high_risk_keywords = ['urgent', 'suspended', 'verify account', 'click here', 'act now']
        detected_risks = [keyword for keyword in high_risk_keywords if keyword in message_lower]
        
        if detected_risks:
            risk_score = min(0.7, len(detected_risks) * 0.2)
            threat_level = ThreatLevel.MEDIUM
            action = ActionRecommendation.WARN
            reasons = [f"Detected risk keyword: {keyword}" for keyword in detected_risks]
            user_message = f"⚠️ Analysis service unavailable, but potential risks detected: {', '.join(detected_risks[:2])}"
        else:
            risk_score = 0.1
            threat_level = ThreatLevel.LOW
            action = ActionRecommendation.ALLOW
            reasons = ["Unable to perform full analysis - exercising caution"]
            user_message = "⚠️ Analysis service temporarily unavailable. Please exercise normal caution."
        
        return AgentDecision(
            threat_level=threat_level,
            action=action,
            confidence=0.3,  # Low confidence due to fallback
            risk_score=risk_score,
            reasons=reasons,
            user_message=user_message,
            technical_details={"error": error_msg, "fallback_mode": True},
            analysis_timestamp=datetime.now()
        )
    
    async def get_threat_intelligence(self) -> Dict[str, Any]:
        """Get current threat intelligence from MCP server"""
        return await self.call_mcp_tool("get_threat_intelligence")
    
    async def update_threat_database(self, domain: str, threat_type: str = "scam") -> Dict[str, Any]:
        """Update threat database with new information"""
        return await self.call_mcp_tool("update_threat_database", domain=domain, threat_type=threat_type)
    
    async def health_check(self) -> Dict[str, Any]:
        """Check health of agent and MCP server connection"""
        try:
            # Test MCP server connectivity
            threat_intel = await self.get_threat_intelligence()
            mcp_healthy = threat_intel.get("success", False)
            
            return {
                "agent_status": "healthy",
                "mcp_server_status": "healthy" if mcp_healthy else "unhealthy",
                "mcp_server_url": self.mcp_server_url,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {
                "agent_status": "healthy",
                "mcp_server_status": "unhealthy",
                "mcp_server_url": self.mcp_server_url,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }