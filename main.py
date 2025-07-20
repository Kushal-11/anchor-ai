#!/usr/bin/env python3
"""
Anchor - AI Scam Protection Service
FastAPI application that serves as the main interface and acts as a client to the MCP server.
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Dict, List, Optional, Any
from datetime import datetime

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn

from agent import AnchorAgent, AnalysisRequest, AgentDecision, ThreatLevel, ActionRecommendation
from mock_data import get_test_message_by_id, generate_test_batch, TESTING_SCENARIOS

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global agent instance
agent: Optional[AnchorAgent] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan - startup and shutdown"""
    global agent
    
    # Startup
    logger.info("Starting Anchor AI Scam Protection Service...")
    agent = AnchorAgent()
    
    # Verify MCP server connection
    health = await agent.health_check()
    if health.get("mcp_server_status") != "healthy":
        logger.warning(f"MCP server not available: {health}")
    else:
        logger.info("Connected to MCP server successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Anchor service...")
    if agent:
        await agent.__aexit__(None, None, None)

# Initialize FastAPI app
app = FastAPI(
    title="Anchor - AI Scam Protection Service",
    description="Intelligent scam detection and protection API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models for API requests and responses
class AnalyzeMessageRequest(BaseModel):
    """Request model for message analysis"""
    message: str = Field(..., description="The message content to analyze")
    sender: Optional[str] = Field(None, description="Sender email or identifier")
    subject: Optional[str] = Field(None, description="Message subject line")
    urls: Optional[List[str]] = Field(None, description="URLs found in the message")
    attachments: Optional[List[str]] = Field(None, description="Attachment information")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")

class AnalysisResponse(BaseModel):
    """Response model for analysis results"""
    success: bool
    threat_level: str
    action: str
    risk_score: float
    confidence: float
    user_message: str
    reasons: List[str]
    technical_details: Optional[Dict[str, Any]] = None
    analysis_timestamp: datetime
    processing_time_ms: Optional[float] = None

class BatchAnalysisRequest(BaseModel):
    """Request model for batch analysis"""
    messages: List[AnalyzeMessageRequest] = Field(..., description="List of messages to analyze")
    batch_id: Optional[str] = Field(None, description="Batch identifier for tracking")

class BatchAnalysisResponse(BaseModel):
    """Response model for batch analysis"""
    success: bool
    batch_id: Optional[str]
    total_messages: int
    results: List[AnalysisResponse]
    summary: Dict[str, Any]
    processing_time_ms: float

class HealthResponse(BaseModel):
    """Health check response model"""
    status: str
    timestamp: datetime
    agent_status: str
    mcp_server_status: str
    version: str = "1.0.0"

# Dependency to get agent instance
async def get_agent() -> AnchorAgent:
    """Dependency to get the global agent instance"""
    if agent is None:
        raise HTTPException(status_code=503, detail="Service not initialized")
    return agent

@app.get("/", response_model=Dict[str, str])
async def root():
    """Root endpoint with service information"""
    return {
        "service": "Anchor - AI Scam Protection Service",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
        "health": "/health"
    }

@app.get("/health", response_model=HealthResponse)
async def health_check(agent: AnchorAgent = Depends(get_agent)):
    """Health check endpoint"""
    try:
        health_data = await agent.health_check()
        
        return HealthResponse(
            status="healthy" if health_data.get("agent_status") == "healthy" else "degraded",
            timestamp=datetime.now(),
            agent_status=health_data.get("agent_status", "unknown"),
            mcp_server_status=health_data.get("mcp_server_status", "unknown")
        )
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail=f"Health check failed: {str(e)}")

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_message(
    request: AnalyzeMessageRequest,
    agent: AnchorAgent = Depends(get_agent)
):
    """
    Analyze a single message for scam indicators
    
    This endpoint performs comprehensive analysis of a message including:
    - Content analysis for scam patterns
    - URL reputation checking
    - Risk assessment and threat classification
    - Action recommendations
    """
    start_time = datetime.now()
    
    try:
        # Convert request to agent format
        analysis_request = AnalysisRequest(
            message=request.message,
            sender=request.sender,
            subject=request.subject,
            urls=request.urls,
            attachments=request.attachments,
            metadata=request.metadata
        )
        
        # Perform analysis
        decision = await agent.analyze_request(analysis_request)
        
        # Calculate processing time
        processing_time = (datetime.now() - start_time).total_seconds() * 1000
        
        return AnalysisResponse(
            success=True,
            threat_level=decision.threat_level.value,
            action=decision.action.value,
            risk_score=decision.risk_score,
            confidence=decision.confidence,
            user_message=decision.user_message,
            reasons=decision.reasons,
            technical_details=decision.technical_details,
            analysis_timestamp=decision.analysis_timestamp,
            processing_time_ms=processing_time
        )
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/analyze/batch", response_model=BatchAnalysisResponse)
async def analyze_batch(
    request: BatchAnalysisRequest,
    background_tasks: BackgroundTasks,
    agent: AnchorAgent = Depends(get_agent)
):
    """
    Analyze multiple messages in batch
    
    Efficiently processes multiple messages and provides summary statistics.
    """
    start_time = datetime.now()
    
    try:
        results = []
        threat_counts = {level.value: 0 for level in ThreatLevel}
        action_counts = {action.value: 0 for action in ActionRecommendation}
        total_risk_score = 0.0
        
        # Process each message
        for msg_request in request.messages:
            try:
                analysis_request = AnalysisRequest(
                    message=msg_request.message,
                    sender=msg_request.sender,
                    subject=msg_request.subject,
                    urls=msg_request.urls,
                    attachments=msg_request.attachments,
                    metadata=msg_request.metadata
                )
                
                decision = await agent.analyze_request(analysis_request)
                
                # Create response
                analysis_response = AnalysisResponse(
                    success=True,
                    threat_level=decision.threat_level.value,
                    action=decision.action.value,
                    risk_score=decision.risk_score,
                    confidence=decision.confidence,
                    user_message=decision.user_message,
                    reasons=decision.reasons,
                    analysis_timestamp=decision.analysis_timestamp
                )
                
                results.append(analysis_response)
                
                # Update counters
                threat_counts[decision.threat_level.value] += 1
                action_counts[decision.action.value] += 1
                total_risk_score += decision.risk_score
                
            except Exception as e:
                logger.error(f"Failed to analyze message in batch: {e}")
                # Add error result
                results.append(AnalysisResponse(
                    success=False,
                    threat_level="unknown",
                    action="allow",
                    risk_score=0.0,
                    confidence=0.0,
                    user_message=f"Analysis failed: {str(e)}",
                    reasons=[],
                    analysis_timestamp=datetime.now()
                ))
        
        # Calculate summary statistics
        total_messages = len(request.messages)
        avg_risk_score = total_risk_score / total_messages if total_messages > 0 else 0.0
        processing_time = (datetime.now() - start_time).total_seconds() * 1000
        
        summary = {
            "total_processed": total_messages,
            "successful_analyses": sum(1 for r in results if r.success),
            "failed_analyses": sum(1 for r in results if not r.success),
            "threat_distribution": threat_counts,
            "action_distribution": action_counts,
            "average_risk_score": avg_risk_score,
            "high_risk_count": threat_counts.get("high", 0) + threat_counts.get("critical", 0),
            "blocked_count": action_counts.get("block", 0)
        }
        
        return BatchAnalysisResponse(
            success=True,
            batch_id=request.batch_id,
            total_messages=total_messages,
            results=results,
            summary=summary,
            processing_time_ms=processing_time
        )
        
    except Exception as e:
        logger.error(f"Batch analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Batch analysis failed: {str(e)}")

@app.get("/threat-intelligence")
async def get_threat_intelligence(agent: AnchorAgent = Depends(get_agent)):
    """Get current threat intelligence data"""
    try:
        threat_intel = await agent.get_threat_intelligence()
        return threat_intel
    except Exception as e:
        logger.error(f"Failed to get threat intelligence: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get threat intelligence: {str(e)}")

@app.post("/threat-intelligence/update")
async def update_threat_database(
    domain: str,
    threat_type: str = "scam",
    agent: AnchorAgent = Depends(get_agent)
):
    """Update threat database with new threat information"""
    try:
        result = await agent.update_threat_database(domain, threat_type)
        return result
    except Exception as e:
        logger.error(f"Failed to update threat database: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update threat database: {str(e)}")

# Testing and demonstration endpoints
@app.get("/demo/test-cases")
async def get_test_cases():
    """Get available test cases for demonstration"""
    return {
        "available_scenarios": list(TESTING_SCENARIOS.keys()),
        "scenarios": TESTING_SCENARIOS,
        "description": "Use these test cases to demonstrate the system capabilities"
    }

@app.post("/demo/test-scenario/{scenario_name}")
async def run_test_scenario(
    scenario_name: str,
    agent: AnchorAgent = Depends(get_agent)
):
    """Run a predefined test scenario"""
    try:
        scenario = TESTING_SCENARIOS.get(scenario_name)
        if not scenario:
            raise HTTPException(status_code=404, detail=f"Test scenario '{scenario_name}' not found")
        
        # Create batch request from scenario
        batch_request = BatchAnalysisRequest(
            messages=[
                AnalyzeMessageRequest(
                    message=msg["message"],
                    sender=msg.get("sender"),
                    subject=msg.get("subject")
                ) for msg in scenario["test_messages"]
            ],
            batch_id=f"test_scenario_{scenario_name}"
        )
        
        # Run analysis
        background_tasks = BackgroundTasks()
        result = await analyze_batch(batch_request, background_tasks, agent)
        
        # Add scenario expectations to result
        result.summary["scenario_name"] = scenario_name
        result.summary["scenario_description"] = scenario["description"]
        result.summary["expected_blocks"] = scenario.get("expected_blocks", 0)
        result.summary["expected_warnings"] = scenario.get("expected_warnings", 0)
        result.summary["actual_blocks"] = result.summary["action_distribution"].get("block", 0)
        result.summary["actual_warnings"] = result.summary["action_distribution"].get("warn", 0)
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Test scenario failed: {e}")
        raise HTTPException(status_code=500, detail=f"Test scenario failed: {str(e)}")

@app.post("/demo/random-test")
async def run_random_test(
    message_count: int = 10,
    scam_ratio: float = 0.3,
    agent: AnchorAgent = Depends(get_agent)
):
    """Generate and analyze random test messages"""
    try:
        if message_count > 100:
            raise HTTPException(status_code=400, detail="Message count cannot exceed 100")
        
        if not 0.0 <= scam_ratio <= 1.0:
            raise HTTPException(status_code=400, detail="Scam ratio must be between 0.0 and 1.0")
        
        # Generate test batch
        test_messages = generate_test_batch(message_count, scam_ratio)
        
        # Create batch request
        batch_request = BatchAnalysisRequest(
            messages=[
                AnalyzeMessageRequest(
                    message=msg["message"],
                    sender=msg.get("sender"),
                    subject=msg.get("subject")
                ) for msg in test_messages
            ],
            batch_id=f"random_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        
        # Run analysis
        background_tasks = BackgroundTasks()
        result = await analyze_batch(batch_request, background_tasks, agent)
        
        # Add test parameters to result
        result.summary["test_parameters"] = {
            "message_count": message_count,
            "scam_ratio": scam_ratio,
            "expected_scam_count": int(message_count * scam_ratio)
        }
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Random test failed: {e}")
        raise HTTPException(status_code=500, detail=f"Random test failed: {str(e)}")

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": "Internal server error",
            "detail": str(exc) if app.debug else "An unexpected error occurred"
        }
    )

def main():
    """Main function to run the FastAPI application"""
    logger.info("Starting Anchor FastAPI application...")
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8080,
        reload=True,
        log_level="info"
    )

if __name__ == "__main__":
    main()