# Anchor - AI Scam Protection Service

Anchor is an AI guardian that proactively shields seniors from malicious phone and email scams, providing real-time analysis and peace of mind for their families.

## 🏗️ Architecture

This is a **client-server architecture** implementation with two main components:

- **FastAPI Application** (`main.py`) - Main API interface running on port 8080
- **MCP Server** (`mcp_server_process.py`) - Context enrichment service running on port 8000
- **Agent Module** (`agent.py`) - Core AI decision-making logic
- **Mock Data** (`mock_data.py`) - Test datasets and scenarios

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Virtual environment (recommended)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Kushal-11/anchor-ai.git
   cd anchor-ai
   ```

2. **Set up virtual environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

### Running the Service

1. **Start the MCP Server (Terminal 1):**
   ```bash
   python mcp_server_process.py
   ```
   Server will start on `http://127.0.0.1:8000`

2. **Start the FastAPI Application (Terminal 2):**
   ```bash
   python main.py
   ```
   Application will start on `http://0.0.0.0:8080`

3. **Access the API Documentation:**
   - Swagger UI: http://localhost:8080/docs
   - ReDoc: http://localhost:8080/redoc

## 📚 API Usage

### Single Message Analysis
```bash
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "message": "URGENT: Your account has been suspended! Click here to verify.",
    "sender": "security@bank.com",
    "subject": "Account Alert"
  }'
```

### Batch Analysis
```bash
curl -X POST http://localhost:8080/analyze/batch \
  -H "Content-Type: application/json" \
  -d '{
    "messages": [
      {"message": "Hi, confirming our meeting tomorrow at 3 PM."},
      {"message": "URGENT: Click here to claim your prize!"}
    ]
  }'
```

### Demo Test Scenarios
```bash
# Run predefined test scenarios
curl -X POST http://localhost:8080/demo/test-scenario/basic_scam_detection

# Generate random test batch
curl -X POST http://localhost:8080/demo/random-test \
  -H "Content-Type: application/json" \
  -d '{"message_count": 10, "scam_ratio": 0.3}'
```

## 🎯 Key Features

### Threat Detection
- **Multi-level Classification**: SAFE → LOW → MEDIUM → HIGH → CRITICAL
- **URL Reputation Analysis**: Real-time blacklist checking
- **Content Analysis**: Urgency detection, emotional manipulation, financial requests
- **Pattern Recognition**: Scam keywords and suspicious phrases

### Decision Making
- **Risk Scoring**: 0.0 to 1.0 risk assessment
- **Confidence Levels**: Algorithm certainty measurement
- **Action Recommendations**: ALLOW, WARN, BLOCK, QUARANTINE
- **User-Friendly Messages**: Clear explanations for decisions

### System Reliability
- **Fallback Handling**: Graceful degradation when services unavailable
- **Health Monitoring**: Comprehensive system status checking
- **Error Recovery**: Robust error handling and recovery mechanisms
- **Async Processing**: High-performance concurrent request handling

## 📊 Response Format

```json
{
  "success": true,
  "threat_level": "high",
  "action": "block",
  "risk_score": 0.85,
  "confidence": 0.92,
  "user_message": "🚨 High scam risk! This appears to be a phishing attempt.",
  "reasons": [
    "Suspicious URL detected",
    "High urgency language",
    "Financial information requested"
  ],
  "analysis_timestamp": "2025-07-20T12:00:00Z",
  "processing_time_ms": 15.4
}
```

## 🧪 Testing

The system includes comprehensive testing capabilities:

### Available Test Scenarios
- `basic_scam_detection` - Test core scam detection
- `legitimate_message_handling` - Verify no false positives
- `borderline_cases` - Test edge cases
- `mixed_batch` - Combined scenario testing

### Health Check
```bash
curl http://localhost:8080/health
```

## 🔧 Configuration

### Decision Thresholds
The agent uses configurable thresholds in `agent.py`:
```python
decision_thresholds = {
    "block_threshold": 0.8,
    "warn_threshold": 0.4,
    "confidence_threshold": 0.7
}
```

### Threat Intelligence
The MCP server maintains threat databases:
- Known scam domains
- Suspicious keywords
- Financial request patterns
- Phishing indicators

## 📁 Project Structure

```
anchor-ai/
├── main.py                 # FastAPI application (port 8080)
├── mcp_server_process.py   # MCP server (port 8000)
├── agent.py               # Core AI agent logic
├── mock_data.py           # Test datasets
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

## 🛡️ Security Features

- **No Data Storage**: Messages are analyzed in real-time, not stored
- **Configurable Sensitivity**: Adjustable threat detection thresholds
- **Audit Trail**: Comprehensive logging of all decisions
- **Privacy Protection**: No personal data retention

## 🚦 System Status

- ✅ **MCP Server**: Context enrichment and threat intelligence
- ✅ **FastAPI App**: Main API interface and user interactions
- ✅ **Agent Logic**: AI-powered decision making
- ✅ **Test Suite**: Comprehensive validation scenarios

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is part of the MCP Hackathon submission.

---

**Built for MCP Hackathon 2025** - Protecting seniors from scams with AI-powered intelligence.
