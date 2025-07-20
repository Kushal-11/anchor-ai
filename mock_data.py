"""
Mock Data for Anchor AI Scam Protection Service
Sample messages, URLs, and test cases for development and testing.
"""

from typing import Dict, List, Any
from datetime import datetime, timedelta

# Sample scam messages for testing
SCAM_MESSAGES = [
    {
        "id": "scam_001",
        "message": "URGENT: Your bank account has been suspended! Click here immediately to verify your account: http://fake-bank-login.com/verify",
        "sender": "security@your-bank.com",
        "subject": "Account Suspension Notice - Immediate Action Required",
        "expected_risk": "high",
        "description": "Classic phishing attempt with urgency and fake bank domain"
    },
    {
        "id": "scam_002", 
        "message": "Congratulations! You've won $10,000 in our lottery! To claim your prize, please provide your social security number and bank details.",
        "sender": "winner@lottery-claims.co",
        "subject": "YOU WON! Claim Your Prize Now!",
        "expected_risk": "high",
        "description": "Lottery scam requesting personal information"
    },
    {
        "id": "scam_003",
        "message": "Your payment method will expire today. Update your information now to avoid service interruption.",
        "sender": "billing@service-update.org",
        "subject": "Payment Method Expiring",
        "expected_risk": "medium",
        "description": "Billing update scam with moderate urgency"
    },
    {
        "id": "scam_004",
        "message": "IRS Tax Refund: You are eligible for a $2,847 refund. Claim it now before it expires!",
        "sender": "refunds@irs-gov.net",
        "subject": "Tax Refund Available",
        "expected_risk": "high",
        "description": "Fake IRS tax refund scam"
    },
    {
        "id": "scam_005",
        "message": "Your Amazon order #12345 has been cancelled. If you did not request this, call 1-800-FAKE-NUM immediately.",
        "sender": "orders@amazon-security.biz",
        "subject": "Order Cancellation Alert",
        "expected_risk": "medium",
        "description": "Fake Amazon order cancellation"
    }
]

# Sample legitimate messages for testing
LEGITIMATE_MESSAGES = [
    {
        "id": "legit_001",
        "message": "Hi, just wanted to confirm our meeting tomorrow at 3 PM. Looking forward to discussing the project.",
        "sender": "colleague@company.com",
        "subject": "Meeting Confirmation",
        "expected_risk": "safe",
        "description": "Normal business communication"
    },
    {
        "id": "legit_002",
        "message": "Your order has been shipped and will arrive by Friday. Track your package here: https://ups.com/tracking/1234567890",
        "sender": "shipping@company.com",
        "subject": "Package Shipped",
        "expected_risk": "safe", 
        "description": "Legitimate shipping notification with real tracking"
    },
    {
        "id": "legit_003",
        "message": "Don't forget about the team lunch on Thursday. The restaurant is confirmed for 12:30 PM.",
        "sender": "admin@office.com",
        "subject": "Team Lunch Reminder",
        "expected_risk": "safe",
        "description": "Normal office communication"
    },
    {
        "id": "legit_004",
        "message": "Your monthly statement is ready for review. Log into your account at your convenience.",
        "sender": "statements@realbank.com",
        "subject": "Monthly Statement Available",
        "expected_risk": "safe",
        "description": "Legitimate bank statement notification"
    }
]

# Sample suspicious but borderline messages
BORDERLINE_MESSAGES = [
    {
        "id": "border_001",
        "message": "Limited time offer! Save 50% on all products. This deal expires in 24 hours!",
        "sender": "sales@legit-store.com",
        "subject": "Flash Sale - 50% Off Everything!",
        "expected_risk": "low",
        "description": "Aggressive marketing that might trigger false positives"
    },
    {
        "id": "border_002",
        "message": "Please update your password for security. Your current password will expire in 7 days.",
        "sender": "security@company.com",
        "subject": "Password Expiration Notice",
        "expected_risk": "low",
        "description": "Legitimate security notice that could be confused with phishing"
    },
    {
        "id": "border_003",
        "message": "Action required: Please verify your email address to continue using our service.",
        "sender": "noreply@service.com",
        "subject": "Email Verification Required",
        "expected_risk": "low",
        "description": "Standard email verification that uses 'action required' language"
    }
]

# Sample malicious URLs for testing
MALICIOUS_URLS = [
    "http://fake-bank-login.com/verify",
    "https://urgent-security-alert.net/update",
    "http://your-account-suspended.org/restore",
    "https://claim-your-prize-now.co/winner",
    "http://verify-payment-info.biz/secure",
    "https://irs-refund-claim.tk/process",
    "http://amazon-security-alert.ml/suspended"
]

# Sample legitimate URLs for testing  
LEGITIMATE_URLS = [
    "https://www.amazon.com/order-history",
    "https://secure.chase.com/banking",
    "https://www.irs.gov/refunds",
    "https://myaccount.google.com/security",
    "https://www.paypal.com/signin",
    "https://login.microsoft.com",
    "https://support.apple.com"
]

# Test cases combining messages and expected outcomes
TEST_CASES = [
    {
        "case_id": "test_001",
        "input": {
            "message": SCAM_MESSAGES[0]["message"],
            "sender": SCAM_MESSAGES[0]["sender"],
            "subject": SCAM_MESSAGES[0]["subject"]
        },
        "expected_output": {
            "threat_level": "high",
            "action": "block",
            "should_contain_reasons": ["urgent", "suspicious url", "verify account"]
        }
    },
    {
        "case_id": "test_002", 
        "input": {
            "message": LEGITIMATE_MESSAGES[0]["message"],
            "sender": LEGITIMATE_MESSAGES[0]["sender"],
            "subject": LEGITIMATE_MESSAGES[0]["subject"]
        },
        "expected_output": {
            "threat_level": "safe",
            "action": "allow",
            "should_contain_reasons": []
        }
    },
    {
        "case_id": "test_003",
        "input": {
            "message": "Click this link now: http://fake-bank-login.com/urgent and enter your password immediately!",
            "sender": "security@suspicious.com"
        },
        "expected_output": {
            "threat_level": "critical",
            "action": "block",
            "should_contain_reasons": ["suspicious url", "urgent", "password request"]
        }
    }
]

# Configuration for different testing scenarios
TESTING_SCENARIOS = {
    "basic_scam_detection": {
        "description": "Test basic scam message detection",
        "test_messages": SCAM_MESSAGES[:3],
        "expected_blocks": 3,
        "expected_warnings": 0
    },
    "legitimate_message_handling": {
        "description": "Test legitimate message handling without false positives", 
        "test_messages": LEGITIMATE_MESSAGES,
        "expected_blocks": 0,
        "expected_warnings": 0
    },
    "borderline_cases": {
        "description": "Test handling of borderline/ambiguous messages",
        "test_messages": BORDERLINE_MESSAGES,
        "expected_blocks": 0,
        "expected_warnings": 2  # Some may trigger warnings
    },
    "mixed_batch": {
        "description": "Test mixed batch of various message types",
        "test_messages": SCAM_MESSAGES[:2] + LEGITIMATE_MESSAGES[:2] + BORDERLINE_MESSAGES[:1],
        "expected_blocks": 2,
        "expected_warnings": 1
    }
}

# Performance testing data
PERFORMANCE_TEST_DATA = {
    "stress_test_messages": [
        f"Test message {i}: This is a normal message for performance testing."
        for i in range(100)
    ],
    "concurrent_test_scenarios": [
        {
            "concurrent_requests": 10,
            "message_count": 5,
            "expected_response_time_ms": 2000
        },
        {
            "concurrent_requests": 50,
            "message_count": 2, 
            "expected_response_time_ms": 5000
        }
    ]
}

# Sample user feedback data for model improvement
USER_FEEDBACK_SAMPLES = [
    {
        "message_id": "scam_001",
        "user_action": "blocked_correctly",
        "feedback": "correctly_identified",
        "timestamp": datetime.now() - timedelta(days=1)
    },
    {
        "message_id": "legit_001", 
        "user_action": "false_positive",
        "feedback": "incorrectly_blocked",
        "timestamp": datetime.now() - timedelta(hours=2)
    },
    {
        "message_id": "border_001",
        "user_action": "user_override",
        "feedback": "acceptable_risk",
        "timestamp": datetime.now() - timedelta(minutes=30)
    }
]

def get_test_message_by_id(message_id: str) -> Dict[str, Any]:
    """Get a specific test message by ID"""
    all_messages = SCAM_MESSAGES + LEGITIMATE_MESSAGES + BORDERLINE_MESSAGES
    for msg in all_messages:
        if msg["id"] == message_id:
            return msg
    return None

def get_random_scam_message() -> Dict[str, Any]:
    """Get a random scam message for testing"""
    import random
    return random.choice(SCAM_MESSAGES)

def get_random_legitimate_message() -> Dict[str, Any]:
    """Get a random legitimate message for testing"""
    import random
    return random.choice(LEGITIMATE_MESSAGES)

def get_test_scenario(scenario_name: str) -> Dict[str, Any]:
    """Get a specific testing scenario configuration"""
    return TESTING_SCENARIOS.get(scenario_name, {})

def generate_test_batch(size: int, scam_ratio: float = 0.3) -> List[Dict[str, Any]]:
    """
    Generate a test batch with a specific ratio of scam to legitimate messages
    
    Args:
        size: Total number of messages to generate
        scam_ratio: Ratio of scam messages (0.0 to 1.0)
    
    Returns:
        List of test messages
    """
    import random
    
    scam_count = int(size * scam_ratio)
    legit_count = size - scam_count
    
    batch = []
    
    # Add scam messages
    for _ in range(scam_count):
        batch.append(random.choice(SCAM_MESSAGES))
    
    # Add legitimate messages  
    for _ in range(legit_count):
        batch.append(random.choice(LEGITIMATE_MESSAGES))
    
    # Shuffle the batch
    random.shuffle(batch)
    return batch

# API response templates for mocking external services
API_RESPONSE_TEMPLATES = {
    "url_reputation_response": {
        "success": True,
        "url": "example.com",
        "reputation_score": 0.95,
        "categories": ["business", "technology"],
        "threat_types": [],
        "last_seen": datetime.now().isoformat()
    },
    "threat_intelligence_response": {
        "success": True,
        "threats": {
            "domains": MALICIOUS_URLS,
            "keywords": ["urgent", "suspended", "verify account"],
            "patterns": ["click here now", "act immediately"],
            "last_updated": datetime.now().isoformat()
        }
    },
    "analysis_error_response": {
        "success": False,
        "error": "Service temporarily unavailable",
        "retry_after": 60
    }
}

def get_mock_api_response(response_type: str, success: bool = True) -> Dict[str, Any]:
    """Get a mock API response for testing"""
    if not success:
        return API_RESPONSE_TEMPLATES["analysis_error_response"]
    
    return API_RESPONSE_TEMPLATES.get(response_type, {})

# Export main data structures for easy import
__all__ = [
    'SCAM_MESSAGES',
    'LEGITIMATE_MESSAGES', 
    'BORDERLINE_MESSAGES',
    'MALICIOUS_URLS',
    'LEGITIMATE_URLS',
    'TEST_CASES',
    'TESTING_SCENARIOS',
    'PERFORMANCE_TEST_DATA',
    'USER_FEEDBACK_SAMPLES',
    'get_test_message_by_id',
    'get_random_scam_message',
    'get_random_legitimate_message',
    'get_test_scenario',
    'generate_test_batch',
    'get_mock_api_response'
]