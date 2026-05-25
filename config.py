"""
Configuration module for PhishGuard Dashboard
Manages API keys, suspicious patterns, and security settings
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Base configuration"""
    
    # Flask Settings
    DEBUG = os.getenv('DEBUG', 'False') == 'True'
    TESTING = False
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # Server Settings
    HOST = os.getenv('HOST', '127.0.0.1')
    PORT = int(os.getenv('PORT', 5000))
    
    # API Keys
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
    
    # Security Scanning
    MAX_HISTORY = int(os.getenv('MAX_HISTORY', 10))
    SCAN_TIMEOUT = int(os.getenv('SCAN_TIMEOUT', 30))
    
    # SSL/TLS Settings
    SSL_TIMEOUT = int(os.getenv('SSL_TIMEOUT', 5))
    SSL_VERIFY = os.getenv('SSL_VERIFY', 'True') == 'True'
    
    # WHOIS Settings
    WHOIS_TIMEOUT = int(os.getenv('WHOIS_TIMEOUT', 10))
    
    # VirusTotal Settings
    VT_TIMEOUT = int(os.getenv('VT_TIMEOUT', 15))
    VT_MAX_RETRIES = int(os.getenv('VT_MAX_RETRIES', 6))
    VT_RETRY_DELAY = int(os.getenv('VT_RETRY_DELAY', 5))
    
    # Threat Scoring Weights
    WHOIS_WEIGHT = float(os.getenv('WHOIS_WEIGHT', 1.0))
    SSL_WEIGHT = float(os.getenv('SSL_WEIGHT', 1.0))
    VT_WEIGHT = float(os.getenv('VT_WEIGHT', 1.5))
    URL_WEIGHT = float(os.getenv('URL_WEIGHT', 1.0))
    
    # Suspicious Keywords (phishing-related)
    SUSPICIOUS_KEYWORDS = [
        "login", "verify", "update", "secure", "account", "banking", "confirm",
        "password", "signin", "paypal", "amazon", "apple", "microsoft", "support",
        "urgent", "suspend", "click", "free", "winner", "prize", "alert", "limited",
        "offer", "ebay", "netflix", "google", "facebook", "instagram", "twitter",
        "validate", "authentication", "authorize", "permission", "suspicious",
        "activity", "unusual", "confirm identity", "verify account", "re-activate"
    ]
    
    # Suspicious Top-Level Domains
    SUSPICIOUS_TLDS = [
        ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".link",
        ".download", ".zip", ".accountant", ".stream", ".online", ".store",
        ".site", ".website", ".tech", ".buzz"
    ]
    
    # Homograph/Unicode Spoofing Characters (Cyrillic, Greek, etc.)
    HOMOGRAPH_CHARS = {
        'а': 'a',      # Cyrillic
        'е': 'e',      # Cyrillic
        'о': 'o',      # Cyrillic
        'р': 'p',      # Cyrillic
        'с': 'c',      # Cyrillic
        'х': 'x',      # Cyrillic
        'у': 'y',      # Cyrillic
        'і': 'i',      # Cyrillic
        'ν': 'v',      # Greek
        'ρ': 'p',      # Greek
        'τ': 't',      # Greek
    }
    
    # Risk Scoring Thresholds
    RISK_LEVELS = {
        'CRITICAL': {'min': 70, 'emoji': '🚨', 'color': '#ff3c5a'},
        'HIGH': {'min': 45, 'emoji': '⚠️', 'color': '#ff6b35'},
        'MODERATE': {'min': 25, 'emoji': '🔍', 'color': '#ffaa00'},
        'LOW': {'min': 10, 'emoji': '🔎', 'color': '#88cc00'},
        'SAFE': {'min': 0, 'emoji': '✅', 'color': '#00ff9d'},
    }
    
    # WHOIS Domain Age Scoring
    WHOIS_SCORING = {
        'new_domain_days': 30,      # < 30 days = +50
        'high_risk_days': 90,       # 30-90 days = +35
        'moderate_risk_days': 180,  # 90-180 days = +20
        'low_risk_days': 365,       # 180-365 days = +10
        'minor_risk_days': 730,     # 365-730 days = +5
    }
    
    # SSL Certificate Scoring
    SSL_SCORING = {
        'expired_penalty': 40,
        'expiring_soon_days': 30,
        'expiring_soon_penalty': 15,
        'self_signed_penalty': 20,
        'no_https_penalty': 15,
        'ssl_verify_fail_penalty': 40,
        'no_port_443_penalty': 30,
    }
    
    # VirusTotal Scoring
    VT_SCORING = {
        'high_malicious': 5,        # 5+ engines = +50
        'high_malicious_penalty': 50,
        'some_malicious_penalty': 25,
    }
    
    # URL Structure Scoring
    URL_SCORING = {
        'ip_address_penalty': 30,
        'suspicious_tld_penalty': 20,
        'long_url_threshold': 100,
        'long_url_penalty': 10,
        'keyword_penalty': 5,
        'keyword_max_penalty': 25,
        'excessive_subdomains_threshold': 3,
        'excessive_subdomains_penalty': 15,
        'homograph_penalty': 30,
        'at_symbol_penalty': 20,
        'double_slash_penalty': 15,
    }


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    SECRET_KEY = os.getenv('SECRET_KEY')
    
    @classmethod
    def init_app(cls, app):
        """Initialize production-specific settings"""
        # Log to syslog in production
        import logging
        from logging.handlers import SysLogHandler
        
        if not app.debug:
            syslog_handler = SysLogHandler()
            syslog_handler.setLevel(logging.WARNING)
            app.logger.addHandler(syslog_handler)


class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    SECRET_KEY = 'testing-key'
    VIRUSTOTAL_API_KEY = ''  # Disabled for testing


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}


def get_config(config_name=None):
    """Get configuration by name"""
    if config_name is None:
        config_name = os.getenv('FLASK_ENV', 'development')
    return config.get(config_name, config['default'])
