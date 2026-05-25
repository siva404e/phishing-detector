"""
Utilities module for PhishGuard Dashboard
Contains helper functions for URL validation, domain extraction, and scoring
"""

import re
import urllib.parse
from datetime import datetime


class URLValidator:
    """Validate and parse URLs"""
    
    @staticmethod
    def extract_domain(url):
        """Extract domain from URL"""
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc or parsed.path
            return domain.replace("www.", "").split("/")[0]
        except:
            return None
    
    @staticmethod
    def normalize_url(url):
        """Normalize URL by adding scheme if missing"""
        if not url.startswith(('http://', 'https://')):
            return 'https://' + url
        return url
    
    @staticmethod
    def is_valid_url(url):
        """Check if URL is valid"""
        try:
            result = urllib.parse.urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False


class RiskScorer:
    """Calculate risk scores for URLs"""
    
    @staticmethod
    def get_verdict(score):
        """Get risk level based on score"""
        if score >= 70:
            return "CRITICAL"
        elif score >= 45:
            return "HIGH"
        elif score >= 25:
            return "MODERATE"
        elif score >= 10:
            return "LOW"
        return "SAFE"
    
    @staticmethod
    def get_score_color(score):
        """Get color code for score"""
        if score >= 70:
            return '#ff3c5a'      # Red - Critical
        elif score >= 45:
            return '#ff6b35'      # Orange - High
        elif score >= 25:
            return '#ffaa00'      # Yellow - Moderate
        elif score >= 10:
            return '#88cc00'      # Light Green - Low
        return '#00ff9d'          # Cyan - Safe
    
    @staticmethod
    def get_verdict_emoji(level):
        """Get emoji for verdict level"""
        emojis = {
            'CRITICAL': '🚨',
            'HIGH': '⚠️',
            'MODERATE': '🔍',
            'LOW': '🔎',
            'SAFE': '✅'
        }
        return emojis.get(level, '🔍')


class DomainAnalyzer:
    """Analyze domain properties"""
    
    @staticmethod
    def get_domain_age_string(creation_date):
        """Convert creation date to readable age string"""
        try:
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo:
                creation_date = creation_date.replace(tzinfo=None)
            
            age_days = (datetime.now() - creation_date).days
            age_months = age_days // 30
            
            return f"{age_months}mo ({age_days}d)", age_days
        except:
            return None, None
    
    @staticmethod
    def categorize_domain_age(age_days):
        """Categorize domain age risk"""
        if age_days < 30:
            return {'risk': 'CRITICAL', 'score': 50, 'label': 'Very New Domain (< 30 days)'}
        elif age_days < 90:
            return {'risk': 'HIGH', 'score': 35, 'label': 'New Domain (30-90 days)'}
        elif age_days < 180:
            return {'risk': 'MODERATE', 'score': 20, 'label': 'Relatively New (90-180 days)'}
        elif age_days < 365:
            return {'risk': 'LOW', 'score': 10, 'label': 'Young Domain (180-365 days)'}
        elif age_days < 730:
            return {'risk': 'LOW', 'score': 5, 'label': 'Established Domain (1-2 years)'}
        else:
            return {'risk': 'SAFE', 'score': 0, 'label': 'Well-Established Domain (2+ years)'}


class PatternDetector:
    """Detect suspicious patterns in URLs"""
    
    IP_PATTERN = re.compile(r"(https?://)?(\d{1,3}\.){3}\d{1,3}")
    SUSPICIOUS_CHARS = ['@', '!', '&', '%', ';']
    
    @staticmethod
    def has_ip_address(url):
        """Check if URL contains IP address instead of domain"""
        return bool(PatternDetector.IP_PATTERN.match(url))
    
    @staticmethod
    def has_suspicious_characters(url):
        """Check for suspicious characters in URL"""
        for char in PatternDetector.SUSPICIOUS_CHARS:
            if char in url:
                return True, char
        return False, None
    
    @staticmethod
    def has_multiple_slashes(url):
        """Check for multiple '//' indicating redirect tricks"""
        return url.count("//") > 1
    
    @staticmethod
    def has_at_symbol(url):
        """Check for '@' symbol (phishing technique)"""
        return '@' in url
    
    @staticmethod
    def excessive_subdomains(domain, threshold=3):
        """Check for excessive subdomains"""
        dot_count = domain.count('.')
        return dot_count > threshold, dot_count
    
    @staticmethod
    def long_url(url, threshold=100):
        """Check if URL is unusually long"""
        return len(url) > threshold


class StringMatcher:
    """Match strings in content for keyword and pattern detection"""
    
    @staticmethod
    def find_keywords(text, keywords):
        """Find matching keywords in text"""
        text_lower = text.lower()
        found = []
        for keyword in keywords:
            if keyword.lower() in text_lower:
                found.append(keyword)
        return found
    
    @staticmethod
    def check_homograph_chars(text, homograph_map):
        """Check for homograph/unicode spoofing characters"""
        for char in text:
            if char in homograph_map:
                return True, char, homograph_map[char]
        return False, None, None


class TimeFormatter:
    """Format time-related information"""
    
    @staticmethod
    def get_current_time():
        """Get current time in HH:MM:SS format"""
        return datetime.now().strftime("%H:%M:%S")
    
    @staticmethod
    def format_certificate_expiry(cert_date):
        """Format certificate expiry date"""
        try:
            days_left = (cert_date - datetime.now()).days
            if days_left < 0:
                return f"Expired {abs(days_left)} days ago", days_left
            elif days_left == 0:
                return "Expires today", 0
            elif days_left == 1:
                return "Expires tomorrow", 1
            else:
                return f"Expires in {days_left} days", days_left
        except:
            return None, None


def sanitize_input(user_input, max_length=2048):
    """Sanitize user input for security"""
    if not user_input:
        return None
    
    # Remove leading/trailing whitespace
    sanitized = user_input.strip()
    
    # Check length
    if len(sanitized) > max_length:
        return None
    
    # Validate URL format
    if not URLValidator.is_valid_url(URLValidator.normalize_url(sanitized)):
        return None
    
    return sanitized


def format_check_result(check_type, text, score=0):
    """Format a check result for the dashboard"""
    return {
        "type": check_type,
        "text": text,
        "score": score
    }
