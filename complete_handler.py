import requests
import time
import threading
import random
import logging
import re
import csv
import os
import urllib3
import traceback
import json
import gates
from concurrent.futures import ThreadPoolExecutor, as_completed
from telebot import types
from shopify_checker import check_site_shopify_direct, process_response_shopify
from datetime import datetime, date

OWNER_ID = [5963548505, 1614278744]

# ============================================================================
# STOP COMMAND HANDLING
# ============================================================================
stop_events = {}  # dict: chat_id -> bool (True means stop requested)

def set_stop(chat_id):
    stop_events[chat_id] = True

def clear_stop(chat_id):
    stop_events.pop(chat_id, None)

def is_stop_requested(chat_id):
    return stop_events.get(chat_id, False)

# ============================================================================
# CONCURRENCY CONTROL
# ============================================================================
user_busy = {}  # dict: user_id -> bool (True means a mass check is running)

def is_user_busy(user_id):
    return user_busy.get(user_id, False)

def set_user_busy(user_id, busy):
    user_busy[user_id] = busy

# ============================================================================
# PROXY CHECKING
# ============================================================================
def check_proxy_live(proxy):
    try:
        parts = proxy.strip().split(':')
        formatted = ""
        if len(parts) == 2:
            formatted = f"http://{parts[0]}:{parts[1]}"
        elif len(parts) == 4:
            formatted = f"http://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
        else:
            return None
        proxies_dict = {'http': formatted, 'https': formatted}
        r = requests.get("http://httpbin.org/ip", proxies=proxies_dict, timeout=5, verify=False)
        if r.status_code == 200:
            return proxy
    except:
        pass
    return None

USER_PROXIES_FILE = "user_proxies.json"

def load_user_proxies():
    if os.path.exists(USER_PROXIES_FILE):
        with open(USER_PROXIES_FILE, 'r') as f:
            return json.load(f)
    return {}

# ============================================================================
# SYSTEM CONFIGURATION
# ============================================================================
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# ============================================================================
# GLOBAL VARIABLES
# ============================================================================
user_sessions = {}
BINS_CSV_FILE = 'bins_all.csv'
MAX_RETRIES = 2
PROXY_TIMEOUT = 5
BIN_DB = {}

# ============================================================================
# CSV BIN DATABASE LOADER
# ============================================================================
def load_bin_database():
    global BIN_DB
    if not os.path.exists(BINS_CSV_FILE):
        logger.warning(f"⚠️ System: BIN CSV file '{BINS_CSV_FILE}' not found.")
        return
    try:
        with open(BINS_CSV_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.reader(f)
            next(reader, None)
            for row in reader:
                if len(row) >= 6:
                    BIN_DB[row[0].strip()] = {
                        'country_name': row[1].strip(),
                        'country_flag': get_flag_emoji(row[1].strip()),
                        'brand': row[2].strip(),
                        'type': row[3].strip(),
                        'level': row[4].strip(),
                        'bank': row[5].strip()
                    }
    except Exception as e:
        logger.error(f"❌ Error loading BIN CSV: {e}")

def get_flag_emoji(country_code):
    if not country_code or len(country_code) != 2: return "🇺🇳"
    return "".join([chr(ord(c.upper()) + 127397) for c in country_code])

load_bin_database()

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================
def get_bin_info(card_number):
    clean_cc = re.sub(r'\D', '', str(card_number))
    bin_code = clean_cc[:6]
    if bin_code in BIN_DB:
        return BIN_DB[bin_code]
    try:
        response = requests.get(f"https://bins.antipublic.cc/bins/{bin_code}", timeout=3)
        if response.status_code == 200:
            data = response.json()
            return {
                'country_name': data.get('country_name', 'Unknown'),
                'country_flag': data.get('country_flag', '🇺🇳'),
                'brand': data.get('brand', 'Unknown'),
                'type': data.get('type', 'Unknown'),
                'level': data.get('level', 'Unknown'),
                'bank': data.get('bank', 'Unknown')
            }
    except:
        pass
    return {'country_name': 'Unknown', 'country_flag': '🇺🇳', 'bank': 'UNKNOWN', 'brand': 'UNKNOWN', 'type': 'UNKNOWN', 'level': 'UNKNOWN'}

def extract_cards_from_text(text):
    valid_ccs = []
    text = text.replace(',', '\n').replace(';', '\n')
    lines = text.split('\n')
    for line in lines:
        line = line.strip()
        if len(line) < 15: continue
        match = re.search(r'(\d{13,19})[|:/\s](\d{1,2})[|:/\s](\d{2,4})[|:/\s](\d{3,4})', line)
        if match:
            cc, mm, yyyy, cvv = match.groups()
            if len(yyyy) == 2: yyyy = "20" + yyyy
            mm = mm.zfill(2)
            if 1 <= int(mm) <= 12:
                valid_ccs.append(f"{cc}|{mm}|{yyyy}|{cvv}")
    return list(set(valid_ccs))

def create_progress_bar(processed, total, length=15):
    if total == 0: return ""
    percent = processed / total
    filled_length = int(length * percent)
    return f"<code>{'█' * filled_length}{'░' * (length - filled_length)}</code> {int(percent * 100)}%"

# ============================================================================
# PROXY VALIDATION
# ============================================================================
def validate_proxies_strict(proxies, bot, message):
    live_proxies = []
    total = len(proxies)
    status_msg = bot.reply_to(message, f"🛡️ <b>Verifying {total} Proxies...</b>", parse_mode='HTML')
    last_ui_update = time.time()
    checked = 0

    def check(proxy_str):
        try:
            parts = proxy_str.split(':')
            if len(parts) == 2: url = f"http://{parts[0]}:{parts[1]}"
            elif len(parts) == 4: url = f"http://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
            else: return False
            requests.get("http://httpbin.org/ip", proxies={'http': url, 'https': url}, timeout=PROXY_TIMEOUT)
            return True
        except:
            return False

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(check, p): p for p in proxies}
        for future in as_completed(futures):
            checked += 1
            if future.result():
                live_proxies.append(futures[future])
            if time.time() - last_ui_update > 2:
                try:
                    bot.edit_message_text(
                        f"🛡️ <b>Verifying Proxies</b>\n✅ Live: {len(live_proxies)}\n💀 Dead: {checked - len(live_proxies)}\n📊 {checked}/{total}",
                        message.chat.id, status_msg.message_id, parse_mode='HTML'
                    )
                    last_ui_update = time.time()
                except:
                    pass

    try:
        bot.delete_message(message.chat.id, status_msg.message_id)
    except:
        pass
    return live_proxies

# ============================================================================
# USAGE TRACKING & LIMITS
# ============================================================================
def reset_usage_if_needed(user_data):
    """If last_usage_reset is not today, reset usage_today to 0."""
    today = date.today().isoformat()
    if user_data.get('last_usage_reset') != today:
        user_data['usage_today'] = 0
        user_data['last_usage_reset'] = today

def get_user_upload_limit(user_id, users_data):
    user_str = str(user_id)
    user_info = users_data.get(user_str, {})
    if not user_info:
        return 0
    # Ensure limit is at least 1 (treat 0 as default 1000)
    limit = user_info.get('limit', 1000)
    return 1000 if limit <= 0 else limit

def get_user_daily_remaining(user_id, users_data):
    user_str = str(user_id)
    user_info = users_data.get(user_str, {})
    if not user_info:
        return 0
    reset_usage_if_needed(user_info)
    daily_limit = user_info.get('daily_limit', 10000)  # default daily total
    used = user_info.get('usage_today', 0)
    return max(0, daily_limit - used)

def increment_usage(user_id, amount, users_data, save_json_func, users_file):
    user_str = str(user_id)
    user_info = users_data.get(user_str)
    if not user_info:
        return
    reset_usage_if_needed(user_info)
    user_info['usage_today'] = user_info.get('usage_today', 0) + amount
    save_json_func(users_file, users_data)

# ============================================================================
# MAIN HANDLER SETUP
# ============================================================================
def setup_complete_handler(bot, get_filtered_sites_func, proxies_data,
                          check_site_func, is_valid_response_func,
                          process_response_func, update_stats_func, save_json_func,
                          is_user_allowed_func, users_data, users_file):

    @bot.message_handler(commands=['stop'])
    def handle_stop(message):
        chat_id = message.chat.id
        if is_stop_requested(chat_id):
            bot.reply_to(message, "⏸️ Stop already requested. Please wait for the current check to finish.")
        else:
            set_stop(chat_id)
            bot.reply_to(message, "⏸️ Stop command received. The mass check will abort after the current card finishes.")

    @bot.message_handler(content_types=['document'])
    def handle_file_upload_event(message):
        if not is_user_allowed_func(message.from_user.id):
            bot.reply_to(message, "🚫 <b>Access Denied</b>", parse_mode='HTML')
            return

        try:
            file_name = message.document.file_name.lower()
            if not file_name.endswith('.txt'):
                bot.reply_to(message, "❌ <b>Format Error:</b> Only .txt files.", parse_mode='HTML')
                return

            msg_loading = bot.reply_to(message, "⏳ <b>Reading File...</b>", parse_mode='HTML')
            file_info = bot.get_file(message.document.file_id)
            file_content = bot.download_file(file_info.file_path).decode('utf-8', errors='ignore')

            ccs = extract_cards_from_text(file_content)

            if ccs:
                user_id = message.from_user.id
                # Check per‑upload limit
                limit = get_user_upload_limit(user_id, users_data)
                if len(ccs) > limit and user_id not in OWNER_ID:
                    bot.edit_message_text(
                        f"⚠️ <b>Limit Exceeded!</b>\n\n"
                        f"Your per‑upload limit is <b>{limit}</b> cards.\n"
                        f"You uploaded <b>{len(ccs)}</b> cards.\n"
                        f"<b>Only the first {limit} cards will be checked.</b>\n\n"
                        f"To check the rest, split your file into smaller parts and upload again.\n"
                        f"Use <code>/stop</code> at any time to abort the current check.",
                        message.chat.id, msg_loading.message_id, parse_mode='HTML'
                    )
                    ccs = ccs[:limit]  # keep only first 'limit' cards
                    # Wait a moment so user reads the warning
                    time.sleep(2)

                if user_id not in user_sessions:
                    user_sessions[user_id] = {}
                user_sessions[user_id]['ccs'] = ccs

                # NEW BUTTONS – only working gates
                markup = types.InlineKeyboardMarkup(row_width=1)
                markup.add(types.InlineKeyboardButton("🛍️ Shopify Multi-Site", callback_data="run_mass_shopify"))
                markup.add(types.InlineKeyboardButton("🅿️ PayPal SFTS", callback_data="run_mass_paypal_sfts"))
                markup.add(types.InlineKeyboardButton("🏫 Morris.edu AuthNet", callback_data="run_mass_morris"))
                markup.add(types.InlineKeyboardButton("⚡ NYEnergyForum $5", callback_data="run_mass_nyenergy"))
                markup.add(types.InlineKeyboardButton("🌱 PlantVine Braintree", callback_data="run_mass_plantvine"))
                markup.add(types.InlineKeyboardButton("❌ Cancel", callback_data="action_cancel"))

                bot.edit_message_text(
                    f"📂 <b>File:</b> <code>{file_name}</code>\n"
                    f"💳 <b>Cards to check:</b> {len(ccs)}\n"
                    f"<b>⚡ Select Checking Gate:</b>",
                    message.chat.id, msg_loading.message_id,
                    reply_markup=markup, parse_mode='HTML'
                )
            else:
                # Proxy file handling
                raw_proxies = [line.strip() for line in file_content.split('\n') if ':' in line]
                if raw_proxies:
                    bot.edit_message_text(
                        f"⏳ <b>Validating {len(raw_proxies)} Proxies...</b>\n<i>Filtering dead ones...</i>",
                        message.chat.id, msg_loading.message_id, parse_mode='HTML'
                    )
                    live_proxies = []
                    with ThreadPoolExecutor(max_workers=50) as executor:
                        futures = {executor.submit(check_proxy_live, p): p for p in raw_proxies}
                        for i, future in enumerate(as_completed(futures)):
                            res = future.result()
                            if res:
                                live_proxies.append(res)
                            if i % 25 == 0:
                                try:
                                    bot.edit_message_text(
                                        f"⚡ <b>Filtering Proxies...</b>\n"
                                        f"Checked: {i}/{len(raw_proxies)}\n"
                                        f"✅ Live: {len(live_proxies)}",
                                        message.chat.id, msg_loading.message_id, parse_mode='HTML'
                                    )
                                except:
                                    pass
                    user_id = message.from_user.id
                    if user_id not in user_sessions:
                        user_sessions[user_id] = {}
                    user_sessions[user_id]['proxies'] = live_proxies
                    bot.edit_message_text(
                        f"✅ <b>Proxy Check Complete</b>\n\n"
                        f"📂 Total Found: {len(raw_proxies)}\n"
                        f"🟢 <b>Live Loaded:</b> {len(live_proxies)}\n"
                        f"🔴 Dead Discarded: {len(raw_proxies) - len(live_proxies)}\n\n"
                        f"✅ You can now run Mass Check.",
                        message.chat.id, msg_loading.message_id, parse_mode='HTML'
                    )
                else:
                    bot.edit_message_text("❌ No valid CCs or Proxies found.", message.chat.id, msg_loading.message_id)

        except Exception as e:
            bot.reply_to(message, f"❌ Error: {e}")

    # Shopify mass check command (unchanged)
    @bot.message_handler(commands=['msh', 'hardcook'])
    def handle_mass_check_command(message):
        if not is_user_allowed_func(message.from_user.id):
            bot.send_message(message.chat.id, "🚫 <b>Access Denied</b>", parse_mode='HTML')
            return
        user_id = message.from_user.id
        if user_id not in user_sessions or 'ccs' not in user_sessions[user_id] or not user_sessions[user_id]['ccs']:
            bot.send_message(message.chat.id, "⚠️ <b>Upload CCs first!</b>", parse_mode='HTML')
            return
        ccs = user_sessions[user_id]['ccs']
        # Check daily remaining
        remaining = get_user_daily_remaining(user_id, users_data)
        if remaining < len(ccs):
            bot.send_message(message.chat.id,
                f"❌ <b>Daily Limit Exceeded!</b>\n\nYou have only {remaining} cards left for today.",
                parse_mode='HTML')
            return
        # Check concurrency
        if is_user_busy(user_id) and user_id not in OWNER_ID:
            bot.send_message(message.chat.id, "⏳ You already have a mass check in progress. Please wait.", parse_mode='HTML')
            return
        set_user_busy(user_id, True)

        sites = get_filtered_sites_func()
        if not sites:
            bot.send_message(message.chat.id, "❌ <b>No sites available!</b> Add sites via /addurls", parse_mode='HTML')
            set_user_busy(user_id, False)
            return
        active_proxies = []
        proxies = get_active_proxies(user_id)
        if not proxies:
            bot.send_message(message.chat.id, "🚫 <b>Proxy Required!</b> Add proxies via /addpro or upload a proxy file.", parse_mode='HTML')
            set_user_busy(user_id, False)
            return
        active_proxies = validate_proxies_strict(proxies, bot, message)
        if not active_proxies:
            bot.send_message(message.chat.id, "❌ <b>All your proxies are dead.</b>", parse_mode='HTML')
            set_user_busy(user_id, False)
            return
        source = f"🔒 User ({len(active_proxies)})"
        start_msg = bot.send_message(message.chat.id, f"🔥 <b>Starting...</b>\n💳 {len(ccs)} Cards\n🔌 {source}", parse_mode='HTML')
        threading.Thread(
            target=process_mass_check_engine,
            args=(bot, message, start_msg, ccs, sites, active_proxies,
                  check_site_func, process_response_func, update_stats_func, user_id, users_data, save_json_func, users_file)
        ).start()

    # Helper to get proxies for user – only returns user's own proxies, no server proxies for non-owners
    def get_active_proxies(user_id):
        user_id = str(user_id)
        logger.info(f"🔍 get_active_proxies for user {user_id}")

        # Priority 1: Temporary Session Proxies (from file upload)
        if int(user_id) in user_sessions and user_sessions[int(user_id)].get('proxies'):
            proxies = user_sessions[int(user_id)]['proxies']
            logger.info(f"   → Found session proxies: {proxies[:3]}... (total {len(proxies)})")
            return proxies

        # Priority 2: Persistent Personal Proxies (from /addpro)
        saved_proxies = load_user_proxies()
        if user_id in saved_proxies and saved_proxies[user_id]:
            proxies = saved_proxies[user_id]
            logger.info(f"   → Found saved proxies: {proxies[:3]}... (total {len(proxies)})")
            return proxies

        # Priority 3: Server Proxies – ONLY for owners
        if int(user_id) in OWNER_ID:
            if proxies_data and 'proxies' in proxies_data and proxies_data['proxies']:
                proxies = proxies_data['proxies']
                logger.info(f"   → Owner using server proxies: {len(proxies)} total")
                return proxies

        logger.info(f"   → No proxies found for user {user_id}")
        return None

    # ===== CALLBACKS FOR EACH GATE =====

    @bot.callback_query_handler(func=lambda call: call.data == "run_mass_shopify")
    def callback_shopify(call):
        bot.delete_message(call.message.chat.id, call.message.message_id)
        bot.send_message(call.message.chat.id, "ℹ️ Shopify mass check not implemented in this button – use the /msh command.")
        return

    def run_mass_gate(call, gate_func, gate_name):
        try:
            bot.delete_message(call.message.chat.id, call.message.message_id)
            user_id = call.from_user.id
            if user_id not in user_sessions or 'ccs' not in user_sessions[user_id]:
                bot.send_message(call.message.chat.id, "⚠️ Session expired. Upload file again.")
                return
            ccs = user_sessions[user_id]['ccs']
            # Check daily remaining
            remaining = get_user_daily_remaining(user_id, users_data)
            if remaining < len(ccs):
                bot.send_message(call.message.chat.id,
                    f"❌ <b>Daily Limit Exceeded!</b>\n\nYou have only {remaining} cards left for today.",
                    parse_mode='HTML')
                return
            # Check concurrency
            if is_user_busy(user_id) and user_id not in OWNER_ID:
                bot.send_message(call.message.chat.id, "⏳ You already have a mass check in progress. Please wait.", parse_mode='HTML')
                return
            set_user_busy(user_id, True)

            proxies = get_active_proxies(user_id)
            if not proxies:
                bot.send_message(call.message.chat.id, "🚫 <b>Proxy Required!</b>", parse_mode='HTML')
                set_user_busy(user_id, False)
                return
            process_mass_gate_check(bot, call.message, ccs, gate_func, gate_name, proxies,
                                    user_id, users_data, save_json_func, users_file)
        except Exception as e:
            bot.send_message(call.message.chat.id, f"❌ Error: {e}")
            set_user_busy(user_id, False)

    @bot.callback_query_handler(func=lambda call: call.data == "run_mass_paypal_sfts")
    def callback_paypal_sfts(call):
        run_mass_gate(call, gates.check_paypal_sfts, "PayPal SFTS")

    @bot.callback_query_handler(func=lambda call: call.data == "run_mass_morris")
    def callback_morris(call):
        run_mass_gate(call, gates.check_morris_authnet, "Morris AuthNet")

    @bot.callback_query_handler(func=lambda call: call.data == "run_mass_nyenergy")
    def callback_nyenergy(call):
        run_mass_gate(call, gates.check_nyenergyforum, "NYEnergyForum")

    @bot.callback_query_handler(func=lambda call: call.data == "run_mass_plantvine")
    def callback_plantvine(call):
        run_mass_gate(call, gates.check_plantvine, "PlantVine")

    @bot.callback_query_handler(func=lambda call: call.data == "action_cancel")
    def callback_cancel(call):
        bot.delete_message(call.message.chat.id, call.message.message_id)

# ============================================================================
# MASS CHECK ENGINE (GENERIC) with STOP support & USAGE TRACKING
# ============================================================================
def process_mass_gate_check(bot, message, ccs, gate_func, gate_name, proxies,
                            user_id, users_data, save_json_func, users_file):
    total = len(ccs)
    results = {"live": [], "dead": [], "error": []}
    chat_id = message.chat.id

    # Clear any previous stop flag for this chat
    clear_stop(chat_id)

    # Validate proxies (live check)
    def validate_proxy(p):
        try:
            parts = p.split(':')
            if len(parts) == 2:
                url = f"http://{parts[0]}:{parts[1]}"
            elif len(parts) == 4:
                url = f"http://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
            else:
                return None
            proxies_dict = {'http': url, 'https': url}
            r = requests.get("https://httpbin.org/ip", proxies=proxies_dict, timeout=10, verify=False)
            return p if r.status_code == 200 else None
        except:
            return None

    live_proxies = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(validate_proxy, p): p for p in proxies}
        for future in as_completed(futures):
            if future.result():
                live_proxies.append(future.result())
    if not live_proxies:
        bot.send_message(chat_id, "❌ No live proxies available. Aborting.")
        set_user_busy(user_id, False)
        return
    proxies = live_proxies

    try:
        status_msg = bot.send_message(
            chat_id,
            f"<b>⚡ {gate_name} Started...</b>\n"
            f"💳 Cards: {total}\n"
            f"🌐 Live Proxies: {len(proxies)}\n"
            f"<i>Use /stop to abort</i>",
            parse_mode="HTML"
        )
    except:
        status_msg = bot.send_message(chat_id, f"<b>{gate_name} Started...</b>", parse_mode="HTML")

    processed = 0
    start_time = time.time()
    last_update_time = time.time()

    def worker(cc):
        # Check stop flag before even starting this card
        if is_stop_requested(chat_id):
            return {
                "cc": cc,
                "response": "Stopped by user",
                "status": "STOPPED",
                "gateway": gate_name,
                "site_url": "API"
            }
        max_tries = 3
        tried_proxies = []
        for attempt in range(max_tries):
            available = [p for p in proxies if p not in tried_proxies]
            if not available:
                break
            proxy = random.choice(available)
            tried_proxies.append(proxy)
            try:
                response_text, status = gate_func(cc, proxy)
                return {
                    "cc": cc,
                    "response": response_text,
                    "status": status,
                    "gateway": gate_name,
                    "site_url": "API"
                }
            except Exception as e:
                print(f"Attempt {attempt+1} failed for {cc} with proxy {proxy}: {e}")
                continue
        return {
            "cc": cc,
            "response": "All proxies failed",
            "status": "ERROR",
            "gateway": gate_name,
            "site_url": "API"
        }

    # Submit futures, but check stop flag before submitting each one
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {}
        for cc in ccs:
            if is_stop_requested(chat_id):
                # Mark remaining cards as stopped
                for remaining_cc in ccs[processed:]:
                    results["error"].append({
                        "cc": remaining_cc,
                        "response": "Stopped by user",
                        "status": "STOPPED",
                        "gateway": gate_name,
                        "site_url": "API"
                    })
                break
            future = executor.submit(worker, cc)
            futures[future] = cc

        for future in as_completed(futures):
            processed += 1
            try:
                res = future.result()
                status = res["status"]
                if status == "STOPPED":
                    results["error"].append(res)
                elif status == "APPROVED" or status == "CHARGED" or "CVV" in status:
                    results["live"].append(res)
                    send_hit(bot, chat_id, res, f"✅ {gate_name} LIVE")
                elif status == "DECLINED":
                    results["dead"].append(res)
                else:
                    results["error"].append(res)
            except Exception as e:
                results["error"].append({"cc": futures[future], "response": str(e), "status": "ERROR"})

            if time.time() - last_update_time > 2.5 or processed == total or is_stop_requested(chat_id):
                try:
                    progress = create_progress_bar(processed, total)
                    msg_text = (
                        f"<b>⚡ {gate_name} Checking...</b>\n"
                        f"{progress}\n"
                        f"📊 <b>Progress:</b> {processed}/{total}\n"
                        f"✅ <b>Live:</b> {len(results['live'])}\n"
                        f"❌ <b>Dead:</b> {len(results['dead'])}\n"
                        f"⚠️ <b>Errors:</b> {len(results['error'])}"
                    )
                    bot.edit_message_text(msg_text, chat_id, status_msg.message_id, parse_mode="HTML")
                    last_update_time = time.time()
                except:
                    pass

    # Clear stop flag after completion
    clear_stop(chat_id)

    # Increment usage (cards processed = total that were actually submitted, including stopped ones)
    increment_usage(user_id, processed, users_data, save_json_func, users_file)

    # Release user busy flag
    set_user_busy(user_id, False)

    duration = time.time() - start_time
    final_text = (
        f"<b>✅ {gate_name} Completed</b>\n"
        f"━━━━━━━━━━━━━━━━\n"
        f"💳 <b>Total Checked:</b> {total}\n"
        f"✅ <b>Live:</b> {len(results['live'])}\n"
        f"❌ <b>Dead:</b> {len(results['dead'])}\n"
        f"⚠️ <b>Errors:</b> {len(results['error'])}\n"
        f"⏱️ <b>Time Taken:</b> {duration:.2f}s"
    )
    try:
        bot.edit_message_text(final_text, chat_id, status_msg.message_id, parse_mode="HTML")
    except:
        bot.send_message(chat_id, final_text, parse_mode="HTML")

# ============================================================================
# SHOPIFY MASS CHECK ENGINE (placeholder – adapt your existing function)
# ============================================================================
def process_mass_check_engine(bot, message, start_msg, ccs, sites, proxies,
                              check_site_func, process_response_func, update_stats_func,
                              user_id, users_data, save_json_func, users_file):
    # This is a placeholder – you need to adapt your existing Shopify mass check function
    # to use the same concurrency and usage tracking.
    # After completion, call increment_usage(user_id, processed, ...)
    # and set_user_busy(user_id, False)
    pass

# ============================================================================
# MESSAGING
# ============================================================================
def send_hit(bot, chat_id, res, title):
    try:
        bin_info = get_bin_info(res['cc'])
        site_name = res['site_url'].replace('https://', '').replace('http://', '').split('/')[0]
        header_emoji = "🔥" if "COOKED" in title else "✅"
        msg = f"""
┏━━━━━━━⍟
┃ <b>{title} HIT!</b> {header_emoji}
┗━━━━━━━━━━━⊛
[⌬] 𝐂𝐚𝐫𝐝↣ <code>{res['cc']}</code>
[⌬] 𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞↣ {res['response']}
[⌬] 𝐆𝐚𝐭𝐞𝐰𝐚𝐲↣ {res['gateway']}
[⌬] 𝐔𝐑𝐋↣ {site_name}
━━━━━━━━━━━━━━━━━━━━
[⌬] 𝐁𝐫𝐚𝐧𝐝↣ {bin_info.get('brand', 'UNKNOWN').upper()} {bin_info.get('type', 'UNKNOWN').upper()}
[⌬] 𝐁𝐚𝐧𝐤↣ {bin_info.get('bank', 'UNKNOWN').upper()}
[⌬] 𝐂𝐨𝐮𝐧𝐭𝐫𝐲↣ {bin_info.get('country_name', 'UNKNOWN').upper()} {bin_info.get('country_flag', '🏳️')}
━━━━━━━━━━━━━━━━━━━━
Owner :- @Unknown_bolte
"""
        bot.send_message(chat_id, msg, parse_mode='HTML')
    except Exception as e:
        print(f"Error sending hit: {e}")

def update_ui(bot, chat_id, mid, processed, total, results):
    try:
        msg = f"""
┏━━━━━━━⍟
┃ <b>⚡ MASS CHECKING...</b>
┗━━━━━━━━━━━⊛
{create_progress_bar(processed, total)}
<b>Progress:</b> {processed}/{total}
🔥 <b>Cooked:</b> {len(results.get('cooked', []))}
✅ <b>Approved:</b> {len(results.get('approved', []))}
❌ <b>Declined:</b> {len(results.get('declined', []))}
⚠️ <b>Errors:</b> {len(results.get('error', []))}
"""
        bot.edit_message_text(msg, chat_id, mid, parse_mode='HTML')
    except:
        pass

def send_final(bot, chat_id, mid, total, results, duration):
    msg = f"""
┏━━━━━━━⍟
┃ <b>✅ CHECK COMPLETED</b>
┗━━━━━━━━━━━⊛
🔥 <b>Cooked:</b> {len(results.get('cooked', []))}
✅ <b>Approved:</b> {len(results.get('approved', []))}
❌ <b>Declined:</b> {len(results.get('declined', []))}
<b>Total:</b> {total} | <b>Time:</b> {duration:.2f}s
"""
    try:
        bot.edit_message_text(msg, chat_id, mid, parse_mode='HTML')
    except:
        bot.send_message(chat_id, msg, parse_mode='HTML')

