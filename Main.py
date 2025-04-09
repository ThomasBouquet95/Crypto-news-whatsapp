import os
import sys
import json
import logging
import hashlib
import requests
import feedparser
import re
from datetime import datetime, timezone, timedelta
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from openai import OpenAI
from twilio.rest import Client  # WhatsApp
import gspread
from oauth2client.service_account import ServiceAccountCredentials

# --- Setup Logging ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# --- Load Environment Variables ---
load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
WHATSAPP_TO = '+41782238841'  # WhatsApp recipient number

# --- Initialize OpenAI Client ---
client = OpenAI(api_key=OPENAI_API_KEY)

# === WHATSAPP SECTION ===
# You can send messages via Twilio WhatsApp here if you implement it (currently unused)

# === TELEGRAM SECTION ===
BOT_TOKEN = os.getenv("TELEGRAM_TOKEN")
if not BOT_TOKEN:
    logging.error("Missing TELEGRAM_TOKEN in .env file.")
    sys.exit(1)
API_BASE_URL = f"https://api.telegram.org/bot{BOT_TOKEN}"

# --- RSS Feeds to Monitor ---
RSS_FEEDS = {
    "CoinDesk": "https://www.coindesk.com/arc/outboundfeeds/rss/",
    "Cointelegraph": "https://cointelegraph.com/rss",
    "Decrypt": "https://decrypt.co/feed",
    "The Block": "https://www.theblock.co/feeds/rss",
    "Financial Times": "https://www.ft.com/?format=rss",
    "Reuters (Tech)": "https://www.reutersagency.com/feed/?best-sectors=technology",
}

# --- Google Sheets Credential Loader ---
def get_google_credentials():
    scope = [
        "https://spreadsheets.google.com/feeds",
        "https://www.googleapis.com/auth/drive"
    ]
    env_creds = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON")
    if env_creds:
        logging.info("🔐 Using credentials from environment variable")
        creds_dict = json.loads(env_creds)
        return ServiceAccountCredentials.from_json_keyfile_dict(creds_dict, scope)
    else:
        logging.info("📁 Using local service_account.json file")
        return ServiceAccountCredentials.from_json_keyfile_name("service_account.json", scope)

# --- Google Sheets Access ---
def get_google_sheet():
    creds = get_google_credentials()
    client = gspread.authorize(creds)
    sheet = client.open("Crypto News Sent Hashes").worksheet("Hashes")
    return sheet

def load_sent_hashes():
    sheet = get_google_sheet()
    records = sheet.get_all_records()
    hashes = set(row["hash"] for row in records)
    logging.info(f"Loaded {len(hashes)} hashes from Google Sheet.")
    return hashes

def save_sent_hashes_and_summaries(hashes_with_blocks):
    sheet = get_google_sheet()
    now = datetime.now(timezone.utc).isoformat()
    rows = [[hash_val, now, block.replace("\n", " ").strip()] for hash_val, block in hashes_with_blocks]
    sheet.append_rows(rows)
    logging.info(f"✅ Saved {len(hashes_with_blocks)} hashes and summaries to Google Sheet.")

# --- Utility Functions ---
def compute_hash_from_url(url):
    return hashlib.sha256(url.encode("utf-8")).hexdigest()

def shorten_url(url):
    try:
        response = requests.get(f"https://tinyurl.com/api-create.php?url={url}")
        return response.text if response.status_code == 200 else url
    except Exception as e:
        logging.warning(f"Failed to shorten URL: {e}")
        return url

def strip_html(text):
    return BeautifulSoup(text, "html.parser").get_text()

# --- News Collection ---
def fetch_crypto_news():
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=24)
    news_items = []

    for source, url in RSS_FEEDS.items():
        feed = feedparser.parse(url)
        for entry in feed.entries:
            pub_datetime = getattr(entry, 'published_parsed', None) or getattr(entry, 'updated_parsed', None)
            if not pub_datetime:
                continue
            pub_datetime = datetime(*pub_datetime[:6], tzinfo=timezone.utc)
            if pub_datetime < cutoff:
                continue

            title = entry.title.strip()
            summary = strip_html(entry.summary)[:300].strip().replace("\n", " ") if hasattr(entry, 'summary') else ""
            date_str = pub_datetime.strftime("%Y-%m-%d %H:%M")
            link = entry.link.strip() if hasattr(entry, 'link') else ""
            short_link = shorten_url(link)
            formatted_news = f"[{title}]: {summary} ({source}, {date_str})\nLink: {short_link}"
            news_items.append(formatted_news)

    logging.info(f"📰 Fetched {len(news_items)} news items in the last 24h.")
    return "\n".join(news_items) if news_items else "No news found in the last 24 hours."

# --- Summarization ---
def summarize_crypto_news(raw_news: str, model="gpt-4"):
    logging.info("🤖 Summarizing news with GPT-4...")
    prompt = (
        "Context: I work at Sygnum, a regulated crypto bank serving corporate, institutional, "
        "and private clients with services including custody, brokerage, lending, and tokenization. "
        "I'm currently based in the Singapore office.\n\n"
        "Task: Based on the crypto news listed below, please identify 1 to 3 key stories that are relevant to "
        "regulatory developments, company activity (e.g., acquisitions, partnerships, launches), or technology updates "
        "in the digital asset space.\n\n"
        "Format: For each selected news item, provide:\n"
        "- A short headline-style summary (2–4 words), followed by\n"
        "- A one to two line description\n"
        "- At the end of the line, include the source and the publication date in this format: (Cointelegraph, 06 Apr 2025)\n"
        "- On the next line, include the full URL to the article (no brackets)\n"
        "- Do not use 'Source:' or 'Date:' labels — just format exactly as shown\n"
        "- Separate each item with a blank line\n\n"
        f"News:\n{raw_news}"
    )

    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content

def deduplicate_with_gpt(past_summaries, candidate_summaries, model="gpt-4"):
    """
    Use GPT to check which candidate stories are duplicates of previously sent stories.
    Returns a list of candidate indexes that are considered duplicates (e.g., [1, 2]).
    """
    prompt = (
        "You are helping deduplicate crypto news stories for a financial intelligence bot.\n\n"
        "Here is a list of news that was already sent to users:\n"
        "PAST:\n"
    )

    for idx, summary in enumerate(past_summaries, 1):
        prompt += f"{idx}. {summary}\n"

    prompt += "\nNow, here are the new stories being considered for today:\nCANDIDATES:\n"

    for idx, summary in enumerate(candidate_summaries, 1):
        prompt += f"{idx}. {summary}\n"

    prompt += (
        "\nPlease respond with:\n"
        "- 0 if none of the candidate stories are duplicates of the past ones.\n"
        "- A list like (1,2) if candidate 1 and 2 are already covered.\n"
        "- Only list the candidate numbers that are clear duplicates. Don't justify.\n\n"
        "Your response:"
    )

    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}]
    )

    reply = response.choices[0].message.content.strip()
    logging.info(f"🤖 GPT deduplication response: {reply}")

    if reply == "0":
        return []

    try:
        # Evaluate safely: e.g. '(1,2)' → [1, 2]
        numbers = eval(reply, {"__builtins__": {}})
        if isinstance(numbers, int):
            return [numbers]
        elif isinstance(numbers, (tuple, list)):
            return list(numbers)
    except Exception as e:
        logging.warning(f"⚠️ Could not parse GPT response: {reply}")
        logging.exception(e)
        return []

    return []

# --- Parsing Utilities ---
def extract_links_and_blocks(summary_text):
    summary_blocks = summary_text.strip().split("\n\n")
    results = []
    for block in summary_blocks:
        url_match = re.search(r'https?://\S+', block)
        if url_match:
            url = url_match.group(0)
            results.append((url, block))
    return results

def parse_block_to_variables(block):
    lines = block.strip().splitlines()
    if len(lines) < 2:
        logging.warning(f"❌ Block skipped due to insufficient lines:\n{block}")
        return None

    title = lines[0].strip().strip('"')
    summary = "No summary provided"
    source = "Unknown"
    date = datetime.now().strftime("%d %b %Y")
    url = ""

    # Try to extract summary + (Source, Date) from line 2
    match = re.match(r"(.+?)\s+\((.+?),\s+([^)]+)\)", lines[1])
    if match:
        summary = match.group(1).strip().lstrip("-").strip()
        source = match.group(2).strip()
        date = match.group(3).strip()
    else:
        logging.warning(f"⚠️ Could not parse source/date from line:\n{lines[1]}")

    # Look for a URL in any line
    for line in lines:
        url_match = re.search(r'https?://\S+', line)
        if url_match:
            url = url_match.group(0).strip(")")
            break

    return {
        "1": title,
        "2": summary,
        "3": source,
        "4": date,
        "5": url
    }

def sanitize_content(value):
    return value.encode("ascii", "ignore").decode("ascii").strip()

# --- TELEGRAM: Get All User Chat IDs ---
def get_all_telegram_chat_ids():
    try:
        response = requests.get(f"{API_BASE_URL}/getUpdates")
        response.raise_for_status()
        updates = response.json()
        messages = updates.get("result", [])
        if not messages:
            logging.warning("No messages found. Send a message to your bot first.")
            return []
        chat_ids = list({msg["message"]["chat"]["id"] for msg in messages if "message" in msg})
        logging.info(f"✅ Found {len(chat_ids)} unique chat_id(s): {chat_ids}")
        return chat_ids
    except requests.RequestException as e:
        logging.error("❌ Failed to fetch updates from Telegram.")
        logging.exception(e)
        return []

# --- TELEGRAM: Send Message ---
def send_telegram_message(chat_id: int, text: str):
    try:
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True
        }
        response = requests.post(f"{API_BASE_URL}/sendMessage", data=payload)
        response.raise_for_status()
        logging.info(f"✅ Message sent to {chat_id}")
    except requests.RequestException as e:
        logging.error(f"❌ Failed to send message to {chat_id}")
        logging.exception(e)

# --- Main Execution ---
if __name__ == "__main__":
    # Step 1: Fetch and summarize news
    news = fetch_crypto_news()
    summary = summarize_crypto_news(news)
    blocks_to_send = extract_links_and_blocks(summary)

    # Step 2: Load previously sent hashes and summaries
    seen_hashes = load_sent_hashes()
    new_hashes = set()
    sheet = get_google_sheet()
    records = sheet.get_all_records()
    past_summaries = [row["summary"] for row in records if "summary" in row and row["summary"].strip()]
    past_summaries = past_summaries[-100:]  # Limit for GPT context

    # Step 3: Deduplicate with GPT
    candidate_summaries = [block.replace("\n", " ").strip() for _, block in blocks_to_send]
    duplicate_indexes = deduplicate_with_gpt(past_summaries, candidate_summaries)

    final_blocks = [
        (url, block) for i, (url, block) in enumerate(blocks_to_send)
        if (i + 1) not in duplicate_indexes
    ]

    # Step 4: Send messages & collect those actually sent
    sent_blocks = []  # list of (hash, block) to save
    for url, block in final_blocks:
        shortened_url = shorten_url(url)
        hash_val = compute_hash_from_url(shortened_url)
        if hash_val not in seen_hashes:
            vars = parse_block_to_variables(block)
            if vars:
                logging.info(f"🚀 Sending with content_variables: {json.dumps(vars)}")
                vars = {k: sanitize_content(v) for k, v in vars.items()}

                expected_keys = {"1", "2", "3", "4", "5"}
                if set(vars.keys()) != expected_keys:
                    logging.error(f"⚠️ Unexpected or missing content variable keys: {vars.keys()}")

                try:
                    chat_ids = get_all_telegram_chat_ids()
                    message = (
                        f"🚨*{vars['1']}*: {vars['2']} ({vars['3']}, {vars['4']})\n"
                        f"🔗 Source: {vars['5']}"
                    )
                    logging.info(f"✅ Sent message for: Title: {vars['1']}")
                    for cid in chat_ids:
                        send_telegram_message(cid, message)
                    new_hashes.add(hash_val)
                    sent_blocks.append((hash_val, block))  # Store what was actually sent
                except Exception as e:
                    logging.error(f"❌ Failed to send message for: {vars}")
                    logging.exception(e)

    # Step 5: Save only the hashes/summaries of what was really sent
    if sent_blocks:
        save_sent_hashes_and_summaries(sent_blocks)
    else:
        logging.info("⏸ No new articles to send.")
