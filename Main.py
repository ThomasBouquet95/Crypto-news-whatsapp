from openai import OpenAI
import json
import os
import requests
import feedparser
from dotenv import load_dotenv
from datetime import datetime, timezone, timedelta
from bs4 import BeautifulSoup
from twilio.rest import Client
import hashlib
import logging
import gspread
import uuid
from oauth2client.service_account import ServiceAccountCredentials

# --- Setup Logging ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# --- Load environment variables ---
load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
WHATSAPP_TO = '+41782238841'  # Replace with your number

# --- Initialize OpenAI client ---
client = OpenAI(api_key=OPENAI_API_KEY)

# --- RSS feeds to monitor ---
RSS_FEEDS = {
    "CoinDesk": "https://www.coindesk.com/arc/outboundfeeds/rss/",
    "Cointelegraph": "https://cointelegraph.com/rss",
    "Decrypt": "https://decrypt.co/feed",
    "The Block": "https://www.theblock.co/feeds/rss",
    "Financial Times": "https://www.ft.com/?format=rss",
    "Reuters (Tech)": "https://www.reutersagency.com/feed/?best-sectors=technology",
}

# --- Google Sheets Credential Loader (hybrid) ---
def get_google_credentials():
    scope = [
        "https://spreadsheets.google.com/feeds",
        "https://www.googleapis.com/auth/drive"
    ]
    env_creds = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON")
    if env_creds:
        logging.info("\ud83d\udd10 Using credentials from environment variable")
        creds_dict = json.loads(env_creds)
        return ServiceAccountCredentials.from_json_keyfile_dict(creds_dict, scope)
    else:
        logging.info("\ud83d\udcc1 Using local service_account.json file")
        return ServiceAccountCredentials.from_json_keyfile_name("service_account.json", scope)

# --- Google Sheets Access ---
def get_google_sheet():
    creds = get_google_credentials()
    client = gspread.authorize(creds)
    sheet = client.open("Crypto News Sent Hashes").worksheet("Hashes")
    return sheet

# --- Tracking Sent News ---
def load_sent_hashes():
    sheet = get_google_sheet()
    records = sheet.get_all_records()
    return set(row["hash"] for row in records)

def save_sent_hashes(hashes):
    sheet = get_google_sheet()
    now = datetime.now(timezone.utc).isoformat()
    rows = [[h, now] for h in hashes]
    sheet.append_rows(rows)
    logging.info(f"\u2705 Saved {len(hashes)} hashes to Google Sheet")

# --- Compute URL Hash ---
def compute_hash_from_url(url):
    return hashlib.sha256(url.encode("utf-8")).hexdigest()

# --- Shorten URLs using TinyURL ---
def shorten_url(url):
    try:
        response = requests.get(f"https://tinyurl.com/api-create.php?url={url}")
        if response.status_code == 200:
            return response.text
        else:
            return url
    except Exception as e:
        logging.warning(f"Failed to shorten URL: {e}")
        return url

# --- Strip HTML from summaries ---
def strip_html(text):
    return BeautifulSoup(text, "html.parser").get_text()

# --- Fetch Crypto News ---
def fetch_crypto_news():
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=24)
    news_items = []

    logging.info("\ud83d\udcf1 Fetching crypto news...")
    for source, url in RSS_FEEDS.items():
        logging.info(f"\ud83c\udf10 Parsing feed from: {source}")
        feed = feedparser.parse(url)
        for entry in feed.entries:
            pub_datetime = None
            if hasattr(entry, 'published_parsed'):
                pub_datetime = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
            elif hasattr(entry, 'updated_parsed'):
                pub_datetime = datetime(*entry.updated_parsed[:6], tzinfo=timezone.utc)

            if not pub_datetime or pub_datetime < cutoff:
                continue

            title = entry.title.strip()
            summary = strip_html(entry.summary)[:300].strip().replace("\n", " ") if hasattr(entry, 'summary') else ""
            date_str = pub_datetime.strftime("%Y-%m-%d %H:%M")
            link = entry.link.strip() if hasattr(entry, 'link') else ""
            short_link = shorten_url(link)

            formatted_news = f"[{title}]: {summary} ({source}, {date_str})\nLink: {short_link}"
            news_items.append(formatted_news)

    logging.info(f"\ud83d\udcf0 Fetched {len(news_items)} news items in the last 24h.")
    return "\n".join(news_items) if news_items else "No news found in the last 24 hours."

# --- Add Header to the Summary ---
def add_crypto_update_header(summary):
    # Add the "Crypto updates" header at the beginning
    return "🚀 Crypto updates:\n\n" + summary

# --- Summarize News with OpenAI ---
def summarize_crypto_news(raw_news: str, model="gpt-4"):
    logging.info("\ud83e\udd16 Summarizing news with GPT-4...")

    prompt = (
        "Context: I work at Sygnum, a regulated crypto bank serving corporate, institutional, "
        "and private clients with services including custody, brokerage, lending, and tokenization. "
        "I'm currently based in the Singapore office.\n\n"
        "Task: Based on the crypto news listed below, please identify 1 to 4 key stories that are relevant to "
        "regulatory developments, company activity (e.g., acquisitions, partnerships, launches), or technology updates "
        "in the digital asset space.\n\n"
        "Format: For each selected news item, provide:\n"
        "- A short headline-style summary (2–4 words), followed by\n"
        "- A one to two line description\n"
        "- At the end of the line, include the source and the publication date in this format: (Cointelegraph, 06 Apr 2025)\n"
        "- On the next line, include the full URL to the article (no brackets)\n"
        "- Do not use 'Source:' or 'Date:' labels — just format exactly as shown\n"
        "- Separate each item with a blank line\n\n"
        "Example:\n"
        "Stablecoin Guidelines Drafted: The SEC released a new proposal for stablecoin oversight. (CoinDesk, 06 Apr 2025)\n"
        "Link: https://example.com/article\n\n"
        f"News:\n{raw_news}"
    )

    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}]
    )

    result = response.choices[0].message.content
    return result

# --- Filter Summary for Unsent Links ---
def extract_links_and_blocks(summary_text):
    summary_blocks = summary_text.strip().split("\n\n")
    results = []
    for block in summary_blocks:
        lines = block.strip().splitlines()
        if len(lines) >= 2 and lines[1].startswith("Link: "):
            url = lines[1].replace("Link: ", "").strip()
            results.append((url, block))
    return results

def filter_unsent_blocks(summary_text):
    seen_hashes = load_sent_hashes()
    new_hashes = set()
    blocks_to_send = []

    for url, block in extract_links_and_blocks(summary_text):
        # 👇 Hash the original (unshortened) URL
        original_url = url.split("?")[0] if "tinyurl.com" in url else url
        hash_val = compute_hash_from_url(original_url)

        if hash_val not in seen_hashes:
            blocks_to_send.append(block)
            new_hashes.add(hash_val)

    if new_hashes:
        save_sent_hashes(new_hashes)
    else:
        logging.info("ℹ️ No new blocks to send (all URLs were already seen).")

    return "\n\n".join(blocks_to_send)

# --- Send WhatsApp via Twilio ---
def send_whatsapp_message(body, to_number):
    client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    message = client.messages.create(
        from_='whatsapp:+14155238886',
        body=body,
        to=f'whatsapp:{to_number}'
    )
    logging.info(f"\ud83d\udce4 WhatsApp message sent (SID: {message.sid})")

# --- Main Execution ---
if __name__ == "__main__":
    logging.info("\ud83d\ude80 Starting Crypto News Summary Bot")
    logging.info("\ud83d\udd10 OpenAI key loaded: " + OPENAI_API_KEY[:8] + "...")

    news = fetch_crypto_news()
    logging.info("\ud83d\udcc4 Raw news fetched.")

    summary = summarize_crypto_news(news)
    logging.info("🧠 GPT-4 Summary:\n" + summary)
    filtered_summary = filter_unsent_blocks(summary)

    if filtered_summary:
        summary_with_header = add_crypto_update_header(filtered_summary)
        send_whatsapp_message(summary_with_header, WHATSAPP_TO)
        logging.info("\u2705 New summary sent.")
        logging.info("\n" + summary_with_header)
    else:
        logging.info("\u23f8 No new articles to send.")
