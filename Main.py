from openai import OpenAI
import os
import requests
import feedparser
from dotenv import load_dotenv
from datetime import datetime, timezone, timedelta
from bs4 import BeautifulSoup
from twilio.rest import Client
import hashlib
import logging

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

# --- File to track previously sent articles ---
SENT_NEWS_FILE = "sent_news.txt"

# --- Utility functions for tracking sent news ---

def load_sent_hashes():
    cutoff = datetime.now(timezone.utc) - timedelta(hours=48)
    valid_hashes = set()
    all_entries = []

    if not os.path.exists(SENT_NEWS_FILE):
        return valid_hashes

    with open(SENT_NEWS_FILE, 'r') as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) != 2:
                continue  # malformed line
            hash_val, timestamp = parts
            try:
                ts = datetime.fromisoformat(timestamp)
                if ts > cutoff:
                    valid_hashes.add(hash_val)
                    all_entries.append((hash_val, timestamp))
            except Exception as e:
                logging.warning(f"⚠️ Skipping malformed timestamp: {timestamp}")

    # Rewrite the file with only valid entries
    with open(SENT_NEWS_FILE, "w") as f:
        for h, t in all_entries:
            f.write(f"{h}|{t}\n")

    logging.info(f"🧹 Retained {len(valid_hashes)} recent hashes (<= 48h)")
    return valid_hashes

def save_sent_hashes(hashes):
    now = datetime.now(timezone.utc).isoformat()
    with open(SENT_NEWS_FILE, 'a') as f:
        for h in hashes:
            f.write(f"{h}|{now}\n")
    logging.info(f"✅ Saved {len(hashes)} new hashes to {SENT_NEWS_FILE}")


def compute_hash_from_url(url):
    return hashlib.sha256(url.encode("utf-8")).hexdigest()

# --- RSS news fetcher ---

def strip_html(text):
    return BeautifulSoup(text, "html.parser").get_text()

def fetch_crypto_news():
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=24)
    news_items = []

    logging.info("📡 Fetching crypto news...")

    for source, url in RSS_FEEDS.items():
        logging.info(f"🌐 Parsing feed from: {source}")
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

            formatted_news = f"[{title}]: {summary} ({source}, {date_str})\nLink: {link}"
            news_items.append(formatted_news)

    logging.info(f"📰 Fetched {len(news_items)} news items in the last 24h.")
    return "\n".join(news_items) if news_items else "No news found in the last 24 hours."

# --- GPT-4 summarizer ---

def summarize_crypto_news(raw_news: str, model="gpt-4"):
    logging.info("🤖 Summarizing news with GPT-4...")
    prompt = (
        "Context: I work at Sygnum, a regulated crypto bank serving corporate, institutional, "
        "and private clients with services including custody, brokerage, lending, and tokenization. "
        "I'm currently based in the Singapore office.\n\n"
        "Task: Based on the crypto news listed below, identify 0 to 3 key stories that are genuinely significant. "
        "These should relate to major regulatory developments, important company activity (such as acquisitions, partnerships, launches), "
        "or notable technology updates in the digital asset space. "
        "If none of the stories stand out as impactful, you may return nothing.\n\n"
        "Format: For each selected news item, provide:\n"
        "- A short headline-style summary (1–3 words), wrapped in asterisks to make it *bold*, followed by\n"
        "- A one to two line description\n"
        "- At the end of the line, include the source and the publication date in this format: (Cointelegraph, 06 Apr 2025)\n"
        "- On the next line, include the full URL to the article (no brackets)\n"
        "- Do not use 'Source:' or 'Date:' labels — just format exactly as shown\n"
        "- Separate each item with a blank line\n\n"
        "Example:\n"
        "*Stablecoin Guidelines Drafted*: The SEC released a new proposal for stablecoin oversight. (CoinDesk, 06 Apr 2025)\n"
        "Link: https://example.com/article\n\n"
        f"News:\n{raw_news}"
    )

    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}]
    )

    return response.choices[0].message.content

# --- GPT Output filtering based on previously sent URLs ---

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
        hash_val = compute_hash_from_url(url)
        if hash_val not in seen_hashes:
            blocks_to_send.append(block)
            new_hashes.add(hash_val)

    if new_hashes:
        save_sent_hashes(new_hashes)
    else:
        logging.info("ℹ️ No new blocks to send (all URLs were already seen).")

    return "\n\n".join(blocks_to_send)

# --- WhatsApp sender (via Twilio) ---

def send_whatsapp_message(body, to_number):
    client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    message = client.messages.create(
        from_='whatsapp:+14155238886',  # Twilio Sandbox number
        body=body,
        to=f'whatsapp:{to_number}'
    )
    logging.info(f"📤 WhatsApp message sent (SID: {message.sid})")

# --- Main execution flow ---

if __name__ == "__main__":
    logging.info("🚀 Starting Crypto News Summary Bot")

    logging.info("🔐 OpenAI key loaded: " + OPENAI_API_KEY[:8] + "...")
    news = fetch_crypto_news()
    logging.info("📄 Raw news fetched.")

    summary = summarize_crypto_news(news)
    filtered_summary = filter_unsent_blocks(summary)

    if filtered_summary:
        send_whatsapp_message(filtered_summary, WHATSAPP_TO)
        logging.info("✅ New summary sent.")
        logging.info("\n" + filtered_summary)
    else:
        logging.info("⏸ No new articles to send.")
