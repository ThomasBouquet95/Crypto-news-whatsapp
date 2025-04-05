from openai import OpenAI
import requests
import os
import feedparser
from dotenv import load_dotenv
from datetime import datetime, timezone
from bs4 import BeautifulSoup
from datetime import timedelta
from twilio.rest import Client
import requests
import hashlib
load_dotenv()
import re
from urllib.parse import quote

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=OPENAI_API_KEY)

RSS_FEEDS = {
    "CoinDesk": "https://www.coindesk.com/arc/outboundfeeds/rss/",
    "Cointelegraph": "https://cointelegraph.com/rss",
    "Decrypt": "https://decrypt.co/feed",
    "The Block": "https://www.theblock.co/feeds/rss",
    "Financial Times": "https://www.ft.com/?format=rss",
    "Reuters (Tech)": "https://www.reutersagency.com/feed/?best-sectors=technology",
}


def shorten_url(url):
    try:
        # Shorten the URL using TinyURL
        response = requests.get(f"https://tinyurl.com/api-create.php?url={url}")
        if response.status_code == 200:
            # Append '?' to prevent WhatsApp preview
            return response.text + "?"
        else:
            return url  # Fallback to original URL if TinyURL fails
    except Exception as e:
        print(f"Error shortening URL: {e}")
        return url  # Return original URL if there was an error

def strip_html(text):
    return BeautifulSoup(text, "html.parser").get_text()

def fetch_crypto_news():
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=24)

    news_items = []

    for source, url in RSS_FEEDS.items():
        feed = feedparser.parse(url)
        for entry in feed.entries:
            # Get published date with fallback
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
            original_link = entry.link.strip() if hasattr(entry, 'link') else ""
            short_link = shorten_url(original_link)
            news_items.append(f"[{title}]: {summary} ({source}, {date_str})\nLink: {short_link}")

    if not news_items:
        return "No news found in the last 24 hours."

    return "\n".join(news_items)


def summarize_crypto_news(raw_news: str, model="gpt-4"):
    prompt = (
        "Context: I work at Sygnum, a regulated crypto bank serving corporate, institutional, "
        "and private clients with services including custody, brokerage, lending, and tokenization. "
        "I'm currently based in the Singapore office.\n\n"
        "Task: Based on the crypto news listed below, please identify 1 to 4 key stories that are relevant to "
        "regulatory developments, company activity (e.g., acquisitions, partnerships, launches), or technology updates "
        "in the digital asset space.\n\n"
        "Format: For each selected news item, provide:\n"
        "- A short headline-style summary (2–4 words), wrapped in asterisks to make it *bold*, followed by\n"
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
        messages=[
            {"role": "user", "content": prompt}
        ]
    )

    return response.choices[0].message.content

def send_whatsapp_message(body, to_number):
    # Twilio credentials from your account
    account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")
    client = Client(account_sid, auth_token)

    message = client.messages.create(
        from_='whatsapp:+14155238886',  # Twilio Sandbox number
        body=body,
        to=f'whatsapp:{to_number}'      # Example: 'whatsapp:+6591234567'
    )

    print(f"Message sent! SID: {message.sid}")

print(f"OpenAI key loaded: {OPENAI_API_KEY[:8]}...")
news = fetch_crypto_news()
print (news)
summary = summarize_crypto_news(news)
send_whatsapp_message(summary, '+41782238841')  # Replace with your number


