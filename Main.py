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
    import re
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

    # --- Tracking Sent News ---
    def load_sent_hashes():
        sheet = get_google_sheet()
        records = sheet.get_all_records()
        hashes = set(row["hash"] for row in records)
        logging.info(f"Loaded {len(hashes)} hashes from Google Sheet.")
        return hashes

    def save_sent_hashes(hashes):
        sheet = get_google_sheet()
        now = datetime.now(timezone.utc).isoformat()
        rows = [[h, now] for h in hashes]
        sheet.append_rows(rows)
        logging.info(f"Saved {len(hashes)} hashes to Google Sheet.")

    # --- Compute URL Hash ---
    def compute_hash_from_url(url):
        hash_val = hashlib.sha256(url.encode("utf-8")).hexdigest()
        return hash_val

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

        logging.info("📱 Fetching crypto news...")
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
                short_link = shorten_url(link)

                formatted_news = f"[{title}]: {summary} ({source}, {date_str})\nLink: {short_link}"
                news_items.append(formatted_news)

        logging.info(f"📰 Fetched {len(news_items)} news items in the last 24h.")
        return "\n".join(news_items) if news_items else "No news found in the last 24 hours."

    # --- Add Header to the Summary ---
    def add_crypto_update_header(summary):
        # Add the "Crypto updates" header at the beginning
        return "⚡ *Crypto updates* ⚡\n\n" + summary


    def add_bold_to_headlines(summary_text):
        lines = summary_text.strip().split("\n")
        formatted_lines = []
        i = 0

        while i < len(lines):
            line = lines[i].strip()

            # Check for a title line that contains a colon
            if ":" in line and not line.lower().startswith("link:"):
                title, rest = line.split(":", 1)
                formatted_title = f"*{title.strip()}*: {rest.strip()}"  # 👈 fixed space
                formatted_lines.append(formatted_title)

                # If next line is a link, keep it
                if i + 1 < len(lines):
                    next_line = lines[i + 1].strip()
                    if next_line.lower().startswith("link:"):
                        formatted_lines.append(next_line)
                        i += 1  # skip link line next time

                formatted_lines.append("")  # blank line
            else:
                formatted_lines.append(line)

            i += 1

        return "\n".join(formatted_lines).strip()


    # --- Summarize News with OpenAI ---
    def summarize_crypto_news(raw_news: str, model="gpt-4"):
        logging.info("🤖 Summarizing news with GPT-4...")

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
        # Remove any markdown-like characters (like '*' or '_') from the headlines
        summary_text = re.sub(r"[*_]", "", summary_text)
        summary_blocks = summary_text.strip().split("\n\n")
        results = []

        for block in summary_blocks:
            # Skip empty blocks
            if not block.strip():
                continue

            lines = block.strip().splitlines()

            # Extract any URL from the block (not necessarily starting with 'Link:')
            url_match = re.search(r'https?://\S+', block)  # Look for a URL in the block
            if url_match:
                url = url_match.group(0)
                results.append((url, block))

        return results

    def filter_unsent_blocks(summary_text):
        seen_hashes = load_sent_hashes()  # Load previously seen hashes from Google Sheets
        new_hashes = set()
        blocks_to_send = []

        for url, block in extract_links_and_blocks(summary_text):
            # Shorten the URL before hashing
            shortened_url = shorten_url(url)
            hash_val = compute_hash_from_url(shortened_url)

            # Check if this hash has already been processed
            if hash_val not in seen_hashes:
                blocks_to_send.append(block)
                new_hashes.add(hash_val)

        # Save new hashes if any
        if new_hashes:
            save_sent_hashes(new_hashes)  # Save the new hashes to Google Sheets

        return "\n\n".join(blocks_to_send)


    # --- Send WhatsApp via Twilio ---
    def send_whatsapp_message(body, to_number):
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        message = client.messages.create(
            from_='whatsapp:+14155238886',
            body=body,  # Ensure the body contains *bold* formatted text
            to=f'whatsapp:{to_number}'
        )
    # Reduce logging verbosity for third-party libraries like Twilio
    # logging.getLogger("twilio.http_client").setLevel(logging.WARNING)

    # --- Main Execution ---
    if __name__ == "__main__":

        news = fetch_crypto_news()
        print (news)
        summary = summarize_crypto_news(news)

        filtered_summary = filter_unsent_blocks(summary)
        if filtered_summary:
            # Apply bold to headlines
            summary_with_bold_headlines = add_bold_to_headlines(filtered_summary)

            # Add the "Crypto updates" header
            summary_with_header = add_crypto_update_header(summary_with_bold_headlines)

            # Send the WhatsApp message
            send_whatsapp_message(summary_with_header, WHATSAPP_TO)
            logging.info("✅ New summary sent.")

        else:
            logging.info("⏸ No new articles to send.")
