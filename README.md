# MailDrop

A web tool for analyzing suspicious emails for signs of phishing or malware.

## What it does

Upload a `.eml` or `.msg` email file and MailDrop will:

- Show email header details (sender, route, SPF/DKIM authentication)
- Plot the email's geographic route on a map
- Scan attachments against [VirusTotal](https://www.virustotal.com) and flag infected files
- Extract all links from the email body and check them against VirusTotal
- Warn if the email looks like a phishing attempt

Uploaded files are processed entirely in memory and are never stored.

## Running it

**With Docker (recommended):**

```bash
cp .env.example .env   # add your API keys
docker compose up
```

Then open `http://localhost`.

**Without Docker:**

```bash
pip install -r requirements.txt
python app.py
```

## Configuration

Create a `.env` file with:

```
API_KEY=your_virustotal_api_key
MAPBOX_TOKEN=your_mapbox_token
BRAND_NAME=Your Organization
```

- `API_KEY` — VirusTotal API key. Required for attachment and link scanning; without it, attachments show as "Not checked".
- `MAPBOX_TOKEN` — Mapbox access token. Optional; the map is hidden when unset.
- `BRAND_NAME` — Optional organization name shown in the page title and header next to "MailDrop".

### Getting a VirusTotal API key

1. Create a free account at <https://www.virustotal.com/gui/join-us>.
2. Sign in, open your profile menu in the top right corner and choose **API key**.
3. Copy the key into `API_KEY` in your `.env` file.

The free tier allows 4 lookups per minute and 500 per day. MailDrop uses one lookup per attachment and up to 10 link lookups per analyzed email, so a busy instance may need a paid tier.

### Getting a Mapbox token

1. Create a free account at <https://account.mapbox.com/auth/signup/>.
2. Go to <https://account.mapbox.com/access-tokens/> and use the **Default public token**, or create a dedicated token for MailDrop.
3. Add a URL restriction on the token so it only works from your site's domain. Public tokens are visible to everyone who visits the page, and the restriction prevents anyone else from using yours.
4. Copy the token into `MAPBOX_TOKEN` in your `.env` file.
