# MailDrop

A web tool for analyzing suspicious emails for signs of phishing or malware.

## What it does

Upload a `.eml` or `.msg` email file and MailDrop will:

- Show email header details (sender, route, SPF/DKIM/DMARC authentication)
- Plot the email's geographic route on a map, using an offline GeoLite2 database so no IP addresses ever leave your server
- Scan attachments against [VirusTotal](https://www.virustotal.com) and flag infected files
- Extract all links from the email body, unwrap security-gateway rewrites, and check them against VirusTotal
- Detect hidden tracking pixels and list all remote content the email would load
- Flag links whose visible text does not match their destination, punycode domains, and lookalikes of the sender domain
- Show a safe text-only preview of the message body
- Warn if the email looks like a phishing attempt, with the evidence explained

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
- `GEOIP_DB_PATH` — Path to the GeoLite2 City database. Optional; geolocation and the map are disabled when the file is missing. With Docker, place the file in `./data/` and the bundled compose file mounts it automatically.

### Getting the GeoLite2 database

Geolocation runs fully offline against a local MaxMind GeoLite2 database, so the IP addresses found in analyzed emails never leave your server.

1. Create a free MaxMind account at <https://www.maxmind.com/en/geolite2/signup>.
2. Sign in and go to **Download Files** under GeoIP, then download the **GeoLite2 City** database in `.mmdb` format.
3. Place the file at `./data/GeoLite2-City.mmdb` next to `docker-compose.yaml` (or set `GEOIP_DB_PATH` to wherever you keep it when running without Docker).
4. Restart the app. MaxMind updates the database twice a week, so re-download it now and then (or automate it with their `geoipupdate` tool).

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
