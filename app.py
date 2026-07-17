import os
import re
import base64
import hashlib
import ipaddress
import time
import email
import requests
import extract_msg
import geoip2.database
import geoip2.errors
import static_analysis
from email import policy
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from io import BytesIO
from urllib.parse import urlparse, parse_qs, unquote
from dotenv import load_dotenv
from flask import Flask, request, render_template
from werkzeug.exceptions import HTTPException

load_dotenv()

app = Flask(__name__)

API_KEY = os.environ.get('API_KEY')
MAPBOX_TOKEN = os.environ.get('MAPBOX_TOKEN')
BRAND_NAME = (os.environ.get('BRAND_NAME') or '').strip()
GEOIP_DB_PATH = os.environ.get('GEOIP_DB_PATH', 'GeoLite2-City.mmdb')

app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024

ALLOWED_EXTENSIONS = {'eml', 'msg'}
REQUEST_TIMEOUT = 10
MAX_URL_LOOKUPS = 10
PREVIEW_MAX_CHARS = 20000

IPV4_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
IPV6_CANDIDATE_REGEX = re.compile(r'\b[0-9A-Fa-f]{1,4}:[0-9A-Fa-f:]+\b')
BRACKET_CONTENT_REGEX = re.compile(r'[\[(]([^\])]*)[\])]')
URL_REGEX = re.compile(r'https?://[^\s<>"\'\]]+')
URL_HOST_REGEX = re.compile(r'https?://([^/?#\s]+)')
SPF_REGEX = re.compile(r'spf=([\w]+)')
DMARC_REGEX = re.compile(r'dmarc=([\w]+)')
DOMAIN_REGEX = re.compile(r'@([A-Za-z0-9.-]+)')
CHECKPOINT_INNER_REGEX = re.compile(r'___(https?://.+?)___\.')
SUBMITTING_HOST_REGEX = re.compile(r'from\s+(.*?)\s+by\s')
RECEIVING_HOST_REGEX = re.compile(r'by\s+(.*?)\s+with\s')
HOP_TIME_REGEX = re.compile(r';\s*(.*)$')
HOP_TYPE_REGEX = re.compile(r'with\s+(.*?)(?=\s+id\s|\s+for\s|;|$)')
CSS_URL_REGEX = re.compile(r'url\(\s*["\']?(https?://[^)"\']+)', re.IGNORECASE)
TEXT_DOMAIN_REGEX = re.compile(r'(?:https?://)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)')

HEADER_FIELDS = [
    'From', 'To', 'Subject', 'Date', 'Return-Path', 'Reply-To', 'Content-Type',
    'X-Mailer', 'User-Agent', 'X-Originating-IP', 'Received-SPF',
    'Authentication-Results', 'DMARC-Filter',
]

TWO_LEVEL_SUFFIXES = {
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au',
    'co.nz', 'co.jp', 'com.br', 'com.mx', 'co.in', 'com.cn', 'com.sg',
    'com.hk', 'co.za', 'com.tr', 'com.ar',
}

COMMON_TLDS = {
    'com', 'net', 'org', 'no', 'se', 'dk', 'de', 'uk', 'io', 'co', 'gov',
    'edu', 'info', 'eu', 'app', 'dev', 'me', 'us', 'ai', 'fi', 'nl', 'fr',
    'es', 'it',
}

BLOCK_TAGS = {
    'p', 'br', 'div', 'tr', 'li', 'table', 'ul', 'ol', 'h1', 'h2', 'h3',
    'h4', 'h5', 'h6', 'blockquote', 'section', 'article', 'header', 'footer',
}

GATEWAY_SIGNATURES = [
    ('protect.checkpoint.com', 'Check Point'),
    ('checkpointcloudsec.com', 'Check Point'),
    ('cloud-sec-av.com', 'Check Point'),
    ('avanan', 'Check Point'),
    ('urldefense', 'Proofpoint'),
    ('pphosted.com', 'Proofpoint'),
    ('mimecast', 'Mimecast'),
    ('safelinks.protection.outlook.com', 'Microsoft Safe Links'),
    ('linkprotect.cudasvc.com', 'Barracuda'),
    ('messagelabs', 'Symantec Email Security'),
]

SPF_EVIDENCE = {
    'fail': (
        'SPF check failed',
        "The sender's domain publishes a list of servers that are allowed to send its email. The server that sent this message is not on that list, which suggests the sender address is forged.",
    ),
    'softfail': (
        'SPF check soft-failed',
        "The sender's domain indicates that the server that sent this message is probably not authorized to send its email, which suggests the sender address may be forged.",
    ),
}
SPF_FALLBACK = (
    'SPF could not verify the sender',
    "The sender address could not be verified against the sender domain's list of approved servers, so there is no proof this email really comes from who it claims.",
)

DKIM_EVIDENCE = {
    'fail': (
        'DKIM signature check failed',
        "The email's digital signature should prove that it came from the sender's domain and was not altered on the way. The signature does not match, which means the message may have been tampered with or the sender forged.",
    ),
    'none': (
        'No DKIM signature',
        "The email carries no digital signature, so there is no cryptographic proof that it really comes from the sender's domain.",
    ),
}
DKIM_FALLBACK = (
    'DKIM could not verify the email',
    "The email's digital signature could not be verified, so there is no proof the message is authentic and unaltered.",
)


def load_geoip_reader():
    try:
        return geoip2.database.Reader(GEOIP_DB_PATH)
    except (OSError, ValueError):
        return None


geoip_reader = load_geoip_reader()


def render_index(**context):
    return render_template('index.html', brand=BRAND_NAME, mapbox_token=MAPBOX_TOKEN, **context)


@app.errorhandler(404)
def page_not_found(error):
    return render_index(error="The page you were looking for does not exist."), 404


@app.errorhandler(413)
def file_too_large(error):
    return render_index(error="The file is too large. The maximum size is 10 MB."), 413


@app.errorhandler(Exception)
def unexpected_error(error):
    if isinstance(error, HTTPException):
        return render_index(error="Something went wrong while handling your request. Please try again."), error.code
    return render_index(error="Something went wrong on our side and we could not analyze the email. Please try again."), 500


@app.route('/')
def index():
    return render_index()


@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files.get('file')
    if file is None or not file.filename:
        return render_index(error="Please attach an .eml or .msg file.")

    extension = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
    if extension not in ALLOWED_EXTENSIONS:
        return render_index(error="This file type is not supported. Please upload an .eml or .msg file.")

    file_bytes = file.read()

    try:
        message, attachments, text_parts = load_email(extension, file_bytes)
    except Exception:
        return render_index(error="We are not able to read this email. Please try again with a valid .eml or .msg file.")

    headers, geolocations, hops, received_headers, arc_results = extract_headers(message)
    from_domain = extract_domain(headers.get('From'))
    url_results = analyze_urls(text_parts, from_domain)
    remote_content = analyze_remote_content(text_parts)
    body_preview, preview_truncated = build_body_preview(text_parts)
    results = [analyze_attachment(name, data) for name, data in attachments]
    is_infected = any(result['status'] == 'malicious' for result in results)
    static_alert = any(result['static_risk'] == 'high' for result in results)
    vt_rate_limited = (
        any(result['status'] == 'rate_limited' for result in results)
        or any(item['status'] == 'rate_limited' for item in url_results)
    )

    gateways = detect_gateways(received_headers, url_results)
    phishing_evidence, phishing_caveats = build_phishing_evidence(headers, url_results, arc_results, gateways)

    return render_index(
        analyzed=True,
        results=results,
        headers=headers,
        geolocations=geolocations,
        is_spoofed=bool(phishing_evidence),
        phishing_evidence=phishing_evidence,
        phishing_caveats=phishing_caveats,
        is_infected=is_infected,
        static_alert=static_alert,
        hops=hops,
        received_headers=received_headers,
        url_results=url_results,
        remote_content=remote_content,
        body_preview=body_preview,
        preview_truncated=preview_truncated,
        vt_rate_limited=vt_rate_limited,
    )


def load_email(extension, file_bytes):
    if extension == 'eml':
        return load_eml(file_bytes)
    return load_msg(file_bytes)


def load_eml(file_bytes):
    message = email.message_from_bytes(file_bytes, policy=policy.default)
    attachments = []
    text_parts = []
    for part in message.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        payload = part.get_payload(decode=True)
        if part.get('Content-Disposition') is not None:
            attachments.append((part.get_filename() or 'Unnamed file', payload))
        elif payload and part.get_content_type() in ('text/plain', 'text/html'):
            text_parts.append((part.get_content_type(), decode_text_payload(part, payload)))
    return message, attachments, text_parts


def load_msg(file_bytes):
    msg = extract_msg.Message(BytesIO(file_bytes))
    message = msg.header
    if message is None:
        message = email.message_from_bytes(b'')

    attachments = []
    for attachment in msg.attachments:
        name = attachment.longFilename or attachment.shortFilename or 'Unnamed file'
        attachments.append((name, attachment.data))

    text_parts = []
    if msg.body:
        text_parts.append(('text/plain', msg.body))
    html_body = getattr(msg, 'htmlBody', None)
    if html_body:
        if isinstance(html_body, bytes):
            html_body = html_body.decode('utf-8', errors='replace')
        text_parts.append(('text/html', html_body))
    return message, attachments, text_parts


def decode_text_payload(part, payload):
    charset = part.get_content_charset() or 'utf-8'
    try:
        return payload.decode(charset, errors='replace')
    except (LookupError, ValueError):
        return payload.decode('utf-8', errors='replace')


def extract_headers(message):
    headers = {}
    for field in HEADER_FIELDS:
        value = message.get(field)
        headers[field] = str(value) if value is not None else None

    received_newest_first = [str(value) for value in (message.get_all('Received') or [])]
    received_headers = list(reversed(received_newest_first))

    ip_addresses = []
    if headers['X-Originating-IP']:
        ip_addresses.extend(find_ip_candidates(headers['X-Originating-IP']))
    for header in received_headers:
        for chunk in BRACKET_CONTENT_REGEX.findall(header):
            ip_addresses.extend(find_ip_candidates(chunk))

    geolocations = get_geolocations(ip_addresses)
    hops = parse_hops(received_newest_first)
    arc_results = '; '.join(str(value) for value in (message.get_all('ARC-Authentication-Results') or []))

    return headers, geolocations, hops, received_headers, arc_results


def find_ip_candidates(text):
    candidates = IPV4_REGEX.findall(text)
    candidates.extend(IPV6_CANDIDATE_REGEX.findall(text))
    valid = []
    for candidate in candidates:
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        valid.append(candidate)
    return valid


def registrable_domain(domain):
    parts = domain.lower().split('.')
    if len(parts) < 3:
        return domain.lower()
    if '.'.join(parts[-2:]) in TWO_LEVEL_SUFFIXES:
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])


def detect_gateways(received_headers, url_results):
    text = ' '.join(received_headers).lower()
    text += ' ' + ' '.join(item['url'].lower() for item in url_results)
    return {vendor for pattern, vendor in GATEWAY_SIGNATURES if pattern in text}


def arc_original_passes(arc_results):
    if not arc_results:
        return []
    passes = []
    for check, label in (('spf', 'SPF'), ('dkim', 'DKIM'), ('dmarc', 'DMARC')):
        if re.search(rf'\b{check}=pass\b', arc_results):
            passes.append(label)
    return passes


def parse_dkim_results(authentication_results):
    results = []
    for segment in authentication_results.split(';'):
        status_match = re.search(r'dkim=(\w+)', segment)
        if not status_match:
            continue
        reason_match = re.search(r'\(([^)]*)\)', segment)
        domain_match = re.search(r'header\.d=([\w.-]+)', segment)
        results.append((
            status_match.group(1).lower(),
            reason_match.group(1) if reason_match else None,
            domain_match.group(1) if domain_match else None,
        ))
    return results


def build_phishing_evidence(headers, url_results, arc_results, gateways):
    triggers = []
    supporting = []
    authentication_results = headers.get('Authentication-Results') or ''

    spf_match = SPF_REGEX.search(authentication_results)
    if spf_match and spf_match.group(1).lower() != 'pass':
        status = spf_match.group(1).lower()
        title, explanation = SPF_EVIDENCE.get(status, SPF_FALLBACK)
        observed = f'spf={status}'
        reason_match = re.search(r'spf=\w+\s*\(([^)]*)\)', authentication_results)
        if reason_match:
            observed += f' ({reason_match.group(1)})'
        mailfrom_match = re.search(r'smtp\.mailfrom=([^;\s]+)', authentication_results)
        if mailfrom_match:
            observed += f', envelope sender {mailfrom_match.group(1)}'
        triggers.append({'title': title, 'observed': observed, 'explanation': explanation})

    dkim_results = parse_dkim_results(authentication_results)
    if dkim_results and not any(status == 'pass' for status, reason, domain in dkim_results):
        parts = []
        for status, reason, domain in dkim_results:
            part = f'dkim={status}'
            if reason:
                part += f' ({reason})'
            if domain:
                part += f' for {domain}'
            parts.append(part)
        title, explanation = DKIM_EVIDENCE.get(dkim_results[0][0], DKIM_FALLBACK)
        triggers.append({'title': title, 'observed': '; '.join(parts), 'explanation': explanation})

    dmarc_match = DMARC_REGEX.search(authentication_results)
    if dmarc_match and dmarc_match.group(1).lower() == 'fail':
        observed = 'dmarc=fail'
        action_match = re.search(r'\baction=(\w+)', authentication_results)
        if action_match:
            observed += f' action={action_match.group(1)}'
        from_match = re.search(r'header\.from=([\w.-]+)', authentication_results)
        if from_match:
            observed += f' header.from={from_match.group(1)}'
        explanation = "The owner of the sender's domain publishes a policy for spotting mail that pretends to come from it. This message failed that check, meaning the domain owner does not recognize it as legitimate."
        if action_match and action_match.group(1).lower() == 'oreject':
            explanation += ' The receiving mail server decided to deliver it anyway despite the failed check.'
        triggers.append({'title': 'DMARC policy check failed', 'observed': observed, 'explanation': explanation})

    malicious_urls = [item['destination'] or item['url'] for item in url_results if item['status'] == 'malicious']
    if malicious_urls:
        observed = ', '.join(malicious_urls[:3])
        if len(malicious_urls) > 3:
            observed += f' and {len(malicious_urls) - 3} more'
        triggers.append({
            'title': 'Contains links flagged as malicious',
            'observed': observed,
            'explanation': 'One or more links in this email are flagged as malicious by security vendors on VirusTotal. Phishing emails use such links to steal passwords or install malware. Do not click any links in this email.',
        })

    lookalike_details = [flag['detail'] for item in url_results for flag in item['flags'] if flag['type'] == 'lookalike']
    if lookalike_details:
        triggers.append({
            'title': "Contains a link imitating the sender's domain",
            'observed': lookalike_details[0],
            'explanation': 'A link in this email points to a domain that looks almost identical to the sender domain. Attackers register such lookalike domains to make fake pages appear legitimate. Do not click links in this email.',
        })

    from_domain = extract_domain(headers.get('From'))
    return_path_domain = extract_domain(headers.get('Return-Path'))
    reply_to_domain = extract_domain(headers.get('Reply-To'))

    if from_domain and return_path_domain and registrable_domain(from_domain) != registrable_domain(return_path_domain):
        supporting.append({
            'title': 'Return address does not match the sender',
            'observed': f'From domain is "{from_domain}" but bounces go to "{return_path_domain}"',
            'explanation': 'Undeliverable copies of this email go to a different domain than the visible sender. Legitimate newsletters sometimes do this, but phishers also use it to hide who really sent the message.',
        })

    if from_domain and reply_to_domain and registrable_domain(from_domain) != registrable_domain(reply_to_domain):
        supporting.append({
            'title': 'Replies go to a different address than the sender',
            'observed': f'From domain is "{from_domain}" but replies go to "{reply_to_domain}"',
            'explanation': 'Answering this email would send your reply to a different domain than the visible sender - a common trick to redirect responses to an attacker.',
        })

    mismatch_details = [flag['detail'] for item in url_results for flag in item['flags'] if flag['type'] == 'mismatch']
    if mismatch_details:
        supporting.append({
            'title': 'Link text does not match its destination',
            'observed': '; '.join(mismatch_details[:2]),
            'explanation': 'The visible text of a link shows a different address than where the link really goes. Newsletters use click-tracking links that look like this, but it is also a common trick to make a malicious link look trustworthy.',
        })

    punycode_details = [flag['detail'] for item in url_results for flag in item['flags'] if flag['type'] == 'punycode']
    if punycode_details:
        supporting.append({
            'title': 'Contains internationalized (punycode) link domains',
            'observed': punycode_details[0],
            'explanation': 'Internationalized domains are legitimate, but attackers also use them to build addresses that look nearly identical to well-known domains.',
        })

    suspicious_count = sum(1 for item in url_results if item['status'] == 'suspicious')
    if suspicious_count:
        suffix = 's' if suspicious_count != 1 else ''
        supporting.append({
            'title': 'Contains links flagged as suspicious',
            'observed': f'{suspicious_count} link{suffix} flagged as suspicious on VirusTotal',
            'explanation': 'Some links in this email look suspicious to security vendors. Be careful before clicking anything in this email.',
        })

    if not triggers:
        return [], []

    caveats = []
    if gateways:
        names = ' and '.join(sorted(gateways))
        caveats.append({
            'title': 'These warnings may have an innocent explanation.',
            'explanation': f'This email passed through {names}, an email security gateway used by your organization. Such gateways rewrite links and can modify the message on the way, which breaks SPF, DKIM and DMARC checks even for legitimate email. The warnings above are therefore not proof of phishing on their own. To be safe, do not click the links in the email - open the website or service directly instead.',
        })

    original_passes = arc_original_passes(arc_results)
    if original_passes:
        checks = ', '.join(original_passes)
        caveats.append({
            'title': 'Authentication originally passed earlier in the delivery.',
            'explanation': f'A previous mail server recorded passing {checks} checks (from the ARC headers) before the message was modified in transit. This supports the possibility that the email is legitimate but was altered by a security gateway or forwarding service after it was sent.',
        })

    return triggers + supporting, caveats


def extract_domain(address):
    if not address:
        return None
    match = DOMAIN_REGEX.search(address)
    return match.group(1).lower().rstrip('.') if match else None


def parse_hops(received_newest_first):
    hops = []
    previous_time = None
    for index, header in enumerate(reversed(received_newest_first), start=1):
        header_text = ' '.join(header.split())
        hop_time = parse_received_time(header_text)

        delay = None
        if hop_time is not None and previous_time is not None:
            try:
                delay = round((hop_time - previous_time).total_seconds(), 1)
            except TypeError:
                delay = None
        if hop_time is not None:
            previous_time = hop_time

        hops.append({
            'index': index,
            'submitting_host': first_match(SUBMITTING_HOST_REGEX, header_text),
            'receiving_host': first_match(RECEIVING_HOST_REGEX, header_text),
            'time': hop_time.strftime('%d/%m/%Y %H:%M:%S') if hop_time else None,
            'delay': delay,
            'type': first_match(HOP_TYPE_REGEX, header_text),
        })
    return hops


def first_match(pattern, text):
    match = pattern.search(text)
    if not match:
        return None
    value = match.group(1).strip()
    return value or None


def parse_received_time(header_text):
    match = HOP_TIME_REGEX.search(header_text)
    if not match:
        return None
    try:
        return parsedate_to_datetime(match.group(1))
    except (TypeError, ValueError, IndexError):
        return None


def get_geolocations(ip_addresses):
    if geoip_reader is None:
        return []
    geolocations = []
    seen = set()
    for ip_address in ip_addresses:
        if ip_address in seen:
            continue
        seen.add(ip_address)

        try:
            if not ipaddress.ip_address(ip_address).is_global:
                continue
        except ValueError:
            continue

        try:
            record = geoip_reader.city(ip_address)
        except (geoip2.errors.AddressNotFoundError, ValueError):
            continue

        latitude = record.location.latitude
        longitude = record.location.longitude
        if latitude is None or longitude is None:
            continue

        geolocations.append({
            'ip_address': ip_address,
            'latitude': float(latitude),
            'longitude': float(longitude),
            'city': record.city.name,
            'country': record.country.name,
        })
    return geolocations


def analyze_attachment(name, data):
    result = {
        'name': name,
        'status': 'error',
        'sha256': None,
        'malicious_count': 0,
        'total_engines': None,
        'yara_rule': None,
        'first_seen': None,
        'last_seen': None,
        'static_findings': [],
        'static_risk': None,
        'type_label': None,
    }
    if not isinstance(data, bytes) or not data:
        return result

    static = static_analysis.analyze_file(name, data)
    result['static_findings'] = static['findings']
    result['static_risk'] = static['risk']
    result['type_label'] = static['type_label']

    result['sha256'] = hashlib.sha256(data).hexdigest()
    report = virustotal_request(f"https://www.virustotal.com/api/v3/files/{result['sha256']}")
    if report is None:
        return result
    if report.get('error') == 'rate_limited':
        result['status'] = 'rate_limited'
        return result
    if 'error' in report:
        result['status'] = 'unknown'
        return result

    stats = dig(report, 'data', 'attributes', 'last_analysis_stats') or {}
    malicious_count = stats.get('malicious') or 0
    result['malicious_count'] = malicious_count
    result['total_engines'] = sum(value for value in stats.values() if isinstance(value, int)) or None
    result['status'] = 'malicious' if malicious_count > 0 else 'clean'

    yara_results = dig(report, 'data', 'attributes', 'crowdsourced_yara_results') or []
    if yara_results and isinstance(yara_results[0], dict):
        result['yara_rule'] = yara_results[0].get('rule_name')

    attributes = dig(report, 'data', 'attributes') or {}
    result['first_seen'] = format_timestamp(attributes.get('first_submission_date') or attributes.get('creation_date'))
    result['last_seen'] = format_timestamp(attributes.get('last_analysis_date') or attributes.get('last_modification_date'))
    return result


def unwrap_url(url):
    host = extract_host(url) or ''

    if 'protect.checkpoint.com' in host or 'checkpointcloudsec.com' in host:
        inner_match = CHECKPOINT_INNER_REGEX.search(url)
        if inner_match:
            inner_url = inner_match.group(1).replace('&fru;', '&').replace('&amp;', '&')
            return 'Check Point', inner_url, extract_host(inner_url)
        return 'Check Point', url, None

    if 'safelinks.protection.outlook.com' in host:
        target = (parse_qs(urlparse(url).query).get('url') or [None])[0]
        if target:
            return 'Microsoft Safe Links', target, extract_host(target)
        return 'Microsoft Safe Links', url, None

    if 'urldefense' in host:
        v3_match = re.search(r'/v3/__(.+?)__;', url)
        if v3_match:
            inner_url = v3_match.group(1)
            return 'Proofpoint', inner_url, extract_host(inner_url)
        target = (parse_qs(urlparse(url).query).get('u') or [None])[0]
        if target:
            inner_url = unquote(target.replace('-', '%').replace('_', '/'))
            return 'Proofpoint', inner_url, extract_host(inner_url)
        return 'Proofpoint', url, None

    if 'mimecast.com' in host:
        return 'Mimecast', url, None
    if 'linkprotect.cudasvc.com' in host:
        return 'Barracuda', url, None

    return None, url, None


def extract_host(url):
    match = URL_HOST_REGEX.match(url)
    return match.group(1).lower() if match else None


def levenshtein(a, b):
    if abs(len(a) - len(b)) > 1:
        return 2
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i]
        for j, char_b in enumerate(b, start=1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (char_a != char_b)))
        previous = current
    return previous[-1]


def decode_punycode(host):
    try:
        return host.encode('ascii').decode('idna')
    except (UnicodeError, ValueError):
        return None


def is_lookalike_domain(link_host, from_domain):
    link_registrable = registrable_domain(link_host)
    from_registrable = registrable_domain(from_domain)
    if link_registrable == from_registrable:
        return False
    link_label = link_registrable.split('.')[0]
    from_label = from_registrable.split('.')[0]
    if link_label == from_label:
        return False
    return len(from_label) >= 5 and levenshtein(link_label, from_label) == 1


def link_flags(item, from_domain):
    flags = []
    effective_host = item['destination'] or extract_host(item['url'])
    if not effective_host:
        return flags

    text = (item.get('text') or '').lower().strip()
    if text:
        text_match = TEXT_DOMAIN_REGEX.search(text)
        if text_match:
            text_domain = text_match.group(1)
            tld = text_domain.rsplit('.', 1)[-1]
            looks_like_address = '://' in text or 'www.' in text or tld in COMMON_TLDS
            if looks_like_address and registrable_domain(text_domain) != registrable_domain(effective_host):
                flags.append({
                    'type': 'mismatch',
                    'label': 'Link text mismatch',
                    'detail': f'The link text shows "{text_domain}" but the link goes to "{effective_host}"',
                })

    if 'xn--' in effective_host:
        decoded = decode_punycode(effective_host)
        detail = f'"{effective_host}"'
        if decoded and decoded != effective_host:
            detail += f' displays as "{decoded}"'
        flags.append({
            'type': 'punycode',
            'label': 'Punycode domain',
            'detail': f'The destination {detail} uses internationalized characters that can imitate other domains',
        })

    if from_domain and is_lookalike_domain(effective_host, from_domain):
        flags.append({
            'type': 'lookalike',
            'label': 'Lookalike domain',
            'detail': f'The link domain "{registrable_domain(effective_host)}" closely resembles the sender domain "{registrable_domain(from_domain)}"',
        })

    return flags


def analyze_urls(text_parts, from_domain):
    items = []
    seen = set()
    for link in extract_links(text_parts):
        vendor, inner_url, destination = unwrap_url(link['url'])
        key = inner_url.replace('&amp;', '&')
        if key in seen:
            continue
        seen.add(key)
        item = {
            'url': link['url'],
            'text': link['text'],
            'vendor': vendor,
            'destination': destination,
            'status': 'unknown',
            'detections': 0,
        }
        item['flags'] = link_flags(item, from_domain)
        items.append(item)

    for position, item in enumerate(items):
        if position >= MAX_URL_LOOKUPS:
            break
        if item['vendor'] and item['destination']:
            report = virustotal_request(f"https://www.virustotal.com/api/v3/domains/{item['destination']}")
            malicious_threshold = 3
        else:
            report = lookup_url_virustotal(item['url'])
            malicious_threshold = 1

        if isinstance(report, dict) and report.get('error') == 'rate_limited':
            item['status'] = 'rate_limited'
            continue

        stats = dig(report, 'data', 'attributes', 'last_analysis_stats') or {}
        malicious = stats.get('malicious') or 0
        suspicious = stats.get('suspicious') or 0
        if malicious >= malicious_threshold:
            item['status'], item['detections'] = 'malicious', malicious
        elif malicious > 0 or suspicious > 0:
            item['status'], item['detections'] = 'suspicious', malicious + suspicious
        elif report is not None and 'error' not in report:
            item['status'] = 'clean'
    return items


class LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self._current = None

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            for attribute, value in attrs:
                if attribute == 'href' and value:
                    self._current = {'href': value, 'text': []}
                    break

    def handle_endtag(self, tag):
        if tag == 'a' and self._current is not None:
            self.links.append({'href': self._current['href'], 'text': ''.join(self._current['text']).strip()})
            self._current = None

    def handle_data(self, data):
        if self._current is not None:
            self._current['text'].append(data)


class RemoteContentExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.resources = []
        self._in_style = False

    def handle_starttag(self, tag, attrs):
        attrs_dict = {}
        for name, value in attrs:
            if name not in attrs_dict:
                attrs_dict[name] = value or ''
        if tag == 'style':
            self._in_style = True
        for attribute in ('src', 'href', 'poster', 'background', 'data'):
            value = attrs_dict.get(attribute) or ''
            if value.lower().startswith(('http://', 'https://')):
                if tag == 'a' and attribute == 'href':
                    continue
                self.resources.append({'tag': tag, 'url': value, 'attrs': attrs_dict})
        for match in CSS_URL_REGEX.finditer(attrs_dict.get('style') or ''):
            self.resources.append({'tag': tag, 'url': match.group(1), 'attrs': attrs_dict})

    def handle_endtag(self, tag):
        if tag == 'style':
            self._in_style = False

    def handle_data(self, data):
        if self._in_style:
            for match in CSS_URL_REGEX.finditer(data):
                self.resources.append({'tag': 'style', 'url': match.group(1), 'attrs': {}})


class TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.chunks = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style', 'head', 'title'):
            self._skip += 1
        elif tag in BLOCK_TAGS:
            self.chunks.append('\n')

    def handle_endtag(self, tag):
        if tag in ('script', 'style', 'head', 'title') and self._skip > 0:
            self._skip -= 1

    def handle_data(self, data):
        if self._skip == 0:
            self.chunks.append(data)


def extract_links(text_parts):
    seen = set()
    links = []
    for content_type, text in text_parts:
        if content_type == 'text/html':
            extractor = LinkExtractor()
            try:
                extractor.feed(text)
            except Exception:
                continue
            found = [(link['href'], link['text']) for link in extractor.links if link['href'].startswith('http')]
        else:
            found = [(url, None) for url in URL_REGEX.findall(text)]

        for url, text_value in found:
            url = url.rstrip('.,;)')
            if url and url not in seen:
                seen.add(url)
                links.append({'url': url, 'text': text_value})
    return links


def parse_dimension(value):
    if value is None:
        return None
    value = str(value).strip().lower().removesuffix('px')
    try:
        return int(float(value))
    except ValueError:
        return None


def is_tracking_pixel(resource):
    if resource['tag'] != 'img':
        return False
    attrs = resource['attrs']
    width = parse_dimension(attrs.get('width'))
    height = parse_dimension(attrs.get('height'))
    if width is not None and height is not None and width <= 2 and height <= 2:
        return True
    style = (attrs.get('style') or '').lower().replace(' ', '')
    if 'display:none' in style or 'visibility:hidden' in style:
        return True
    if re.search(r'(width|height):[0-2]px', style):
        return True
    return False


def analyze_remote_content(text_parts):
    resources = []
    seen = set()
    for content_type, text in text_parts:
        if content_type != 'text/html':
            continue
        extractor = RemoteContentExtractor()
        try:
            extractor.feed(text)
        except Exception:
            continue
        for resource in extractor.resources:
            url = resource['url'].rstrip('.,;)')
            if not url or url in seen:
                continue
            seen.add(url)
            resources.append({
                'url': url,
                'host': extract_host(url),
                'tag': resource['tag'],
                'tracker': is_tracking_pixel(resource),
            })

    resources.sort(key=lambda resource: not resource['tracker'])
    hosts = {resource['host'] for resource in resources if resource['host']}
    return {
        'resources': resources[:100],
        'total': len(resources),
        'trackers': sum(1 for resource in resources if resource['tracker']),
        'host_count': len(hosts),
    }


def build_body_preview(text_parts):
    text = None
    for content_type, part_text in text_parts:
        if content_type == 'text/plain' and part_text.strip():
            text = part_text
            break
    if text is None:
        for content_type, part_text in text_parts:
            if content_type != 'text/html':
                continue
            extractor = TextExtractor()
            try:
                extractor.feed(part_text)
            except Exception:
                continue
            candidate = ''.join(extractor.chunks)
            if candidate.strip():
                text = candidate
                break
    if text is None:
        return None, False

    text = re.sub(r'[ \t]+\n', '\n', text)
    text = re.sub(r'\n{3,}', '\n\n', text).strip()
    truncated = len(text) > PREVIEW_MAX_CHARS
    return text[:PREVIEW_MAX_CHARS], truncated


def lookup_url_virustotal(url):
    url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b'=').decode()
    return virustotal_request(f'https://www.virustotal.com/api/v3/urls/{url_id}')


def virustotal_request(url):
    if not API_KEY:
        return None
    try:
        response = requests.get(
            url,
            headers={'accept': 'application/json', 'x-apikey': API_KEY},
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException:
        return None

    if response.status_code == 429:
        return {'error': 'rate_limited'}
    if response.status_code == 404:
        return {'error': 'not_found'}
    if response.status_code != 200:
        return None

    try:
        data = response.json()
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def dig(value, *keys):
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def format_timestamp(timestamp):
    try:
        return time.strftime('%d/%m/%Y', time.localtime(int(timestamp)))
    except (TypeError, ValueError, OverflowError, OSError):
        return None


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
