import re
import math
import zlib
import zipfile
from io import BytesIO
from collections import Counter

try:
    from oletools.olevba import VBA_Parser
    OLEVBA_AVAILABLE = True
except Exception:
    OLEVBA_AVAILABLE = False

SEVERITY_ORDER = {'high': 0, 'medium': 1, 'low': 2, 'info': 3}

INSPECTORS = []

ZIP_BOMB_SIZE = 100 * 1024 * 1024
ZIP_BOMB_RATIO = 100
ENTROPY_THRESHOLD = 7.2

MAGIC_SIGNATURES = [
    (0, b'MZ', 'exe', 'executable', 'Windows executable (PE)'),
    (0, b'\x7fELF', 'elf', 'executable', 'Linux/Unix executable (ELF)'),
    (0, b'\xca\xfe\xba\xbe', 'macho', 'executable', 'macOS executable (Mach-O)'),
    (0, b'\xcf\xfa\xed\xfe', 'macho', 'executable', 'macOS executable (Mach-O)'),
    (0, b'\xfe\xed\xfa\xce', 'macho', 'executable', 'macOS executable (Mach-O)'),
    (0, b'L\x00\x00\x00\x01\x14\x02\x00', 'lnk', 'executable', 'Windows shortcut (LNK)'),
    (0, b'ITSF', 'chm', 'executable', 'Compiled HTML Help (CHM)'),
    (0, b'#!', 'shebang', 'script', 'Script with an interpreter line'),
    (0, b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'ole', 'office-legacy', 'Legacy Office or OLE compound file'),
    (0, b'PK\x03\x04', 'zip', 'archive', 'ZIP archive'),
    (0, b'PK\x05\x06', 'zip', 'archive', 'ZIP archive'),
    (0, b'Rar!\x1a\x07', 'rar', 'archive', 'RAR archive'),
    (0, b'7z\xbc\xaf\x27\x1c', '7z', 'archive', '7-Zip archive'),
    (0, b'\x1f\x8b', 'gzip', 'archive', 'GZIP archive'),
    (0, b'BZh', 'bzip2', 'archive', 'BZIP2 archive'),
    (0, b'\xfd7zXZ\x00', 'xz', 'archive', 'XZ archive'),
    (0, b'MSCF', 'cab', 'archive', 'Microsoft Cabinet archive'),
    (0, b'%PDF-', 'pdf', 'document', 'PDF document'),
    (0, b'{\\rtf', 'rtf', 'document', 'Rich Text Format document'),
    (0, b'%!PS', 'ps', 'document', 'PostScript document'),
    (0, b'\xff\xd8\xff', 'jpeg', 'image', 'JPEG image'),
    (0, b'\x89PNG\r\n\x1a\n', 'png', 'image', 'PNG image'),
    (0, b'GIF87a', 'gif', 'image', 'GIF image'),
    (0, b'GIF89a', 'gif', 'image', 'GIF image'),
    (0, b'BM', 'bmp', 'image', 'Bitmap image'),
    (0, b'II*\x00', 'tiff', 'image', 'TIFF image'),
    (0, b'MM\x00*', 'tiff', 'image', 'TIFF image'),
]

EXTENSION_TYPES = {
    'exe': 'executable', 'dll': 'executable', 'scr': 'executable', 'com': 'executable',
    'pif': 'executable', 'cpl': 'executable', 'sys': 'executable', 'msi': 'executable',
    'msix': 'executable', 'jar': 'executable', 'apk': 'executable',
    'bat': 'script', 'cmd': 'script', 'ps1': 'script', 'psm1': 'script', 'vbs': 'script',
    'vbe': 'script', 'js': 'script', 'jse': 'script', 'wsf': 'script', 'wsh': 'script',
    'hta': 'script', 'sh': 'script',
    'pdf': 'document', 'rtf': 'document', 'ps': 'document',
    'doc': 'office-legacy', 'xls': 'office-legacy', 'ppt': 'office-legacy',
    'docx': 'ooxml', 'xlsx': 'ooxml', 'pptx': 'ooxml',
    'docm': 'ooxml', 'xlsm': 'ooxml', 'pptm': 'ooxml',
    'jpg': 'image', 'jpeg': 'image', 'png': 'image', 'gif': 'image', 'bmp': 'image',
    'webp': 'image', 'tiff': 'image', 'tif': 'image',
    'txt': 'text', 'csv': 'text', 'log': 'text', 'htm': 'text', 'html': 'text',
    'zip': 'archive', 'rar': 'archive', '7z': 'archive', 'gz': 'archive', 'tar': 'archive',
    'bz2': 'archive', 'xz': 'archive', 'cab': 'archive', 'iso': 'archive',
}

DANGEROUS_EXTENSIONS = {
    'exe': 'Windows program', 'com': 'DOS/Windows program', 'scr': 'Windows screensaver (executable)',
    'pif': 'Windows program shortcut', 'cpl': 'Windows control panel applet', 'sys': 'Windows system driver',
    'msi': 'Windows installer', 'msix': 'Windows installer', 'msp': 'Windows installer patch',
    'bat': 'Batch script', 'cmd': 'Batch script', 'ps1': 'PowerShell script', 'psm1': 'PowerShell module',
    'vbs': 'VBScript', 'vbe': 'Encoded VBScript', 'js': 'Windows Script Host JavaScript',
    'jse': 'Encoded JScript', 'wsf': 'Windows Script File', 'wsh': 'Windows Script Host settings',
    'hta': 'HTML Application', 'jar': 'Java application', 'lnk': 'Windows shortcut',
    'reg': 'Windows registry file', 'inf': 'Setup information file', 'scf': 'Windows Explorer command',
    'msc': 'Management console file', 'gadget': 'Windows desktop gadget', 'application': 'ClickOnce application',
    'iso': 'Disk image (bypasses download protection)', 'img': 'Disk image', 'vhd': 'Virtual hard disk',
    'vhdx': 'Virtual hard disk', 'cab': 'Windows cabinet archive', 'chm': 'Compiled HTML Help',
    'apk': 'Android application', 'dll': 'Windows library',
}

ARCHIVE_EXTENSIONS = {'zip', 'rar', '7z', 'gz', 'tar', 'bz2', 'xz', 'cab', 'iso'}
HTML_EXTENSIONS = {'htm', 'html', 'shtml', 'xhtml', 'svg'}
SCRIPT_LIKE_EXTENSIONS = {'js', 'jse', 'vbs', 'vbe', 'ps1', 'bat', 'cmd', 'hta', 'wsf', 'sh', 'htm', 'html'}
DOUBLE_EXTENSION_LURES = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'jpg', 'jpeg', 'png', 'txt', 'zip'}
BIDI_CONTROLS = ['‪', '‫', '‬', '‭', '‮', '⁦', '⁧', '⁨', '⁩', '‎', '‏']
SAFE_EXPECTED = {'document', 'image', 'text'}

PDF_STREAM_REGEX = re.compile(rb'stream\r?\n(.*?)\r?\n?endstream', re.DOTALL)
RELATIONSHIP_REGEX = re.compile(r'<Relationship\b[^>]*?/?>', re.IGNORECASE)
TARGET_ATTR_REGEX = re.compile(r'Target="([^"]*)"', re.IGNORECASE)
URL_IN_TEXT_REGEX = re.compile(r'https?://[^\s<>"\')]+')
LONG_BASE64_REGEX = re.compile(r'[A-Za-z0-9+/]{2000,}={0,2}')


def register(func):
    INSPECTORS.append(func)
    return func


def finding(severity, category, title, observed, explanation):
    return {
        'severity': severity,
        'category': category,
        'title': title,
        'observed': observed,
        'explanation': explanation,
    }


def strip_bidi_controls(name):
    for control in BIDI_CONTROLS:
        name = name.replace(control, '')
    return name


def looks_like_text(data):
    sample = data[:1024]
    if not sample or b'\x00' in sample:
        return False
    printable = sum(1 for byte in sample if byte in (9, 10, 13) or 32 <= byte <= 126 or byte >= 128)
    return printable / len(sample) > 0.90


def refine_zip(data):
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            names = archive.namelist()
    except (zipfile.BadZipFile, OSError):
        return {'type': 'zip', 'category': 'archive', 'label': 'ZIP archive'}

    name_set = set(names)
    is_office = '[Content_Types].xml' in name_set or any(
        name.startswith(('word/', 'xl/', 'ppt/')) for name in names
    )
    if is_office:
        if any(name.startswith('word/') for name in names):
            label = 'Word document (OOXML)'
        elif any(name.startswith('xl/') for name in names):
            label = 'Excel workbook (OOXML)'
        elif any(name.startswith('ppt/') for name in names):
            label = 'PowerPoint presentation (OOXML)'
        else:
            label = 'Office document (OOXML)'
        return {'type': 'ooxml', 'category': 'ooxml', 'label': label}
    if 'AndroidManifest.xml' in name_set:
        return {'type': 'apk', 'category': 'executable', 'label': 'Android package (APK)'}
    if any(name.endswith('.class') for name in names):
        return {'type': 'jar', 'category': 'executable', 'label': 'Java archive (JAR)'}
    return {'type': 'zip', 'category': 'archive', 'label': 'ZIP archive'}


def detect_file_type(data):
    if len(data) > 0x8006 and data[0x8001:0x8006] == b'CD001':
        return {'type': 'iso', 'category': 'archive', 'label': 'ISO disk image'}
    for offset, signature, type_id, category, label in MAGIC_SIGNATURES:
        if data[offset:offset + len(signature)] == signature:
            if type_id == 'zip':
                return refine_zip(data)
            return {'type': type_id, 'category': category, 'label': label}
    if looks_like_text(data):
        return {'type': 'text', 'category': 'text', 'label': 'Plain text'}
    return {'type': 'unknown', 'category': 'unknown', 'label': 'Unknown or unrecognized format'}


class FileContext:
    def __init__(self, name, data):
        self.name = name or ''
        self.data = data if isinstance(data, bytes) else b''
        self.display_name = strip_bidi_controls(self.name)
        self.extension = self.display_name.rsplit('.', 1)[-1].lower() if '.' in self.display_name else ''
        self.detected = detect_file_type(self.data)


def categories_conflict(expected, detected):
    if expected == detected:
        return False
    if detected in {'executable', 'script'} and expected in SAFE_EXPECTED:
        return True
    if expected == 'image' and detected in {'archive', 'ooxml', 'office-legacy'}:
        return True
    if expected == 'document' and detected in {'archive', 'executable', 'script'}:
        return True
    if expected == 'text' and detected in {'executable', 'archive', 'ooxml', 'office-legacy'}:
        return True
    return False


@register
def inspect_type_mismatch(ctx):
    if not ctx.extension or ctx.detected['type'] == 'unknown':
        return []
    expected = EXTENSION_TYPES.get(ctx.extension)
    if expected is None:
        return []
    if categories_conflict(expected, ctx.detected['category']):
        return [finding(
            'high', 'type-mismatch',
            'File contents do not match the extension',
            f'Named ".{ctx.extension}" but the contents are {ctx.detected["label"]}',
            'The real file type does not match the extension in the name. Attackers disguise executables and other dangerous files as documents or images so they look safe to open.',
        )]
    return []


@register
def inspect_dangerous_type(ctx):
    reason = DANGEROUS_EXTENSIONS.get(ctx.extension)
    if reason:
        return [finding(
            'high', 'dangerous-type',
            'Dangerous file type',
            f'.{ctx.extension} - {reason}',
            'This type of file can run commands on your computer as soon as it is opened. Do not open it unless you are certain it is safe.',
        )]
    if ctx.detected['category'] in {'executable', 'script'}:
        return [finding(
            'high', 'dangerous-type',
            'Attachment is an executable program',
            ctx.detected['label'],
            'This attachment is an executable program or script regardless of its name, which can run commands on your computer.',
        )]
    return []


@register
def inspect_filename_tricks(ctx):
    findings = []
    if any(control in ctx.name for control in BIDI_CONTROLS):
        findings.append(finding(
            'high', 'filename-trick',
            'Filename uses hidden text-direction characters',
            f'Real filename displays as "{ctx.display_name}"',
            'The filename contains hidden characters that reverse how part of the name reads. This is used to hide a dangerous extension, for example making an executable appear to end in ".jpg".',
        ))
    parts = ctx.display_name.lower().split('.')
    if len(parts) >= 3:
        inner, final = parts[-2], parts[-1]
        if inner in DOUBLE_EXTENSION_LURES and final not in DANGEROUS_EXTENSIONS:
            findings.append(finding(
                'medium', 'filename-trick',
                'File has a double extension',
                f'"{ctx.display_name}" appears to be a .{inner} but really ends in .{final}',
                'The filename carries two extensions so it looks like a harmless document while its real type is the final extension.',
            ))
    return findings


@register
def inspect_office_macros(ctx):
    if ctx.detected['category'] not in {'office-legacy', 'ooxml'} or not OLEVBA_AVAILABLE:
        return []
    findings = []
    parser = None
    try:
        parser = VBA_Parser(filename=ctx.display_name or 'attachment', data=ctx.data)
        if parser.detect_vba_macros():
            results = parser.analyze_macros(show_decoded_strings=False) or []
            autoexec = [keyword for kind, keyword, _ in results if kind == 'AutoExec']
            suspicious = [keyword for kind, keyword, _ in results if kind == 'Suspicious']
            if autoexec:
                findings.append(finding(
                    'high', 'office-macro',
                    'Document contains an auto-running macro',
                    '; '.join(dict.fromkeys(autoexec))[:200],
                    'This document runs macro code automatically the moment it is opened. Malicious documents use auto-run macros to install malware without any further action from you.',
                ))
            else:
                findings.append(finding(
                    'medium', 'office-macro',
                    'Document contains macros',
                    'VBA macro code present',
                    'This document contains macro code. Macros can run commands on your computer and are a common way to deliver malware.',
                ))
            if suspicious:
                findings.append(finding(
                    'medium', 'office-macro',
                    'Macros use suspicious commands',
                    '; '.join(dict.fromkeys(suspicious))[:200],
                    'The macro code uses commands often seen in malware, such as running programs, downloading files or hiding what it does.',
                ))
    except Exception:
        return findings
    finally:
        if parser is not None:
            try:
                parser.close()
            except Exception:
                pass
    return findings


@register
def inspect_office_structure(ctx):
    if ctx.detected['category'] != 'ooxml':
        return []
    findings = []
    try:
        with zipfile.ZipFile(BytesIO(ctx.data)) as archive:
            names = archive.namelist()
            for rels_name in [name for name in names if name.endswith('.rels')]:
                try:
                    content = archive.read(rels_name).decode('utf-8', 'replace')
                except (OSError, zipfile.BadZipFile):
                    continue
                for match in RELATIONSHIP_REGEX.finditer(content):
                    relationship = match.group(0)
                    if 'targetmode="external"' in relationship.lower() and re.search(
                        r'attachedTemplate|oleObject|frame', relationship, re.IGNORECASE
                    ):
                        target = TARGET_ATTR_REGEX.search(relationship)
                        findings.append(finding(
                            'high', 'office-template',
                            'Document loads external content when opened',
                            target.group(1) if target else 'external target',
                            'This document pulls a template or object from a remote location the moment it opens. Attackers use remote templates to fetch and run malicious macros while the document itself looks clean.',
                        ))
            for doc_name in [name for name in names if name.endswith(('document.xml', 'workbook.xml'))]:
                try:
                    text = archive.read(doc_name).decode('utf-8', 'replace').upper()
                except (OSError, zipfile.BadZipFile):
                    continue
                if 'DDEAUTO' in text or 'DDE ' in text:
                    findings.append(finding(
                        'high', 'office-dde',
                        'Document contains a DDE command field',
                        'DDE or DDEAUTO field present',
                        'Dynamic Data Exchange fields can run external programs when the document opens. This is a known technique for delivering malware without macros.',
                    ))
    except (zipfile.BadZipFile, OSError):
        return findings
    return dedupe_findings(findings)


def decompress_pdf_streams(data):
    chunks = []
    total = 0
    for match in PDF_STREAM_REGEX.finditer(data):
        if total > 5 * 1024 * 1024:
            break
        try:
            decoded = zlib.decompressobj().decompress(match.group(1))
        except zlib.error:
            continue
        chunks.append(decoded)
        total += len(decoded)
    return b'\n'.join(chunks)


@register
def inspect_pdf(ctx):
    if ctx.detected['type'] != 'pdf':
        return []
    data = ctx.data + b'\n' + decompress_pdf_streams(ctx.data)
    findings = []
    has_javascript = b'/JavaScript' in data or b'/JS' in data
    has_autoaction = b'/OpenAction' in data or b'/AA' in data
    if b'/Launch' in data:
        findings.append(finding(
            'high', 'pdf-action',
            'PDF can launch external programs',
            '/Launch action present',
            'This PDF is set up to run an external program. Legitimate PDFs almost never do this; it is a common malware technique.',
        ))
    if has_javascript and has_autoaction:
        findings.append(finding(
            'high', 'pdf-javascript',
            'PDF runs JavaScript automatically when opened',
            '/JavaScript combined with /OpenAction',
            'This PDF runs embedded JavaScript the moment it is opened, with no interaction. This is a common way to trigger exploits.',
        ))
    elif has_javascript:
        findings.append(finding(
            'medium', 'pdf-javascript',
            'PDF contains JavaScript',
            '/JavaScript present',
            'This PDF contains embedded JavaScript. Ordinary documents rarely need it, and it can be used to trigger exploits.',
        ))
    if b'/EmbeddedFile' in data:
        findings.append(finding(
            'medium', 'pdf-embedded',
            'PDF contains an embedded file',
            '/EmbeddedFile present',
            'This PDF has another file packed inside it, which can be used to smuggle in an executable or other document.',
        ))
    if b'/RichMedia' in data:
        findings.append(finding(
            'medium', 'pdf-richmedia',
            'PDF contains embedded rich media',
            '/RichMedia present',
            'Embedded Flash or media in a PDF has historically been used to deliver exploits.',
        ))
    return findings


@register
def inspect_archive(ctx):
    detected = ctx.detected
    if detected['type'] in {'rar', '7z', 'cab', 'iso', 'gzip', 'bzip2', 'xz'}:
        return [finding(
            'low', 'archive-opaque',
            'Archive contents could not be inspected',
            detected['label'],
            'This archive format cannot be opened for inspection by this tool. Be cautious: attackers use archives to hide dangerous files from scanners.',
        )]
    if detected['type'] != 'zip':
        return []

    findings = []
    try:
        with zipfile.ZipFile(BytesIO(ctx.data)) as archive:
            infos = archive.infolist()
            if any(info.flag_bits & 0x1 for info in infos):
                findings.append(finding(
                    'medium', 'archive-encrypted',
                    'Password-protected archive',
                    'Contents are encrypted',
                    'Password-protected archives cannot be scanned for malware. Attackers use them, with the password written in the email, specifically to slip malware past security tools.',
                ))
            uncompressed = sum(info.file_size for info in infos)
            compressed = sum(info.compress_size for info in infos) or 1
            if uncompressed > ZIP_BOMB_SIZE or uncompressed / compressed > ZIP_BOMB_RATIO:
                findings.append(finding(
                    'medium', 'archive-bomb',
                    'Archive expands to a very large size',
                    f'{human_size(uncompressed)} unpacked from {human_size(compressed)}',
                    'This archive expands enormously when opened, a sign of a decompression bomb designed to exhaust memory or disk.',
                ))
            dangerous = [info.filename for info in infos if inner_extension(info.filename) in DANGEROUS_EXTENSIONS]
            if dangerous:
                findings.append(finding(
                    'high', 'archive-contents',
                    'Archive contains dangerous files',
                    ', '.join(dangerous[:5]) + (f' and {len(dangerous) - 5} more' if len(dangerous) > 5 else ''),
                    'The archive contains executable or script files. Opening them can run commands on your computer.',
                ))
            nested = [info.filename for info in infos if inner_extension(info.filename) in ARCHIVE_EXTENSIONS]
            if nested:
                findings.append(finding(
                    'low', 'archive-nested',
                    'Archive contains more archives',
                    ', '.join(nested[:5]),
                    'Nested archives are sometimes used to bury malicious files deeper so scanners miss them.',
                ))
    except (zipfile.BadZipFile, OSError):
        return findings
    return findings


@register
def inspect_html_smuggling(ctx):
    if ctx.extension not in HTML_EXTENSIONS:
        return []
    text = ctx.data.decode('utf-8', 'replace').lower()
    strong = []
    weak = []
    if 'mssaveoropenblob' in text or 'mssaveblob' in text:
        strong.append('msSaveOrOpenBlob download')
    if 'createobjecturl' in text and 'blob' in text:
        strong.append('Blob with createObjectURL download')
    if 'application/octet-stream' in text and 'base64' in text:
        strong.append('base64 octet-stream payload')
    if 'atob(' in text:
        weak.append('base64 decoding in script')
    if re.search(r'<a\b[^>]*\bdownload\b', text):
        weak.append('forced-download link')
    if LONG_BASE64_REGEX.search(ctx.data[:3 * 1024 * 1024].decode('latin-1', 'replace')):
        weak.append('large embedded encoded blob')
    if not strong and not weak:
        return []
    severity = 'high' if strong else 'medium'
    return [finding(
        severity, 'html-smuggling',
        'HTML file may smuggle a hidden download',
        '; '.join((strong + weak)[:4]),
        'This HTML attachment contains code that can assemble and download a file directly in your browser, bypassing email and network scanners. This technique, called HTML smuggling, is used to deliver malware.',
    )]


@register
def inspect_embedded_iocs(ctx):
    if ctx.detected['category'] not in {'script', 'text'} and ctx.extension not in SCRIPT_LIKE_EXTENSIONS:
        return []
    if ctx.detected['category'] == 'text' and ctx.extension not in SCRIPT_LIKE_EXTENSIONS:
        return []
    text = ctx.data.decode('utf-8', 'replace')
    urls = list(dict.fromkeys(URL_IN_TEXT_REGEX.findall(text)))
    if not urls:
        return []
    observed = ', '.join(urls[:3]) + (f' and {len(urls) - 3} more' if len(urls) > 3 else '')
    return [finding(
        'medium', 'embedded-url',
        'Script references web addresses',
        observed,
        'This script contains web addresses it may download from or send data to. In an executable script this is a common malware download pattern.',
    )]


@register
def inspect_entropy(ctx):
    detected = ctx.detected
    if detected['category'] in {'image', 'archive', 'ooxml'} or detected['type'] in {'pdf'}:
        return []
    if len(ctx.data) < 4096:
        return []
    entropy = shannon_entropy(ctx.data[:1024 * 1024])
    if entropy > ENTROPY_THRESHOLD:
        return [finding(
            'info', 'entropy',
            'File data looks compressed or encrypted',
            f'entropy {entropy:.2f} out of 8.00',
            'Almost all of this file is high-entropy data, which can indicate packed or encrypted content used to hide malware from scanners. It can also be normal for some file types.',
        )]
    return []


def inner_extension(filename):
    return filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''


def human_size(size):
    value = float(size)
    for unit in ('B', 'KB', 'MB', 'GB'):
        if value < 1024 or unit == 'GB':
            return f'{value:.0f} {unit}' if unit == 'B' else f'{value:.1f} {unit}'
        value /= 1024
    return f'{value:.1f} GB'


def shannon_entropy(data):
    if not data:
        return 0.0
    length = len(data)
    entropy = 0.0
    for count in Counter(data).values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def dedupe_findings(findings):
    seen = set()
    unique = []
    for item in findings:
        key = (item['category'], item['title'], item['observed'])
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def highest_severity(findings):
    if not findings:
        return None
    return min(findings, key=lambda item: SEVERITY_ORDER[item['severity']])['severity']


def analyze_file(name, data):
    if not isinstance(data, bytes) or not data:
        return {'findings': [], 'risk': None, 'type_label': None}
    ctx = FileContext(name, data)
    findings = []
    for inspector in INSPECTORS:
        try:
            findings.extend(inspector(ctx) or [])
        except Exception:
            continue
    findings = dedupe_findings(findings)
    findings.sort(key=lambda item: SEVERITY_ORDER[item['severity']])
    return {
        'findings': findings,
        'risk': highest_severity(findings),
        'type_label': ctx.detected['label'],
    }
