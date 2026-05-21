import re
import struct


MIN_STRING_LEN = 4


def extract_strings(file_path: str) -> dict:
    result = {
        'ascii': [],
        'unicode': [],
        'iocs': [],
        'total_ascii': 0,
        'total_unicode': 0,
    }

    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        # ASCII strings
        ascii_strings = _extract_ascii(data)
        result['ascii'] = ascii_strings[:200]
        result['total_ascii'] = len(ascii_strings)

        # Unicode strings (UTF-16 LE — common in Windows binaries)
        unicode_strings = _extract_unicode(data)
        result['unicode'] = unicode_strings[:100]
        result['total_unicode'] = len(unicode_strings)

        # IOC extraction from all strings
        all_strings = ascii_strings + unicode_strings
        iocs = extract_iocs(all_strings)
        result['iocs'] = iocs

        return result

    except Exception as e:
        return {'error': str(e), 'ascii': [], 'unicode': [], 'iocs': []}


def _extract_ascii(data: bytes) -> list:
    printable = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}
    strings = []
    current = []

    for byte in data:
        if byte in printable:
            current.append(chr(byte))
        else:
            if len(current) >= MIN_STRING_LEN:
                strings.append(''.join(current))
            current = []

    if len(current) >= MIN_STRING_LEN:
        strings.append(''.join(current))

    return strings


def _extract_unicode(data: bytes) -> list:
    strings = []
    i = 0

    while i < len(data) - 2:
        # Look for UTF-16 LE sequences
        if (0x20 <= data[i] < 0x7F) and data[i + 1] == 0:
            chars = []
            j = i
            while j + 1 < len(data) and 0x20 <= data[j] < 0x7F and data[j + 1] == 0:
                chars.append(chr(data[j]))
                j += 2

            if len(chars) >= MIN_STRING_LEN:
                strings.append(''.join(chars))
                i = j
                continue
        i += 1

    return strings


def extract_iocs(strings: list) -> list:
    iocs = []
    seen = set()

    # IPv4 addresses (exclude common non-IOC ones)
    ip_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
    excluded_ips = {'127.0.0.1', '0.0.0.0', '255.255.255.255', '224.0.0.0', '8.8.8.8', '8.8.4.4'}

    # Domain/URL pattern
    url_pattern = re.compile(r'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s]*)?')
    domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9\-]+\.)+(?:com|net|org|io|ru|cn|cc|tk|top|xyz|pw|su|biz|info|onion)\b')

    # Registry keys
    registry_pattern = re.compile(r'(?:HKEY_|HKLM|HKCU|HKCR|HKU|HKCC)[\\\w\s]+')

    # File paths
    path_pattern = re.compile(r'(?:[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*|/(?:etc|tmp|var|home|usr|bin|sbin|proc)/[^\s]+)')

    # Mutex names (often GUIDs or random strings in specific contexts)
    mutex_pattern = re.compile(r'(?:Global\\|Local\\)[A-Za-z0-9_\-]{8,}')

    for s in strings:
        # IPs
        for match in ip_pattern.finditer(s):
            ip = match.group()
            if ip not in excluded_ips and not ip.startswith('10.') and not ip.startswith('192.168.') and ip not in seen:
                seen.add(ip)
                iocs.append({'type': 'ip', 'value': ip})

        # URLs
        for match in url_pattern.finditer(s):
            url = match.group()
            if url not in seen:
                seen.add(url)
                iocs.append({'type': 'url', 'value': url[:200]})

        # Domains (not already captured by URL)
        for match in domain_pattern.finditer(s):
            domain = match.group()
            if domain not in seen and not any(domain in ioc['value'] for ioc in iocs if ioc['type'] == 'url'):
                seen.add(domain)
                iocs.append({'type': 'domain', 'value': domain})

        # Registry
        for match in registry_pattern.finditer(s):
            reg = match.group().strip()
            if len(reg) > 10 and reg not in seen:
                seen.add(reg)
                iocs.append({'type': 'registry', 'value': reg[:200]})

        # Paths
        for match in path_pattern.finditer(s):
            path = match.group().strip()
            if len(path) > 5 and path not in seen:
                seen.add(path)
                iocs.append({'type': 'filepath', 'value': path[:200]})

        # Mutex
        for match in mutex_pattern.finditer(s):
            mutex = match.group()
            if mutex not in seen:
                seen.add(mutex)
                iocs.append({'type': 'mutex', 'value': mutex})

    return iocs[:100]
