import re


# Dangerous PDF keywords
DANGEROUS_KEYS = [
    '/JavaScript', '/JS',
    '/AA',          # Additional Actions (auto-trigger)
    '/OpenAction',  # Auto-run on open
    '/Launch',      # Launch external program
    '/EmbeddedFile',
    '/RichMedia',
    '/XFA',         # XML Forms Architecture (exploitable)
    '/Encrypt',
    '/AcroForm',
    '/URI',
    '/SubmitForm',
    '/ImportData',
]

AUTO_ACTION_KEYS = ['/AA', '/OpenAction', '/Launch']


def analyze_pdf(file_path: str) -> dict:
    result = {
        'has_javascript': False,
        'has_auto_action': False,
        'has_embedded_files': False,
        'has_encryption': False,
        'has_xfa': False,
        'has_acroform': False,
        'has_uri_actions': False,
        'page_count': None,
        'dangerous_keywords': [],
        'keyword_counts': {},
        'streams': [],
        'suspicious_patterns': [],
        'metadata': {},
    }

    try:
        with open(file_path, 'rb') as f:
            raw = f.read()

        # Decode safely for pattern matching
        try:
            text = raw.decode('latin-1')
        except Exception:
            text = raw.decode('utf-8', errors='replace')

        # Keyword scanning
        for key in DANGEROUS_KEYS:
            count = len(re.findall(re.escape(key), text, re.IGNORECASE))
            if count > 0:
                result['dangerous_keywords'].append(key)
                result['keyword_counts'][key] = count

        # Feature flags
        result['has_javascript'] = any(k in result['dangerous_keywords'] for k in ['/JavaScript', '/JS'])
        result['has_auto_action'] = any(k in result['dangerous_keywords'] for k in AUTO_ACTION_KEYS)
        result['has_embedded_files'] = '/EmbeddedFile' in result['dangerous_keywords']
        result['has_encryption'] = '/Encrypt' in result['dangerous_keywords']
        result['has_xfa'] = '/XFA' in result['dangerous_keywords']
        result['has_acroform'] = '/AcroForm' in result['dangerous_keywords']
        result['has_uri_actions'] = '/URI' in result['dangerous_keywords']

        # Page count
        page_matches = re.findall(r'/Type\s*/Page[^s]', text)
        result['page_count'] = len(page_matches)

        # Find streams
        stream_matches = re.findall(r'stream\r?\n(.*?)\r?\nendstream', raw.decode('latin-1', errors='replace'), re.DOTALL)
        result['streams'] = [{
            'index': i,
            'size': len(s),
            'has_filtered': bool(re.search(r'/Filter', text))
        } for i, s in enumerate(stream_matches[:20])]

        # Suspicious URL patterns in content
        urls = re.findall(r'https?://[^\s\)\]\>\"\']+', text)
        external_urls = [u for u in urls if not u.startswith('https://www.adobe')]
        if external_urls:
            result['suspicious_patterns'].append(f'External URLs found: {len(external_urls)}')
            result['external_urls'] = list(set(external_urls[:10]))

        # Suspicious: base64 blobs (obfuscated content)
        b64_matches = re.findall(r'[A-Za-z0-9+/]{100,}={0,2}', text)
        if b64_matches:
            result['suspicious_patterns'].append(f'Possible base64 encoded content ({len(b64_matches)} blobs)')

        # Metadata (from /Info dictionary)
        info_match = re.search(r'/Info\s*<<(.*?)>>', text, re.DOTALL)
        if info_match:
            meta_block = info_match.group(1)
            for field in ['Author', 'Creator', 'Producer', 'Title', 'Subject', 'CreationDate', 'ModDate']:
                m = re.search(rf'/{field}\s*\(([^)]*)\)', meta_block)
                if m:
                    result['metadata'][field] = m.group(1)

        # Header check
        if not raw[:8].startswith(b'%PDF-'):
            result['suspicious_patterns'].append('File does not start with %PDF- header — possible disguised file')

        return result

    except Exception as e:
        return {'error': f'PDF analysis failed: {str(e)}'}
