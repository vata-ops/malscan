import zipfile
import re
import os


# Auto-executing macro names
AUTO_MACRO_NAMES = [
    'AutoOpen', 'AutoClose', 'AutoExec', 'AutoExit', 'AutoNew',
    'Document_Open', 'Document_Close', 'Workbook_Open', 'Workbook_Close',
    'Auto_Open', 'Auto_Close',
]

# Dangerous VBA functions
DANGEROUS_VBA = [
    'Shell', 'WScript', 'PowerShell', 'cmd.exe', 'CreateObject',
    'GetObject', 'Environ', 'CallByName', 'URLDownloadToFile',
    'XMLHTTP', 'WinHttp', 'ActiveXObject', 'Chr(', 'Asc(',
    'StrReverse', 'Base64', 'FromBase64', 'Execute', 'Eval',
    'CallWindowProc', 'VirtualAlloc', 'WriteProcessMemory',
]


def analyze_office(file_path: str) -> dict:
    result = {
        'format': 'unknown',
        'has_macros': False,
        'has_auto_macros': False,
        'auto_macro_names': [],
        'has_external_links': False,
        'has_ole_objects': False,
        'has_dde': False,
        'suspicious_patterns': [],
        'vba_code_size': 0,
        'dangerous_functions': [],
        'embedded_files': [],
        'relationships': [],
        'metadata': {},
    }

    ext = os.path.splitext(file_path)[1].lower()

    # OOXML formats (docx, xlsx, pptx) are ZIP archives
    if ext in ('.docx', '.xlsx', '.pptx'):
        result['format'] = 'OOXML'
        _analyze_ooxml(file_path, result)
    else:
        # Legacy binary formats (.doc, .xls, .ppt) — OLE
        result['format'] = 'OLE (legacy binary)'
        _analyze_ole(file_path, result)

    # DDE detection (raw scan regardless of format)
    try:
        with open(file_path, 'rb') as f:
            raw = f.read()
        if b'DDE(' in raw or b'DDEAUTO(' in raw or b'\x00D\x00D\x00E' in raw:
            result['has_dde'] = True
            result['suspicious_patterns'].append('DDE (Dynamic Data Exchange) field detected — can execute commands')
    except Exception:
        pass

    return result


def _analyze_ooxml(file_path: str, result: dict):
    try:
        with zipfile.ZipFile(file_path, 'r') as zf:
            names = zf.namelist()

            # Check for VBA macros
            macro_files = [n for n in names if 'vbaProject' in n or n.endswith('.bas') or n.endswith('.cls')]
            if macro_files:
                result['has_macros'] = True
                for mf in macro_files:
                    try:
                        data = zf.read(mf)
                        result['vba_code_size'] += len(data)
                        _scan_vba(data.decode('latin-1', errors='replace'), result)
                    except Exception:
                        pass

            # External relationships
            rel_files = [n for n in names if n.endswith('.rels')]
            for rf in rel_files:
                try:
                    content = zf.read(rf).decode('utf-8', errors='replace')
                    if 'TargetMode="External"' in content:
                        result['has_external_links'] = True
                        # Extract external targets
                        targets = re.findall(r'Target="([^"]+)"[^>]*TargetMode="External"', content)
                        for t in targets:
                            if t not in result['relationships']:
                                result['relationships'].append(t)
                except Exception:
                    pass

            # Embedded OLE objects
            ole_files = [n for n in names if 'oleObject' in n or n.endswith('.bin')]
            if ole_files:
                result['has_ole_objects'] = True
                result['embedded_files'].extend(ole_files[:10])

            # Metadata from core.xml
            if 'docProps/core.xml' in names:
                try:
                    core = zf.read('docProps/core.xml').decode('utf-8', errors='replace')
                    for field in ['dc:creator', 'dc:title', 'cp:lastModifiedBy', 'dcterms:created', 'dcterms:modified']:
                        m = re.search(rf'<{re.escape(field)}>(.*?)</{re.escape(field)}>', core)
                        if m:
                            result['metadata'][field.split(':')[1]] = m.group(1)
                except Exception:
                    pass

    except zipfile.BadZipFile:
        result['suspicious_patterns'].append('File has OOXML extension but is not a valid ZIP archive')
    except Exception as e:
        result['suspicious_patterns'].append(f'OOXML analysis error: {str(e)}')


def _analyze_ole(file_path: str, result: dict):
    """Analyze legacy OLE binary formats."""
    try:
        import olefile
        if not olefile.isOleFile(file_path):
            result['suspicious_patterns'].append('File has OLE extension but is not a valid OLE file')
            return

        ole = olefile.OleFileIO(file_path)
        entries = ole.listdir()

        # Check for VBA macros
        vba_streams = [e for e in entries if 'VBA' in str(e).upper() or 'MACRO' in str(e).upper()]
        if vba_streams:
            result['has_macros'] = True
            for stream_path in vba_streams:
                try:
                    data = ole.openstream(stream_path).read()
                    result['vba_code_size'] += len(data)
                    _scan_vba(data.decode('latin-1', errors='replace'), result)
                except Exception:
                    pass

        # Metadata
        try:
            meta = ole.get_metadata()
            if meta.author:
                result['metadata']['author'] = meta.author.decode('latin-1', errors='replace')
            if meta.last_saved_by:
                result['metadata']['last_saved_by'] = meta.last_saved_by.decode('latin-1', errors='replace')
            if meta.create_time:
                result['metadata']['created'] = str(meta.create_time)
        except Exception:
            pass

        ole.close()

    except ImportError:
        result['suspicious_patterns'].append('olefile not installed — legacy Office format analysis limited')
    except Exception as e:
        result['suspicious_patterns'].append(f'OLE analysis error: {str(e)}')


def _scan_vba(code: str, result: dict):
    """Scan VBA code for dangerous patterns."""
    # Auto-executing macros
    for macro_name in AUTO_MACRO_NAMES:
        if re.search(rf'\bSub\s+{re.escape(macro_name)}\b', code, re.IGNORECASE):
            result['has_auto_macros'] = True
            if macro_name not in result['auto_macro_names']:
                result['auto_macro_names'].append(macro_name)

    # Dangerous functions
    for func in DANGEROUS_VBA:
        if func.lower() in code.lower():
            if func not in result['dangerous_functions']:
                result['dangerous_functions'].append(func)

    # Obfuscation patterns
    chr_calls = len(re.findall(r'Chr\s*\(\s*\d+\s*\)', code, re.IGNORECASE))
    if chr_calls > 10:
        result['suspicious_patterns'].append(f'Heavy Chr() usage ({chr_calls} calls) — likely string obfuscation')

    # Base64 strings
    b64 = re.findall(r'"[A-Za-z0-9+/]{40,}={0,2}"', code)
    if b64:
        result['suspicious_patterns'].append(f'Possible Base64 encoded strings in VBA ({len(b64)} occurrences)')

    # URL patterns
    urls = re.findall(r'https?://[^\s"\']+', code)
    if urls:
        result['suspicious_patterns'].append(f'URLs in VBA code: {", ".join(set(urls[:3]))}')
