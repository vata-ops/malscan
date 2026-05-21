import re
import os
import math
from collections import Counter


# Pattern definitions per language
PATTERNS = {
    'global': [
        (r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'HTTP request to raw IP address'),
        (r'base64[_\.\s]*decode', 'Base64 decoding (possible obfuscation)'),
        (r'eval\s*\(', 'eval() call — dynamic code execution'),
        (r'exec\s*\(', 'exec() call — dynamic code execution'),
        (r'\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){8,}', 'Hex-encoded string (obfuscation)'),
    ],
    '.py': [
        (r'subprocess\.(call|run|Popen|check_output)', 'subprocess execution'),
        (r'os\.(system|popen|execv|execve)', 'OS command execution'),
        (r'__import__\s*\(', 'Dynamic import (possible evasion)'),
        (r'ctypes\.(windll|cdll|CDLL)', 'ctypes usage — direct API calls'),
        (r'socket\.connect\s*\(', 'Socket connection'),
        (r'marshal\.(loads|dumps)', 'marshal serialization — code obfuscation risk'),
        (r'pickle\.(loads|load)', 'pickle deserialization — RCE risk'),
    ],
    '.js': [
        (r'require\s*\([\'"]child_process', 'child_process usage'),
        (r'new\s+Function\s*\(', 'new Function() — dynamic code execution'),
        (r'document\.write\s*\(', 'document.write() — XSS risk'),
        (r'window\.location\s*=', 'Redirect via window.location'),
        (r'unescape\s*\(', 'unescape() — obfuscation pattern'),
        (r'String\.fromCharCode', 'String.fromCharCode — obfuscation pattern'),
        (r'atob\s*\(', 'atob() Base64 decoding'),
    ],
    '.ps1': [
        (r'-enc(odedcommand)?', 'Encoded command (common obfuscation)', re.IGNORECASE),
        (r'iex\s*[\(\$]', 'IEX (Invoke-Expression) — dynamic execution', re.IGNORECASE),
        (r'Invoke-Expression', 'Invoke-Expression — dynamic execution', re.IGNORECASE),
        (r'DownloadString|DownloadFile|WebClient', 'Network download activity'),
        (r'bypass', 'Execution policy bypass', re.IGNORECASE),
        (r'hidden', 'Hidden window execution', re.IGNORECASE),
        (r'Add-Type.*DllImport', 'P/Invoke — direct Windows API call', re.IGNORECASE),
        (r'VirtualAlloc|WriteProcessMemory', 'Memory manipulation (injection pattern)'),
        (r'\[Convert\]::FromBase64', 'Base64 decoding'),
        (r'New-Object.*Net\.WebClient', 'WebClient instantiation — download'),
    ],
    '.sh': [
        (r'curl\s+.*\s*\|\s*(bash|sh)', 'curl pipe to shell — RCE pattern'),
        (r'wget\s+.*\s*\|\s*(bash|sh)', 'wget pipe to shell — RCE pattern'),
        (r'chmod\s+[0-7]*7[0-7]*\s+', 'Making file executable'),
        (r'\$\(.*curl|`.*curl', 'Command substitution with curl'),
        (r'>/dev/tcp/', 'TCP reverse shell pattern'),
        (r'nc\s+-', 'Netcat usage'),
        (r'base64\s+-d', 'Base64 decoding'),
        (r'nohup\s+', 'Background persistence (nohup)'),
    ],
    '.bat': [
        (r'powershell.*-enc', 'PowerShell encoded command from batch', re.IGNORECASE),
        (r'certutil.*-decode', 'certutil decode — bypass technique', re.IGNORECASE),
        (r'bitsadmin.*transfer', 'BITS download (LOLBin)', re.IGNORECASE),
        (r'regsvr32.*scrobj', 'regsvr32 SCT execution (LOLBin)', re.IGNORECASE),
        (r'mshta\s+http', 'mshta remote execution (LOLBin)', re.IGNORECASE),
    ],
    '.vbs': [
        (r'WScript\.Shell', 'WScript.Shell — command execution'),
        (r'CreateObject.*WScript', 'WScript object creation'),
        (r'XMLHTTP|WinHttp', 'HTTP request in VBScript'),
        (r'Eval\s*\(', 'Eval() — dynamic execution'),
        (r'Execute\s*\(', 'Execute() — dynamic code execution'),
    ],
}


def analyze_script(file_path: str, filename: str) -> dict:
    result = {
        'language': None,
        'line_count': 0,
        'suspicious_patterns': [],
        'is_obfuscated': False,
        'obfuscation_indicators': [],
        'network_indicators': [],
        'execution_indicators': [],
        'avg_line_length': 0,
        'max_line_length': 0,
        'entropy': 0,
    }

    ext = ('.' + filename.rsplit('.', 1)[-1].lower()) if '.' in filename else ''
    result['language'] = _ext_to_language(ext)

    try:
        with open(file_path, 'rb') as f:
            raw = f.read()

        try:
            code = raw.decode('utf-8')
        except UnicodeDecodeError:
            code = raw.decode('latin-1')

        lines = code.splitlines()
        result['line_count'] = len(lines)

        # Line length stats
        lengths = [len(l) for l in lines if l.strip()]
        if lengths:
            result['avg_line_length'] = round(sum(lengths) / len(lengths), 1)
            result['max_line_length'] = max(lengths)

        # Very long lines = obfuscation
        long_lines = [l for l in lines if len(l) > 500]
        if long_lines:
            result['obfuscation_indicators'].append(f'{len(long_lines)} line(s) over 500 chars — common obfuscation indicator')
            result['is_obfuscated'] = True

        # Apply patterns
        patterns_to_check = PATTERNS.get('global', []) + PATTERNS.get(ext, [])
        for pattern_tuple in patterns_to_check:
            if len(pattern_tuple) == 3:
                pattern, description, flags = pattern_tuple
                matches = re.findall(pattern, code, flags)
            else:
                pattern, description = pattern_tuple
                matches = re.findall(pattern, code)

            if matches:
                result['suspicious_patterns'].append(f'{description} ({len(matches)} occurrence{"s" if len(matches) > 1 else ""})')

        # Entropy-based obfuscation check
        entropy = _string_entropy(code)
        result['entropy'] = round(entropy, 3)
        if entropy > 5.5 and result['avg_line_length'] > 100:
            result['is_obfuscated'] = True
            result['obfuscation_indicators'].append(f'High entropy ({entropy:.2f}) with long lines')

        # Network indicators
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', code)
        domains = re.findall(r'https?://([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})', code)
        result['network_indicators'] = list(set(ips[:10] + domains[:10]))

        # Execution indicators
        exec_patterns = ['exec', 'eval', 'shell', 'spawn', 'popen', 'system', 'invoke']
        for ep in exec_patterns:
            if ep.lower() in code.lower():
                if ep not in result['execution_indicators']:
                    result['execution_indicators'].append(ep)

        return result

    except Exception as e:
        return {'error': f'Script analysis failed: {str(e)}'}


def _ext_to_language(ext: str) -> str:
    map_ = {
        '.py': 'Python',
        '.js': 'JavaScript',
        '.ps1': 'PowerShell',
        '.sh': 'Bash/Shell',
        '.bat': 'Windows Batch',
        '.vbs': 'VBScript',
        '.rb': 'Ruby',
        '.php': 'PHP',
    }
    return map_.get(ext, 'Unknown Script')


def _string_entropy(text: str) -> float:
    if not text:
        return 0.0
    counter = Counter(text)
    total = len(text)
    entropy = 0.0
    for count in counter.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy
