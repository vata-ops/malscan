import hashlib
import time
import requests


def compute_hashes(file_path: str) -> dict:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)

        return {
            'md5': md5.hexdigest(),
            'sha1': sha1.hexdigest(),
            'sha256': sha256.hexdigest(),
        }
    except Exception as e:
        return {'error': str(e)}


def virustotal_lookup(sha256: str, api_key: str) -> dict:
    url = f'https://www.virustotal.com/api/v3/files/{sha256}'
    headers = {'x-apikey': api_key}

    try:
        resp = requests.get(url, headers=headers, timeout=15)

        if resp.status_code == 404:
            return {
                'found': False,
                'message': 'File not found in VirusTotal database (never submitted)',
                'sha256': sha256
            }

        if resp.status_code == 401:
            return {'error': 'Invalid VirusTotal API key'}

        if resp.status_code == 429:
            return {'error': 'VirusTotal rate limit exceeded. Try again in a minute.'}

        if resp.status_code != 200:
            return {'error': f'VirusTotal returned HTTP {resp.status_code}'}

        data = resp.json()
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})

        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)
        undetected = stats.get('undetected', 0)
        total_engines = malicious + suspicious + harmless + undetected

        # Get individual engine results (only flagging ones)
        engine_results = attributes.get('last_analysis_results', {})
        detections = []
        for engine, result in engine_results.items():
            if result.get('category') in ('malicious', 'suspicious'):
                detections.append({
                    'engine': engine,
                    'result': result.get('result', 'detected'),
                    'category': result.get('category')
                })

        # Sort detections by engine name
        detections.sort(key=lambda x: x['engine'])

        return {
            'found': True,
            'malicious': malicious,
            'suspicious': suspicious,
            'harmless': harmless,
            'undetected': undetected,
            'total_engines': total_engines,
            'detection_rate': round((malicious / total_engines * 100), 1) if total_engines > 0 else 0,
            'detections': detections[:20],  # Top 20 flagging engines
            'permalink': f'https://www.virustotal.com/gui/file/{sha256}',
            'last_analysis_date': attributes.get('last_analysis_date'),
            'names': attributes.get('names', [])[:5],
            'tags': attributes.get('tags', []),
            'type_description': attributes.get('type_description', ''),
        }

    except requests.exceptions.Timeout:
        return {'error': 'VirusTotal request timed out'}
    except requests.exceptions.ConnectionError:
        return {'error': 'Could not connect to VirusTotal'}
    except Exception as e:
        return {'error': f'VirusTotal lookup failed: {str(e)}'}
