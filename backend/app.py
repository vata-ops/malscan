import os
import sys
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename
import tempfile

from analyzers.file_identifier import identify_file
from analyzers.hash_analyzer import compute_hashes, virustotal_lookup
from analyzers.entropy_analyzer import compute_entropy, compute_section_entropy
from analyzers.pe_analyzer import analyze_pe
from analyzers.pdf_analyzer import analyze_pdf
from analyzers.office_analyzer import analyze_office
from analyzers.script_analyzer import analyze_script
from analyzers.string_extractor import extract_strings

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), '..', 'uploads')
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

ALLOWED_EXTENSIONS = {
    'exe', 'dll', 'sys',
    'pdf',
    'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    'js', 'py', 'sh', 'ps1', 'bat', 'vbs', 'rb', 'php'
}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'version': '1.0.0'})


@app.route('/api/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    vt_api_key = request.form.get('vt_api_key', '').strip()

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': f'File type not supported'}), 400

    filename = secure_filename(file.filename)

    with tempfile.NamedTemporaryFile(delete=False, suffix='_' + filename) as tmp:
        file.save(tmp.name)
        tmp_path = tmp.name

    try:
        result = run_analysis(tmp_path, filename, vt_api_key)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


def run_analysis(file_path, original_filename, vt_api_key=''):
    result = {
        'filename': original_filename,
        'file_type': None,
        'hashes': {},
        'virustotal': None,
        'entropy': {},
        'strings': [],
        'specific_analysis': {},
        'risk_score': 0,
        'risk_factors': [],
        'iocs': []
    }

    # File identification
    file_info = identify_file(file_path, original_filename)
    result['file_type'] = file_info

    # Hashes
    hashes = compute_hashes(file_path)
    result['hashes'] = hashes

    # VirusTotal lookup
    if vt_api_key:
        vt_result = virustotal_lookup(hashes['sha256'], vt_api_key)
        result['virustotal'] = vt_result

    # Overall entropy
    entropy_info = compute_entropy(file_path)
    result['entropy'] = entropy_info

    # String extraction
    strings = extract_strings(file_path)
    result['strings'] = strings

    # Type-specific analysis
    category = file_info.get('category', 'unknown')

    if category == 'executable':
        pe_result = analyze_pe(file_path)
        result['specific_analysis'] = pe_result
        section_entropy = compute_section_entropy(file_path)
        result['entropy']['sections'] = section_entropy

    elif category == 'pdf':
        pdf_result = analyze_pdf(file_path)
        result['specific_analysis'] = pdf_result

    elif category == 'office':
        office_result = analyze_office(file_path)
        result['specific_analysis'] = office_result

    elif category == 'script':
        script_result = analyze_script(file_path, original_filename)
        result['specific_analysis'] = script_result

    # Risk scoring
    risk_score, risk_factors, iocs = calculate_risk(result)
    result['risk_score'] = risk_score
    result['risk_factors'] = risk_factors
    result['iocs'] = iocs

    return result


def calculate_risk(result):
    score = 0
    factors = []
    iocs = []

    # Entropy-based risk
    overall_entropy = result['entropy'].get('overall', 0)
    if overall_entropy > 7.5:
        score += 30
        factors.append({
            'severity': 'high',
            'description': f'Very high entropy ({overall_entropy:.2f}/8.0) — likely packed or encrypted',
            'category': 'entropy'
        })
    elif overall_entropy > 7.0:
        score += 15
        factors.append({
            'severity': 'medium',
            'description': f'Elevated entropy ({overall_entropy:.2f}/8.0) — possible obfuscation',
            'category': 'entropy'
        })

    # VirusTotal hits
    vt = result.get('virustotal')
    if vt and vt.get('found'):
        detections = vt.get('malicious', 0)
        total = vt.get('total_engines', 0)
        if detections > 0:
            pct = (detections / total * 100) if total > 0 else 0
            score += min(50, int(pct))
            severity = 'critical' if pct > 30 else 'high' if pct > 10 else 'medium'
            factors.append({
                'severity': severity,
                'description': f'VirusTotal: {detections}/{total} engines flagged this file',
                'category': 'reputation'
            })

    # Specific analysis flags
    specific = result.get('specific_analysis', {})

    # PE-specific
    if result['file_type'].get('category') == 'executable':
        if specific.get('is_packed'):
            score += 20
            factors.append({
                'severity': 'high',
                'description': 'File appears to be packed (common in malware)',
                'category': 'pe'
            })
        suspicious_imports = specific.get('suspicious_imports', [])
        if suspicious_imports:
            score += min(20, len(suspicious_imports) * 5)
            factors.append({
                'severity': 'medium',
                'description': f'Suspicious imports found: {", ".join(suspicious_imports[:5])}',
                'category': 'imports'
            })
        if specific.get('no_aslr') or specific.get('no_dep'):
            score += 10
            factors.append({
                'severity': 'low',
                'description': 'Missing security mitigations (ASLR/DEP)',
                'category': 'mitigations'
            })

    # PDF-specific
    if result['file_type'].get('category') == 'pdf':
        if specific.get('has_javascript'):
            score += 25
            factors.append({
                'severity': 'high',
                'description': 'PDF contains embedded JavaScript',
                'category': 'pdf'
            })
        if specific.get('has_auto_action'):
            score += 20
            factors.append({
                'severity': 'high',
                'description': 'PDF has auto-open/auto-launch actions',
                'category': 'pdf'
            })
        if specific.get('has_embedded_files'):
            score += 15
            factors.append({
                'severity': 'medium',
                'description': 'PDF contains embedded files',
                'category': 'pdf'
            })

    # Office-specific
    if result['file_type'].get('category') == 'office':
        if specific.get('has_macros'):
            score += 30
            factors.append({
                'severity': 'high',
                'description': 'Office file contains VBA macros',
                'category': 'office'
            })
        if specific.get('has_auto_macros'):
            score += 20
            factors.append({
                'severity': 'critical',
                'description': 'Auto-executing macros detected (AutoOpen/AutoExec)',
                'category': 'office'
            })
        if specific.get('has_external_links'):
            score += 10
            factors.append({
                'severity': 'medium',
                'description': 'External links/OLE objects present',
                'category': 'office'
            })

    # Script-specific
    if result['file_type'].get('category') == 'script':
        suspicious_patterns = specific.get('suspicious_patterns', [])
        if suspicious_patterns:
            score += min(30, len(suspicious_patterns) * 8)
            for p in suspicious_patterns[:5]:
                factors.append({
                    'severity': 'medium',
                    'description': p,
                    'category': 'script'
                })
        if specific.get('is_obfuscated'):
            score += 25
            factors.append({
                'severity': 'high',
                'description': 'Script appears obfuscated',
                'category': 'script'
            })

    # IOC extraction from strings
    strings_data = result.get('strings', {})
    iocs = strings_data.get('iocs', [])

    if iocs:
        score += min(15, len(iocs) * 3)
        factors.append({
            'severity': 'medium',
            'description': f'{len(iocs)} potential IOC(s) found in strings (IPs, URLs, domains)',
            'category': 'iocs'
        })

    score = min(100, score)
    return score, factors, iocs


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
