import os
import magic


EXTENSION_MAP = {
    # Executables
    'exe': {'category': 'executable', 'label': 'Windows Executable (PE32)'},
    'dll': {'category': 'executable', 'label': 'Dynamic Link Library (DLL)'},
    'sys': {'category': 'executable', 'label': 'Windows Driver'},
    # PDF
    'pdf': {'category': 'pdf', 'label': 'PDF Document'},
    # Office
    'doc':  {'category': 'office', 'label': 'Word Document (Legacy)'},
    'docx': {'category': 'office', 'label': 'Word Document (OOXML)'},
    'xls':  {'category': 'office', 'label': 'Excel Spreadsheet (Legacy)'},
    'xlsx': {'category': 'office', 'label': 'Excel Spreadsheet (OOXML)'},
    'ppt':  {'category': 'office', 'label': 'PowerPoint Presentation (Legacy)'},
    'pptx': {'category': 'office', 'label': 'PowerPoint Presentation (OOXML)'},
    # Scripts
    'js':   {'category': 'script', 'label': 'JavaScript'},
    'py':   {'category': 'script', 'label': 'Python Script'},
    'sh':   {'category': 'script', 'label': 'Shell Script (Bash)'},
    'ps1':  {'category': 'script', 'label': 'PowerShell Script'},
    'bat':  {'category': 'script', 'label': 'Windows Batch File'},
    'vbs':  {'category': 'script', 'label': 'VBScript'},
    'rb':   {'category': 'script', 'label': 'Ruby Script'},
    'php':  {'category': 'script', 'label': 'PHP Script'},
}


def identify_file(file_path: str, original_filename: str) -> dict:
    result = {
        'category': 'unknown',
        'label': 'Unknown',
        'mime_type': None,
        'magic_description': None,
        'size_bytes': 0,
        'extension': None,
        'extension_matches_magic': True,
    }

    # File size
    try:
        result['size_bytes'] = os.path.getsize(file_path)
    except Exception:
        pass

    # Extension from original filename
    ext = ''
    if '.' in original_filename:
        ext = original_filename.rsplit('.', 1)[1].lower()
    result['extension'] = ext

    # Map extension
    if ext in EXTENSION_MAP:
        result['category'] = EXTENSION_MAP[ext]['category']
        result['label'] = EXTENSION_MAP[ext]['label']

    # libmagic identification
    try:
        mime = magic.from_file(file_path, mime=True)
        description = magic.from_file(file_path)
        result['mime_type'] = mime
        result['magic_description'] = description

        # Cross-check: does magic match extension?
        magic_category = _mime_to_category(mime)
        if magic_category and magic_category != result['category']:
            result['extension_matches_magic'] = False
            # Trust magic over extension for category
            result['category'] = magic_category
            result['label'] = description[:80] if description else result['label']

    except Exception as e:
        result['magic_error'] = str(e)

    return result


def _mime_to_category(mime: str) -> str | None:
    mime = mime.lower()
    if 'executable' in mime or 'x-dosexec' in mime or 'x-msdownload' in mime:
        return 'executable'
    if mime == 'application/pdf':
        return 'pdf'
    if 'officedocument' in mime or 'msword' in mime or 'ms-excel' in mime or 'ms-powerpoint' in mime:
        return 'office'
    if mime in ('text/x-python', 'text/x-shellscript', 'text/x-powershell',
                'application/x-sh', 'text/javascript', 'application/javascript'):
        return 'script'
    if mime.startswith('text/'):
        return 'script'
    return None
