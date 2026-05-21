import math
import os
from collections import Counter


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counter = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counter.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def compute_entropy(file_path: str) -> dict:
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        overall = _shannon_entropy(data)

        # Chunk-based entropy (detect high-entropy regions)
        chunk_size = 4096
        chunks = []
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            if len(chunk) >= 256:
                chunks.append({
                    'offset': i,
                    'entropy': _shannon_entropy(chunk)
                })

        high_entropy_chunks = [c for c in chunks if c['entropy'] > 7.0]
        avg_chunk = round(sum(c['entropy'] for c in chunks) / len(chunks), 4) if chunks else 0

        return {
            'overall': overall,
            'avg_chunk': avg_chunk,
            'high_entropy_chunks': len(high_entropy_chunks),
            'total_chunks': len(chunks),
            'interpretation': _interpret_entropy(overall),
            'chunks_sample': chunks[:50]  # For chart rendering
        }

    except Exception as e:
        return {'error': str(e), 'overall': 0}


def compute_section_entropy(file_path: str) -> list:
    """PE section entropy — called separately for executables."""
    try:
        import pefile
        pe = pefile.PE(file_path)
        sections = []
        for section in pe.sections:
            name = section.Name.decode('utf-8', errors='replace').rstrip('\x00')
            data = section.get_data()
            entropy = _shannon_entropy(data)
            sections.append({
                'name': name,
                'entropy': entropy,
                'size': len(data),
                'virtual_address': hex(section.VirtualAddress),
                'characteristics': hex(section.Characteristics),
                'interpretation': _interpret_entropy(entropy)
            })
        pe.close()
        return sections
    except Exception as e:
        return [{'error': str(e)}]


def _interpret_entropy(entropy: float) -> str:
    if entropy < 1.0:
        return 'Very low — mostly uniform data (zeros/padding)'
    elif entropy < 4.0:
        return 'Low — plain text or structured data'
    elif entropy < 6.0:
        return 'Normal — typical compiled code'
    elif entropy < 7.0:
        return 'Elevated — compressed or complex data'
    elif entropy < 7.5:
        return 'High — likely compressed or partially encrypted'
    else:
        return 'Very high — likely packed, encrypted, or obfuscated'
