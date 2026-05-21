import datetime


SUSPICIOUS_IMPORTS = {
    # Process injection / hollowing
    'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
    'NtUnmapViewOfSection', 'ZwUnmapViewOfSection', 'SetThreadContext',
    'QueueUserAPC', 'NtQueueApcThread',
    # Persistence
    'RegSetValueEx', 'RegCreateKeyEx', 'CreateService', 'ChangeServiceConfig',
    # Network
    'WSAStartup', 'connect', 'send', 'recv', 'URLDownloadToFile',
    'InternetOpenUrl', 'HttpSendRequest', 'WinHttpOpen',
    # Evasion
    'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
    'GetTickCount', 'QueryPerformanceCounter', 'Sleep',
    # Shell / execution
    'ShellExecute', 'WinExec', 'CreateProcess', 'system',
    # Crypto / encoding (suspicious in context)
    'CryptEncrypt', 'CryptDecrypt', 'CryptGenRandom',
    # Keylogging
    'SetWindowsHookEx', 'GetAsyncKeyState', 'GetForegroundWindow',
}

KNOWN_PACKERS = {
    'UPX0', 'UPX1', 'UPX2',
    '.MPRESS1', '.MPRESS2',
    'ASPack', 'Themida',
    '.netsect', 'BitArts',
}


def analyze_pe(file_path: str) -> dict:
    try:
        import pefile

        pe = pefile.PE(file_path)

        result = {
            'is_valid_pe': True,
            'architecture': None,
            'subsystem': None,
            'compilation_timestamp': None,
            'entry_point': None,
            'image_base': None,
            'is_packed': False,
            'packer_hints': [],
            'is_dll': bool(pe.FILE_HEADER.Characteristics & 0x2000),
            'sections': [],
            'imports': [],
            'exports': [],
            'suspicious_imports': [],
            'security_mitigations': {},
            'no_aslr': False,
            'no_dep': False,
            'resources': [],
            'version_info': {},
            'overlay': None,
        }

        # Architecture
        machine = pe.FILE_HEADER.Machine
        if machine == 0x14c:
            result['architecture'] = 'x86 (32-bit)'
        elif machine == 0x8664:
            result['architecture'] = 'x64 (64-bit)'
        elif machine == 0x1c0:
            result['architecture'] = 'ARM'
        else:
            result['architecture'] = f'Unknown (0x{machine:04x})'

        # Subsystem
        subsystem_map = {
            2: 'Windows GUI',
            3: 'Windows Console (CUI)',
            9: 'Windows CE GUI',
            10: 'EFI Application',
        }
        if hasattr(pe, 'OPTIONAL_HEADER'):
            oh = pe.OPTIONAL_HEADER
            result['subsystem'] = subsystem_map.get(oh.Subsystem, f'0x{oh.Subsystem:x}')
            result['entry_point'] = hex(oh.AddressOfEntryPoint)
            result['image_base'] = hex(oh.ImageBase)

            # Security mitigations
            dll_chars = oh.DllCharacteristics
            result['security_mitigations'] = {
                'ASLR': bool(dll_chars & 0x0040),
                'DEP/NX': bool(dll_chars & 0x0100),
                'SEH': bool(dll_chars & 0x0400),
                'CFG': bool(dll_chars & 0x4000),
                'high_entropy_va': bool(dll_chars & 0x0020),
            }
            result['no_aslr'] = not result['security_mitigations']['ASLR']
            result['no_dep'] = not result['security_mitigations']['DEP/NX']

        # Compilation timestamp
        try:
            ts = pe.FILE_HEADER.TimeDateStamp
            dt = datetime.datetime.utcfromtimestamp(ts)
            result['compilation_timestamp'] = {
                'raw': ts,
                'human': dt.strftime('%Y-%m-%d %H:%M:%S UTC'),
                'suspicious': ts == 0 or ts > datetime.datetime.utcnow().timestamp()
            }
        except Exception:
            pass

        # Sections
        section_names = []
        for section in pe.sections:
            name = section.Name.decode('utf-8', errors='replace').rstrip('\x00')
            section_names.append(name)
            result['sections'].append({
                'name': name,
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'virtual_address': hex(section.VirtualAddress),
                'characteristics': hex(section.Characteristics),
                'executable': bool(section.Characteristics & 0x20000000),
                'writable': bool(section.Characteristics & 0x80000000),
                'readable': bool(section.Characteristics & 0x40000000),
            })

        # Packer detection
        for sec_name in section_names:
            stripped = sec_name.strip()
            if stripped in KNOWN_PACKERS:
                result['is_packed'] = True
                result['packer_hints'].append(f'Known packer section: {stripped}')

        # UPX specific
        if 'UPX0' in section_names or 'UPX1' in section_names:
            result['is_packed'] = True
            result['packer_hints'].append('UPX packer detected')

        # Imports
        suspicious_found = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='replace')
                functions = []
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='replace')
                        functions.append(func_name)
                        if func_name in SUSPICIOUS_IMPORTS:
                            suspicious_found.append(func_name)

                result['imports'].append({
                    'dll': dll_name,
                    'functions': functions[:30]
                })

        result['suspicious_imports'] = list(set(suspicious_found))

        # Exports
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    result['exports'].append(exp.name.decode('utf-8', errors='replace'))

        # Overlay (data after last section — common in droppers)
        overlay_offset = pe.get_overlay_data_start_offset()
        if overlay_offset:
            overlay_size = len(pe.__data__) - overlay_offset
            if overlay_size > 0:
                result['overlay'] = {
                    'offset': overlay_offset,
                    'size': overlay_size,
                    'suspicious': overlay_size > 10000
                }

        # Version info
        if hasattr(pe, 'FileInfo'):
            try:
                for fi in pe.FileInfo:
                    for entry in fi:
                        if hasattr(entry, 'StringTable'):
                            for st in entry.StringTable:
                                for k, v in st.entries.items():
                                    key = k.decode('utf-8', errors='replace')
                                    val = v.decode('utf-8', errors='replace')
                                    result['version_info'][key] = val
            except Exception:
                pass

        pe.close()
        return result

    except ImportError:
        return {'error': 'pefile not installed. Run: pip install pefile'}
    except Exception as e:
        return {'error': f'PE analysis failed: {str(e)}', 'is_valid_pe': False}
