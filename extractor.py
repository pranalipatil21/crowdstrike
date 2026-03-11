import pefile
import hashlib
import math

def calculate_entropy(data):
    if not data: return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def get_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def extract_pe_features(file_path):
    try:
        pe = pefile.PE(file_path)
        # 13 Core Features for the ML Model
        features = [
            pe.FILE_HEADER.Machine, pe.FILE_HEADER.SizeOfOptionalHeader,
            pe.FILE_HEADER.Characteristics, pe.OPTIONAL_HEADER.MajorLinkerVersion,
            pe.OPTIONAL_HEADER.MinorLinkerVersion, pe.OPTIONAL_HEADER.SizeOfCode,
            pe.OPTIONAL_HEADER.SizeOfInitializedData, pe.OPTIONAL_HEADER.SizeOfUninitializedData,
            pe.OPTIONAL_HEADER.AddressOfEntryPoint, pe.OPTIONAL_HEADER.BaseOfCode,
            pe.OPTIONAL_HEADER.ImageBase, pe.OPTIONAL_HEADER.SectionAlignment,
            pe.OPTIONAL_HEADER.FileAlignment
        ]
        
        # Additional Security Metrics
        with open(file_path, "rb") as f:
            raw_data = f.read()
        
        entropy = calculate_entropy(raw_data)
        file_hash = get_file_hash(file_path)
        
        pe.close()
        return features, entropy, file_hash
    except:
        return None, None, None