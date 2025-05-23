import hashlib
import sys # For printing to stderr, to be replaced by logging
import logging

# TODO: Integrate machine learning model for advanced signature analysis

logger = logging.getLogger("RansomwareAnalyzer")

KNOWN_RANSOMWARE_HASHES = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "Generic.Ransom.ExampleA",
    "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b": "Specific.Trojan.Lockbit模仿",
    "c1f1fb33973ab85466906e9fd419397b316678008050180080c030e010a010a0": "DummyWare.Crypt",
    "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2": "Generic.Ransom.ExampleB" # Added another one
}

def get_file_hash(filepath):
    """
    Calculates the SHA256 hash of a file's content.
    """
    try:
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            # Read and update hash string value in blocks of 4K
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        logger.error(f"File not found at {filepath}")
        return None
    except Exception as e:
        logger.error(f"Error hashing file {filepath}: {e}")
        return None

def analyze_file(filepath):
    """
    Analyzes a file for ransomware signatures, including hash matching.
    """
    # Current order of checks:
    # 1. Hash check: Strongest indicator, done first. Requires full file read.
    #    A match here is a high-confidence detection.
    # 2. Extension check: Very fast, good for quick filtering or flagging
    #    files that are commonly associated with ransomware.
    # 3. Content pattern check: Requires file read (currently partial - first 100 bytes).
    #    This order prioritizes definitive (hash) and then quick checks (extension)
    #    before more content-based analysis.
    #
    # Future considerations:
    # If performance for non-hit cases on very large files becomes an issue,
    # and content check remains partial (e.g., first N bytes/KB),
    # the order: Extension -> Partial Content -> Full Hash might be considered.
    # This would avoid a full file read for hashing if a quick check already yields a result.
    # However, a positive hash match is a very strong signal, justifying its current primary position.

    # TODO: Potential optimization: If multiple checks require reading significant
    # portions of the file (e.g., if content check needed more than just the first 100 bytes,
    # or if other content-based analyses were added), consider reading the file content
    # once (or in chunks) and passing it to helper functions.
    # This would avoid multiple I/O operations on the same file.
    # Currently, get_file_hash reads the full file, and the content check below reads the first 100 bytes.
    # The overhead of reading the first 100 bytes again after a full file read for hashing is minor.

    logger.info(f"Starting signature analysis for file: {filepath}")
    file_hash = get_file_hash(filepath) # Uses 'with open', ensuring file handle closure.

    if file_hash is None:
        logger.error(f"Error analyzing file {filepath}: File not accessible for hashing")
        return "Error: File not accessible for analysis"

    if file_hash in KNOWN_RANSOMWARE_HASHES:
        threat_name = KNOWN_RANSOMWARE_HASHES[file_hash]
        message = f"Suspicious: Known ransomware hash match (Threat: {threat_name}) for file: {filepath}"
        logger.critical(message)
        return message

    ransomware_extensions = ['.locky', '.wannacry', '.ryuk']
    for ext in ransomware_extensions:
        if filepath.endswith(ext):
            message = f"Suspicious: Known ransomware extension for file: {filepath}"
            logger.warning(message)
            return message

    try:
        # Uses 'with open', ensuring file handle closure.
        with open(filepath, 'rb') as f:
            file_content = f.read(100) # Read first 100 bytes for signature pattern
            if b"RANSOMWARE_SIGNATURE_TEST" in file_content:
                message = f"Suspicious: Known ransomware signature pattern found in file: {filepath}"
                logger.warning(message)
                return message
    except FileNotFoundError:
        # This case should ideally be caught by get_file_hash,
        # but kept for robustness in case analyze_file is called directly
        # with a path that becomes inaccessible after the hash check.
        logger.error(f"File not found at {filepath} during content check.")
        return "Error: File not accessible for content analysis"
    except Exception as e:
        logger.error(f"Error reading file {filepath} for content analysis: {e}")
        return "Error: Could not perform content analysis"

    logger.info(f"File seems clean: {filepath}")
    return "File seems clean"

import os

COMMON_EXTENSIONS = [
    '.txt', '.docx', '.xlsx', '.pptx', '.zip', '.rar', '.jpg', '.png', '.gif',
    '.mp3', '.mp4', '.exe', '.dll', '.py', '.js', '.html', '.css', '.pdf', '.log',
    '.csv', '.json', '.xml', '.ini', '.cfg', '.iso', '.tar', '.gz', '.7z', '.bak',
    '.tmp', '.temp', '.lnk', '.sys', '.drv', '.bat', '.sh', '.ps1'
]

def analyze_file_modification(filepath, original_checksum=None, current_checksum=None):
    """
    Analyzes file modifications based on checksums and file type to detect suspicious activity.
    """
    logger.info(f"Starting file modification analysis for: {filepath}")
    _, ext = os.path.splitext(filepath)
    ext = ext.lower()

    if original_checksum and current_checksum and original_checksum != current_checksum:
        if ext not in COMMON_EXTENSIONS and ext: # Check if ext is not empty (unknown extension)
            message = f"Suspicious: Potential unauthorized encryption activity detected on '{filepath}' (checksum changed on uncommon file type)."
            logger.warning(message)
            return message
        else: # Checksum changed on a common file type or a file with no extension
            message = f"Warning: File '{filepath}' has been modified (checksum changed). Needs further investigation if unexpected."
            logger.warning(message)
            return message
    elif current_checksum and not original_checksum: # New file or monitoring started post-creation
        if ext not in COMMON_EXTENSIONS and ext: # Check if ext is not empty
            message = f"Info: New file '{filepath}' with uncommon extension detected. Monitor for further changes."
            logger.info(message)
            return message
        # No specific message if a new file with a common extension is created, covered by the final return.
    
    # Covers cases:
    # 1. original_checksum and current_checksum are the same.
    # 2. Only original_checksum is provided (not a typical scenario for this function's logic).
    # 3. Neither checksum is provided.
    # 4. New file with common extension (current_checksum provided, original_checksum is None, ext in COMMON_EXTENSIONS)
    message = f"Info: No suspicious modification detected for '{filepath}' based on provided checksums."
    logger.info(message)
    return message
