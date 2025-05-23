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
    Reads file in chunks to efficiently hash large files without loading entirely into memory.
    """
    sha256_hasher = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(4096) # Read in 4KB chunks
                if not chunk:
                    break
                sha256_hasher.update(chunk)
        return sha256_hasher.hexdigest()
    except FileNotFoundError:
        logger.error(f"File not found during hashing: {filepath}", extra={'filepath': filepath})
        return None
    except OSError as e: # Catch other potential I/O errors
        logger.error(f"OS error during hashing of file {filepath}: {e}", extra={'filepath': filepath, 'error': str(e)})
        return None
    except Exception as e: # Catch any other unexpected errors
        logger.error(f"Unexpected error hashing file {filepath}: {e}", extra={'filepath': filepath, 'error': str(e)})
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
        # Content check is limited to the first 100 bytes for performance and to quickly find known markers
        # if present at the beginning of the file.
        # TODO: Consider more extensive content scanning for future versions, though this has performance implications.
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

# --- Threat Scoring Logic ---

# Assuming logger is already configured at the module level or obtained
# logger = logging.getLogger("RansomwareAnalyzer.Scoring")
# Re-using the existing module logger, or you can define a new one.
# For consistency with the existing pattern in this file:
logger_scoring = logging.getLogger("RansomwareAnalyzer.Scoring")


# Define score constants (can be tuned)
SCORE_KNOWN_HASH = 95
SCORE_ML_SUSPICIOUS_HIGH_CONF = 90 # For ML results with high confidence
SCORE_ML_SUSPICIOUS_MED_CONF = 75  # For ML results with medium confidence
SCORE_BEHAVIORAL_MODIFICATION_UNCOMMON = 70 # From analyze_file_modification
SCORE_CONTENT_PATTERN = 65
SCORE_BEHAVIORAL_MODIFICATION_COMMON = 50
SCORE_SUSPICIOUS_EXTENSION = 45
SCORE_ML_SUSPICIOUS_LOW_CONF = 40 # For ML results with low confidence
SCORE_DEFAULT_CLEAN = 5

def calculate_threat_score(analysis_result_str=None, ml_result_dict=None, behavioral_result_str=None):
    """
    Calculates a threat score based on various analysis inputs.
    Inputs are expected to be the string outputs from analyze_file, 
    the dictionary from predict_ransomware_behavior, and string from analyze_file_modification.
    """
    final_score = 0
    reasons = []

    # 1. Score from analyze_file output string
    if analysis_result_str:
        if "Known ransomware hash match" in analysis_result_str:
            final_score = max(final_score, SCORE_KNOWN_HASH)
            reasons.append(f"Known Hash (Score: {SCORE_KNOWN_HASH})")
        elif "Suspicious: Known ransomware signature pattern found" in analysis_result_str:
            final_score = max(final_score, SCORE_CONTENT_PATTERN)
            reasons.append(f"Content Pattern (Score: {SCORE_CONTENT_PATTERN})")
        elif "Suspicious: Known ransomware extension" in analysis_result_str:
            final_score = max(final_score, SCORE_SUSPICIOUS_EXTENSION)
            reasons.append(f"Suspicious Extension (Score: {SCORE_SUSPICIOUS_EXTENSION})")
        elif "File seems clean" in analysis_result_str:
            # Only apply if no other suspicious indicators push score higher
            if final_score < SCORE_DEFAULT_CLEAN: # Check if it's still at initial 0 or a very low score
                 final_score = SCORE_DEFAULT_CLEAN
            reasons.append(f"Clean by basic scan (Score: {SCORE_DEFAULT_CLEAN})")


    # 2. Score from ML model result dictionary
    if ml_result_dict and isinstance(ml_result_dict, dict) and ml_result_dict.get('is_suspicious'):
        confidence = ml_result_dict.get('confidence', 0.0)
        if confidence >= 0.8: # High confidence
            final_score = max(final_score, SCORE_ML_SUSPICIOUS_HIGH_CONF)
            reasons.append(f"ML High Confidence (Score: {SCORE_ML_SUSPICIOUS_HIGH_CONF}, Conf: {confidence:.2f})")
        elif confidence >= 0.5: # Medium confidence
            final_score = max(final_score, SCORE_ML_SUSPICIOUS_MED_CONF)
            reasons.append(f"ML Medium Confidence (Score: {SCORE_ML_SUSPICIOUS_MED_CONF}, Conf: {confidence:.2f})")
        else: # Low confidence
            final_score = max(final_score, SCORE_ML_SUSPICIOUS_LOW_CONF)
            reasons.append(f"ML Low Confidence (Score: {SCORE_ML_SUSPICIOUS_LOW_CONF}, Conf: {confidence:.2f})")
    
    # 3. Score from behavioral analysis (analyze_file_modification output string)
    if behavioral_result_str:
        if "Potential unauthorized encryption activity detected on" in behavioral_result_str and "uncommon file type" in behavioral_result_str :
            final_score = max(final_score, SCORE_BEHAVIORAL_MODIFICATION_UNCOMMON)
            reasons.append(f"Behavioral - Uncommon Mod (Score: {SCORE_BEHAVIORAL_MODIFICATION_UNCOMMON})")
        elif "File" in behavioral_result_str and "has been modified (checksum changed)" in behavioral_result_str:
            final_score = max(final_score, SCORE_BEHAVIORAL_MODIFICATION_COMMON)
            reasons.append(f"Behavioral - Common Mod (Score: {SCORE_BEHAVIORAL_MODIFICATION_COMMON})")


    if not reasons and final_score == 0: # Default for no information or truly clean and no explicit clean flags hit
        reasons.append("No specific threat indicators found.")
        # Ensure final_score reflects the default clean score if it's still 0
        final_score = SCORE_DEFAULT_CLEAN 

    # Ensure the lowest score is SCORE_DEFAULT_CLEAN if no threat indicators found
    # and it wasn't already set by "File seems clean" logic
    if not reasons or (len(reasons) == 1 and "Clean by basic scan" in reasons[0] and final_score < SCORE_DEFAULT_CLEAN):
         if final_score < SCORE_DEFAULT_CLEAN: # Handles case where final_score might be 0
            final_score = SCORE_DEFAULT_CLEAN
    
    # Correct the case where "Clean by basic scan" might be the only reason but final_score is 0
    if final_score == 0 and any("Clean by basic scan" in r for r in reasons):
        final_score = SCORE_DEFAULT_CLEAN
    
    # If truly no reasons and score is 0, it means no analysis yielded anything, default to clean.
    if not reasons and final_score == 0:
        reasons.append(f"No specific threat indicators found (Score: {SCORE_DEFAULT_CLEAN})")
        final_score = SCORE_DEFAULT_CLEAN


    logger_scoring.info(f"Threat score calculated: {final_score}. Reasons: {'; '.join(reasons) or 'N/A'}")
    return final_score, reasons
