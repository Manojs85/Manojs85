import unittest
import os
import hashlib
import logging
import shutil # For rmtree
from ransomware_analyzer.threat_detection.analyzer import (
    analyze_file,
    KNOWN_RANSOMWARE_HASHES,
    get_file_hash,
    analyze_file_modification
)
from ransomware_analyzer.logger_config import setup_logging

class TestAnalyzer(unittest.TestCase):
    dummy_dir_path = "ransomware_analyzer/tests/dummy_files"
    test_log_file = "test_analyzer.log"

    @classmethod
    def setUpClass(cls):
        # Configure logging for tests to a separate file and DEBUG level
        setup_logging(log_level=logging.DEBUG, log_file=cls.test_log_file)
        # Ensure dummy directory exists at the start of the test suite
        if not os.path.exists(cls.dummy_dir_path):
            os.makedirs(cls.dummy_dir_path)

    @classmethod
    def tearDownClass(cls):
        # Clean up the dummy directory and test log file after all tests in the class
        if os.path.exists(cls.dummy_dir_path):
            shutil.rmtree(cls.dummy_dir_path)
        if os.path.exists(cls.test_log_file):
            os.remove(cls.test_log_file)

    def setUp(self):
        # This method is called before each test.
        # We ensure the dummy directory exists.
        # Individual tests will create files within this directory.
        if not os.path.exists(self.dummy_dir_path):
            os.makedirs(self.dummy_dir_path)

    def tearDown(self):
        # This method is called after each test.
        # Clean up files created by individual tests within the dummy directory.
        # This prevents tests from interfering with each other if they use same filenames.
        # For more robust cleanup, tests should manage their specific files.
        # Or, if setUp creates files for each test, tearDown should remove them.
        # For now, we rely on setUpClass/tearDownClass for the directory,
        # and tests manage their own created files.
        pass


    def test_clean_file(self):
        filepath = os.path.join(self.dummy_dir_path, "clean.txt")
        with open(filepath, "w") as f:
            f.write("This is a safe file.")
        result = analyze_file(filepath)
        self.assertEqual(result, "File seems clean")
        os.remove(filepath)

    def test_suspicious_extension(self):
        filepath = os.path.join(self.dummy_dir_path, "test.locky")
        with open(filepath, "w") as f: # Create an empty file, content doesn't matter for this test
            f.write("some content")
        result = analyze_file(filepath)
        # Ensure the hash is not in KNOWN_RANSOMWARE_HASHES if it's a new file
        file_hash = get_file_hash(filepath)
        self.assertNotIn(file_hash, KNOWN_RANSOMWARE_HASHES)
        self.assertEqual(result, "Suspicious: Known ransomware extension for file: " + filepath)
        os.remove(filepath)

    def test_suspicious_content(self):
        filepath = os.path.join(self.dummy_dir_path, "suspicious_content.txt")
        with open(filepath, "wb") as f: # Open in binary mode for content check
            f.write(b"This is some text RANSOMWARE_SIGNATURE_TEST and more text.")
        result = analyze_file(filepath)
        # Ensure the hash is not in KNOWN_RANSOMWARE_HASHES
        file_hash = get_file_hash(filepath)
        self.assertNotIn(file_hash, KNOWN_RANSOMWARE_HASHES)
        self.assertEqual(result, "Suspicious: Known ransomware signature pattern found in file: " + filepath)
        os.remove(filepath)

    def test_suspicious_extension_and_content(self):
        # This test verifies that hash check has priority, then extension.
        filepath = os.path.join(self.dummy_dir_path, "suspicious_both.locky")
        with open(filepath, "wb") as f:
            f.write(b"RANSOMWARE_SIGNATURE_TEST")
        
        file_hash = get_file_hash(filepath)
        self.assertNotIn(file_hash, KNOWN_RANSOMWARE_HASHES) # Ensure not a hash match

        result = analyze_file(filepath)
        # Hash check is first, if no match, then extension check.
        self.assertEqual(result, "Suspicious: Known ransomware extension for file: " + filepath)
        os.remove(filepath)

    def test_known_ransomware_hash(self):
        filepath = os.path.join(self.dummy_dir_path, "hash_test_malicious.dat")
        content = b"This is a test file that will have a known hash."
        with open(filepath, "wb") as f:
            f.write(content)

        calculated_hash = hashlib.sha256(content).hexdigest()
        
        # Temporarily add to KNOWN_RANSOMWARE_HASHES
        original_hashes = KNOWN_RANSOMWARE_HASHES.copy() # Keep a copy to restore
        KNOWN_RANSOMWARE_HASHES[calculated_hash] = "Test.Ransomware.Dynamic"
        
        try:
            result = analyze_file(filepath)
            expected_message = f"Suspicious: Known ransomware hash match (Threat: Test.Ransomware.Dynamic) for file: {filepath}"
            self.assertEqual(result, expected_message)
        finally:
            # Clean up: restore original KNOWN_RANSOMWARE_HASHES
            KNOWN_RANSOMWARE_HASHES.clear()
            KNOWN_RANSOMWARE_HASHES.update(original_hashes)
            
        os.remove(filepath)

    def test_unknown_hash_clean_file(self):
        filepath = os.path.join(self.dummy_dir_path, "unknown_hash_clean.txt")
        with open(filepath, "w") as f:
            f.write("This is a clean file with an unknown hash.")
        
        # Ensure its hash is NOT in KNOWN_RANSOMWARE_HASHES (highly unlikely for a new random file)
        file_hash = get_file_hash(filepath)
        self.assertNotIn(file_hash, KNOWN_RANSOMWARE_HASHES)
        
        result = analyze_file(filepath)
        self.assertEqual(result, "File seems clean")
        os.remove(filepath)

    # Tests for analyze_file_modification
    def test_analyze_file_modification_suspicious_uncommon_type(self):
        filepath = "test.uncommonext"
        result = analyze_file_modification(filepath, original_checksum="abc", current_checksum="def")
        expected = f"Suspicious: Potential unauthorized encryption activity detected on '{filepath}' (checksum changed on uncommon file type)."
        self.assertEqual(result, expected)

    def test_analyze_file_modification_warning_common_type(self):
        filepath = "test.docx"
        result = analyze_file_modification(filepath, original_checksum="abc", current_checksum="def")
        expected = f"Warning: File '{filepath}' has been modified (checksum changed). Needs further investigation if unexpected."
        self.assertEqual(result, expected)

    def test_analyze_file_modification_new_uncommon_file(self):
        filepath = "newfile.crypt"
        result = analyze_file_modification(filepath, current_checksum="xyz")
        expected = f"Info: New file '{filepath}' with uncommon extension detected. Monitor for further changes."
        self.assertEqual(result, expected)

    def test_analyze_file_modification_no_change(self):
        filepath = "stable.txt"
        result = analyze_file_modification(filepath, original_checksum="abc", current_checksum="abc")
        expected = f"Info: No suspicious modification detected for '{filepath}' based on provided checksums."
        self.assertEqual(result, expected)

    def test_logging_output(self):
        # Create a dummy suspicious file that will trigger a specific log message
        filepath_hash = os.path.join(self.dummy_dir_path, "log_test_hash.dat")
        content_hash = b"Content for hash log test"
        with open(filepath_hash, "wb") as f:
            f.write(content_hash)
        
        calculated_hash = hashlib.sha256(content_hash).hexdigest()
        original_hashes = KNOWN_RANSOMWARE_HASHES.copy()
        KNOWN_RANSOMWARE_HASHES[calculated_hash] = "LogTest.Ransomware"

        try:
            analyze_file(filepath_hash) # This action should generate logs
        finally:
            KNOWN_RANSOMWARE_HASHES.clear()
            KNOWN_RANSOMWARE_HASHES.update(original_hashes)
            os.remove(filepath_hash)

        filepath_ext = os.path.join(self.dummy_dir_path, "log_test_ext.locky")
        with open(filepath_ext, "w") as f:
            f.write("content")
        analyze_file(filepath_ext) # Another action
        os.remove(filepath_ext)

        # Check the content of the test log file
        self.assertTrue(os.path.exists(self.test_log_file))
        with open(self.test_log_file, 'r') as lf:
            log_content = lf.read()
        
        self.assertIn("Starting signature analysis for file", log_content)
        self.assertIn(f"Suspicious: Known ransomware hash match (Threat: LogTest.Ransomware) for file: {filepath_hash}", log_content)
        self.assertIn(f"Suspicious: Known ransomware extension for file: {filepath_ext}", log_content)
        self.assertIn("DEBUG", log_content) # Check if DEBUG level logs are present

    # Tests for calculate_threat_score
    def test_calculate_threat_score_hash_match(self):
        score, reasons = calculate_threat_score(analysis_result_str="Suspicious: Known ransomware hash match (Threat: TestWare)")
        self.assertEqual(score, 95) # SCORE_KNOWN_HASH
        self.assertIn("Known Hash", reasons[0])

    def test_calculate_threat_score_ml_high_confidence(self):
        score, reasons = calculate_threat_score(ml_result_dict={'is_suspicious': True, 'confidence': 0.9})
        self.assertEqual(score, 90) # SCORE_ML_SUSPICIOUS_HIGH_CONF
        self.assertIn("ML High Confidence", reasons[0])

    def test_calculate_threat_score_behavioral_uncommon(self):
        score, reasons = calculate_threat_score(behavioral_result_str="Suspicious: Potential unauthorized encryption activity detected on 'test.dat' (uncommon file type)")
        self.assertEqual(score, 70) # SCORE_BEHAVIORAL_MODIFICATION_UNCOMMON
        self.assertIn("Behavioral - Uncommon Mod", reasons[0])

    def test_calculate_threat_score_multiple_inputs(self):
        # Extension + ML Medium
        score, reasons = calculate_threat_score(
            analysis_result_str="Suspicious: Known ransomware extension",
            ml_result_dict={'is_suspicious': True, 'confidence': 0.6}
        )
        self.assertEqual(score, 75) # SCORE_ML_SUSPICIOUS_MED_CONF (higher than extension)
        self.assertTrue(any("ML Medium Confidence" in r for r in reasons))
        self.assertTrue(any("Suspicious Extension" in r for r in reasons))
        
    def test_calculate_threat_score_clean(self):
        score, reasons = calculate_threat_score(analysis_result_str="File seems clean")
        self.assertEqual(score, 5) # SCORE_DEFAULT_CLEAN
        self.assertIn("Clean by basic scan", reasons[0])

    def test_calculate_threat_score_no_input(self):
        score, reasons = calculate_threat_score()
        self.assertEqual(score, 5) # SCORE_DEFAULT_CLEAN
        self.assertIn("No specific threat indicators found", reasons[0])

    def test_get_file_hash_correctness_with_chunking(self):
        # Create a dummy file with some content
        dummy_filepath = os.path.join(self.dummy_dir_path, "chunk_test_file.dat")
        # Make it a bit larger than one chunk (e.g. > 4KB if chunk size is 4KB, let's use 8KB)
        test_content = b"This is some test content for hashing, " * (256 * 2) # Approx 8KB
        with open(dummy_filepath, "wb") as f:
            f.write(test_content)

        # Calculate hash using the chunked method from analyzer.py
        chunked_hash = get_file_hash(dummy_filepath)

        # Calculate hash using a simple full-read method for verification
        import hashlib
        expected_hash = hashlib.sha256(test_content).hexdigest()
        
        self.assertEqual(chunked_hash, expected_hash, "Hash from chunked method does not match expected hash.")
        os.remove(dummy_filepath)


if __name__ == '__main__':
    unittest.main()
