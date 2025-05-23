import unittest
import os
from ransomware_analyzer.threat_detection.analyzer import analyze_file

class TestAnalyzer(unittest.TestCase):
    DUMMY_FILES_DIR = "ransomware_analyzer/tests/dummy_files"

    def setUp(self):
        if not os.path.exists(self.DUMMY_FILES_DIR):
            os.makedirs(self.DUMMY_FILES_DIR)

    def tearDown(self):
        # Clean up dummy files after each test if necessary,
        # or use a class-level cleanup if files are created once per class.
        # For now, we create and delete within each test.
        pass

    def test_clean_file(self):
        filepath = os.path.join(self.DUMMY_FILES_DIR, "clean.txt")
        with open(filepath, "w") as f:
            f.write("This is a safe file.")
        result = analyze_file(filepath)
        self.assertEqual(result, "File seems clean")
        os.remove(filepath)

    def test_suspicious_extension(self):
        filepath = os.path.join(self.DUMMY_FILES_DIR, "test.locky")
        open(filepath, "w").close() # Create an empty file
        result = analyze_file(filepath)
        self.assertEqual(result, "Suspicious: Known ransomware extension")
        os.remove(filepath)

    def test_suspicious_content(self):
        filepath = os.path.join(self.DUMMY_FILES_DIR, "suspicious_content.txt")
        with open(filepath, "w") as f:
            f.write("RANSOMWARE_SIGNATURE_TEST")
        result = analyze_file(filepath)
        self.assertEqual(result, "Suspicious: Known ransomware signature pattern found")
        os.remove(filepath)

    def test_suspicious_extension_and_content(self):
        filepath = os.path.join(self.DUMMY_FILES_DIR, "suspicious_both.locky")
        with open(filepath, "w") as f:
            f.write("RANSOMWARE_SIGNATURE_TEST")
        # The extension check is performed first in the current implementation
        result = analyze_file(filepath)
        self.assertEqual(result, "Suspicious: Known ransomware extension")
        os.remove(filepath)

if __name__ == '__main__':
    unittest.main()
