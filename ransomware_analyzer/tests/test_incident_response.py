import unittest
import os
import shutil
import logging
from ransomware_analyzer.incident_response.actions import isolate_file, DEFAULT_QUARANTINE_DIR
from ransomware_analyzer.logger_config import setup_logging # If logs are checked

TEST_ISOLATE_DIR = "test_isolation_source_dir"
TEST_QUARANTINE_IR_BASE = "test_quarantine_ir" # Test-specific quarantine

class TestIncidentResponse(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        setup_logging(log_level=logging.DEBUG, log_file="test_incident_response.log")
        # Determine project root to set up TEST_QUARANTINE_IR_BASE correctly
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        cls.test_quarantine_full_path = os.path.join(project_root, TEST_QUARANTINE_IR_BASE)

    def setUp(self):
        os.makedirs(TEST_ISOLATE_DIR, exist_ok=True)
        # Clean and recreate test quarantine for each test
        if os.path.exists(self.test_quarantine_full_path):
            shutil.rmtree(self.test_quarantine_full_path)
        os.makedirs(self.test_quarantine_full_path, exist_ok=True)

    def tearDown(self):
        if os.path.exists(TEST_ISOLATE_DIR):
            shutil.rmtree(TEST_ISOLATE_DIR)
        if os.path.exists(self.test_quarantine_full_path):
            shutil.rmtree(self.test_quarantine_full_path)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists("test_incident_response.log"):
            os.remove("test_incident_response.log")

    def _create_dummy_file_for_isolation(self, filename="to_be_isolated.txt"):
        filepath = os.path.join(TEST_ISOLATE_DIR, filename)
        with open(filepath, "w") as f:
            f.write("quarantine me")
        return filepath

    def test_isolate_file_success(self):
        filename_to_isolate = "test_move.txt" # Renamed for clarity
        filepath = self._create_dummy_file_for_isolation(filename_to_isolate)
        self.assertTrue(os.path.exists(filepath))
        
        with self.assertLogs(logger='RansomwareAnalyzer.IncidentResponse', level='INFO') as cm:
            # Pass the test-specific quarantine base path
            self.assertTrue(isolate_file(filepath, quarantine_dir_base=self.test_quarantine_full_path))
        
        self.assertFalse(os.path.exists(filepath)) 
        
        # Check if file exists in the test quarantine directory structure
        # isolate_file creates a sub-folder named after the file, then places the file in it
        # e.g. test_quarantine_ir/test_move.txt/test_move.txt
        expected_quarantined_file_path = os.path.join(self.test_quarantine_full_path, filename_to_isolate, filename_to_isolate)
        self.assertTrue(os.path.exists(expected_quarantined_file_path), f"Expected file not found at {expected_quarantined_file_path}")
        self.assertTrue(any(f"File '{filepath}' isolated to" in log for log in cm.output))

    def test_isolate_file_source_not_found(self):
        non_existent_filepath = "non_existent_file.txt" # Made path relative for this test case
        with self.assertLogs(logger='RansomwareAnalyzer.IncidentResponse', level='ERROR') as cm:
            self.assertFalse(isolate_file(non_existent_filepath, quarantine_dir_base=self.test_quarantine_full_path))
        self.assertTrue(any(f"Source file '{non_existent_filepath}' not found" in log for log in cm.output))

if __name__ == '__main__': # Added main execution block
    unittest.main()
