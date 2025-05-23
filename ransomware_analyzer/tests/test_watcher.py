import unittest
from unittest.mock import MagicMock, patch
import os
import shutil
import time # For potential sleep if testing async behavior, though direct calls are better
import logging
from watchdog.events import FileSystemEvent # To create mock events

from ransomware_analyzer.realtime_monitor.watcher import AnalysisEventHandler, file_checksums_cache
from ransomware_analyzer.ml_model.predictor import RansomwarePredictor
from ransomware_analyzer.incident_response.actions import isolate_file, DEFAULT_QUARANTINE_DIR
from ransomware_analyzer.threat_detection.analyzer import calculate_threat_score, analyze_file, get_file_hash, KNOWN_RANSOMWARE_HASHES
from ransomware_analyzer.logger_config import setup_logging

# Test setup
TEST_WATCH_DIR = "test_watch_directory"
TEST_QUARANTINE_BASE = "test_quarantine_zone" # Use a test-specific quarantine

class TestRealtimeMonitor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        setup_logging(log_level=logging.DEBUG, log_file="test_watcher.log")
        if os.path.exists(TEST_WATCH_DIR):
            shutil.rmtree(TEST_WATCH_DIR)
        os.makedirs(TEST_WATCH_DIR, exist_ok=True)
        
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        cls.test_quarantine_full_path = os.path.join(project_root, TEST_QUARANTINE_BASE)


    @classmethod
    def tearDownClass(cls):
        if os.path.exists(TEST_WATCH_DIR):
            shutil.rmtree(TEST_WATCH_DIR)
        if os.path.exists(cls.test_quarantine_full_path): # Clean up test quarantine
            shutil.rmtree(cls.test_quarantine_full_path)
        if os.path.exists("test_watcher.log"):
            os.remove("test_watcher.log")

    def setUp(self):
        file_checksums_cache.clear()
        if os.path.exists(TEST_WATCH_DIR):
            shutil.rmtree(TEST_WATCH_DIR)
        os.makedirs(TEST_WATCH_DIR)
        
        if os.path.exists(self.test_quarantine_full_path):
             shutil.rmtree(self.test_quarantine_full_path)
        os.makedirs(self.test_quarantine_full_path, exist_ok=True)

        self.handler = AnalysisEventHandler()
        
        self.patcher = patch('ransomware_analyzer.incident_response.actions.DEFAULT_QUARANTINE_DIR', TEST_QUARANTINE_BASE)
        self.mock_default_quarantine = self.patcher.start()


    def tearDown(self):
        self.patcher.stop()


    def _create_dummy_file(self, filename, content="dummy content"):
        filepath = os.path.join(TEST_WATCH_DIR, filename)
        with open(filepath, "w") as f:
            f.write(content)
        return filepath

    def test_on_created_clean_file(self):
        filepath = self._create_dummy_file("clean.txt", "This is a safe file.")
        event = FileSystemEvent(filepath)
        event.is_directory = False
        
        with self.assertLogs(logger='RansomwareAnalyzer', level='INFO') as cm:
            self.handler.on_created(event)
        
        self.assertTrue(any("Analysis for new file" in log_msg and "File seems clean" in log_msg for log_msg in cm.output))
        self.assertTrue(any("Calculated Threat Score" in log_msg and "Score: 5" in log_msg for log_msg in cm.output))
        self.assertIn(filepath, file_checksums_cache)

    def test_on_created_suspicious_hash_and_isolate(self):
        filename = "evil_hash.exe"
        filepath = self._create_dummy_file(filename, "this is very evil content")
        file_hash = get_file_hash(filepath)
        
        original_hashes = KNOWN_RANSOMWARE_HASHES.copy()
        KNOWN_RANSOMWARE_HASHES[file_hash] = "Test.EvilHashWare"
        
        event = FileSystemEvent(filepath)
        event.is_directory = False
        
        with self.assertLogs(logger='RansomwareAnalyzer', level='INFO') as cm:
            self.handler.on_created(event)
        
        KNOWN_RANSOMWARE_HASHES.clear()
        KNOWN_RANSOMWARE_HASHES.update(original_hashes)

        self.assertTrue(any("Known ransomware hash match" in log_msg for log_msg in cm.output))
        self.assertTrue(any(f"Calculated Threat Score for {filepath}: 95" in log_msg for log_msg in cm.output))
        self.assertTrue(any(f"High threat detected for {filepath} by hash match. Attempting isolation." in log_msg for log_msg in cm.output))
        self.assertTrue(any(f"File '{filepath}' isolated to" in log_msg for log_msg in cm.output))
        
        self.assertFalse(os.path.exists(filepath))
        
        expected_quarantined_file_path_part = os.path.join(TEST_QUARANTINE_BASE, filename, filename)
        self.assertTrue(any(expected_quarantined_file_path_part in log_msg for log_msg in cm.output), "Did not find expected quarantine path in logs")
            
        found_in_quarantine = False
        for root, _, files in os.walk(self.test_quarantine_full_path):
            if filename in files:
                found_in_quarantine = True
                break
        self.assertTrue(found_in_quarantine, f"File {filename} not found in test quarantine {self.test_quarantine_full_path}")
        self.assertNotIn(filepath, file_checksums_cache)

    def test_on_modified_checksum_change_behavioral(self):
        filename = "changing_file.dat" # Uncommon extension
        filepath = self._create_dummy_file(filename, "initial content")
        initial_hash = get_file_hash(filepath)
        file_checksums_cache[filepath] = initial_hash

        time.sleep(0.01) 
        with open(filepath, "w") as f:
            f.write("modified content makes it suspicious")
        
        event = FileSystemEvent(filepath)
        event.is_directory = False
        
        with self.assertLogs(logger='RansomwareAnalyzer', level='INFO') as cm:
            self.handler.on_modified(event)
        
        self.assertTrue(any("Behavioral analysis for" in log_msg and "Potential unauthorized encryption activity" in log_msg for log_msg in cm.output))
        self.assertTrue(any(f"Calculated Threat Score for {filepath}: 70" in log_msg for log_msg in cm.output))
        current_file_hash = file_checksums_cache.get(filepath)
        self.assertIsNotNone(current_file_hash)
        self.assertNotEqual(current_file_hash, initial_hash)

if __name__ == '__main__':
    unittest.main()
