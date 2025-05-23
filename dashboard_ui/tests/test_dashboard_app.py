import unittest
import json
import sys
import os

# Adjust path to import app from dashboard_ui
# This assumes tests directory is dashboard_ui/tests/
sys.path.append(os.path.join(os.path.dirname(__file__), '..')) # Add dashboard_ui to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..')) # Add project root to path for ransomware_analyzer

from app import app # From dashboard_ui.app

class TestDashboardApp(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.testing = True # Enable testing mode
        self.client = self.app.test_client()
        # Ensure that the dummy data provider functions are accessible
        # This might require ensuring ransomware_analyzer is in PYTHONPATH
        # or more robust path handling in app.py if tests are run from dashboard_ui/tests

    def test_index_route(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Ransomware Analyzer Dashboard", response.data) # Check for title or key content

    def test_api_recent_alerts_dummy(self):
        response = self.client.get('/api/recent_alerts')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data.decode('utf-8'))
        self.assertIsInstance(data, list)
        if data: # If list is not empty
            self.assertIn('id', data[0])
            self.assertIn('filepath', data[0])
            self.assertIn('threat_level', data[0])

    def test_api_stats_dummy(self):
        response = self.client.get('/api/stats')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data.decode('utf-8'))
        self.assertIsInstance(data, dict)
        self.assertIn('total_files_scanned', data)
        self.assertIn('system_status', data)

if __name__ == '__main__':
    unittest.main()
