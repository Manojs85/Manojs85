# Placeholder module for providing data to the dashboard API
# In a real application, this would interact with a database or live data source.

def get_recent_alerts_dummy():
    return [
        {'id': 1, 'timestamp': '2023-10-27T10:00:00Z', 'filepath': '/path/to/suspicious_file.exe', 'threat_level': 'High', 'score': 95, 'details': 'Known ransomware hash match.'},
        {'id': 2, 'timestamp': '2023-10-27T10:05:00Z', 'filepath': '/path/to/another_file.dll', 'threat_level': 'Medium', 'score': 70, 'details': 'Suspicious modification detected.'},
        {'id': 3, 'timestamp': '2023-10-27T10:15:00Z', 'filepath': '/path/to/document.doc', 'threat_level': 'Low', 'score': 40, 'details': 'Uncommon file extension for this location.'}
    ]

def get_stats_dummy():
    return {
        'total_files_scanned': 10234,
        'threats_detected_today': 5,
        'files_quarantined_total': 12,
        'system_status': 'Monitoring Active - Healthy'
    }

if __name__ == '__main__':
    # For simple testing of this module
    print("Recent Alerts (Dummy):")
    for alert in get_recent_alerts_dummy():
        print(alert)
    print("\nStats (Dummy):")
    print(get_stats_dummy())
