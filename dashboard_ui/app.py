from flask import Flask, render_template, jsonify
import sys
import os

# Adjust path to import from the ransomware_analyzer package
# This assumes dashboard_ui is parallel to ransomware_analyzer
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from ransomware_analyzer.api_data_provider import get_recent_alerts_dummy, get_stats_dummy # Placeholder import

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html', title='Ransomware Analyzer Dashboard')

@app.route('/api/recent_alerts')
def recent_alerts():
    alerts = get_recent_alerts_dummy() # Use the imported function
    return jsonify(alerts)

@app.route('/api/stats')
def stats():
    stats_data = get_stats_dummy() # Use the imported function
    return jsonify(stats_data)

if __name__ == '__main__':
    # Note: For development, Flask's built-in server is fine.
    # For production, a proper WSGI server (e.g., Gunicorn) should be used.
    app.run(debug=True, port=5001) # Running on a different port, e.g. 5001
