from flask import Flask, render_template, request, jsonify
import threading
import time
import hashlib
import json
from collections import defaultdict, Counter
from capture import PacketCapture

app = Flask(__name__)

# Store results in memory (keyed by session id)
capture_sessions = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/capture', methods=['POST'])
def capture():
    data = request.json
    url = data.get('url', '').strip()
    duration = int(data.get('duration', 10))
    session_id = data.get('session_id', 'default')

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    if duration < 3 or duration > 30:
        duration = 10

    cap = PacketCapture(url, duration)
    result = cap.run()

    if 'error' in result:
        return jsonify(result), 500

    capture_sessions[session_id] = result
    return jsonify(result)

@app.route('/api/compare', methods=['POST'])
def compare():
    data = request.json
    session_a = data.get('session_a')
    session_b = data.get('session_b')

    if session_a not in capture_sessions or session_b not in capture_sessions:
        return jsonify({'error': 'One or both sessions not found. Capture both websites first.'}), 400

    a = capture_sessions[session_a]
    b = capture_sessions[session_b]

    comparison = compare_fingerprints(a, b)
    return jsonify(comparison)

def compare_fingerprints(a, b):
    def safe_div(x, y):
        return round(x / y, 4) if y else 0

    fp_a = a['fingerprint']
    fp_b = b['fingerprint']
    stats_a = a['stats']
    stats_b = b['stats']

    similarity_scores = []

    # Protocol similarity
    protos_a = set(a['charts']['protocols'].keys())
    protos_b = set(b['charts']['protocols'].keys())
    if protos_a or protos_b:
        overlap = len(protos_a & protos_b) / len(protos_a | protos_b)
        similarity_scores.append(overlap)

    # Packet size similarity (normalized)
    avg_a = stats_a.get('avg_packet_size', 0)
    avg_b = stats_b.get('avg_packet_size', 0)
    if avg_a and avg_b:
        diff = abs(avg_a - avg_b) / max(avg_a, avg_b)
        similarity_scores.append(1 - diff)

    # Total packets similarity
    pkts_a = stats_a.get('total_packets', 0)
    pkts_b = stats_b.get('total_packets', 0)
    if pkts_a and pkts_b:
        diff = abs(pkts_a - pkts_b) / max(pkts_a, pkts_b)
        similarity_scores.append(max(0, 1 - diff))

    overall_similarity = round(sum(similarity_scores) / len(similarity_scores) * 100, 1) if similarity_scores else 0

    return {
        'website_a': a['url'],
        'website_b': b['url'],
        'fingerprint_a': fp_a,
        'fingerprint_b': fp_b,
        'similarity_score': overall_similarity,
        'stats_a': stats_a,
        'stats_b': stats_b,
        'protocols_a': a['charts']['protocols'],
        'protocols_b': b['charts']['protocols'],
        'behavior_a': a['behavior'],
        'behavior_b': b['behavior'],
        'differences': {
            'avg_packet_size': {
                'a': stats_a.get('avg_packet_size', 0),
                'b': stats_b.get('avg_packet_size', 0)
            },
            'total_packets': {
                'a': stats_a.get('total_packets', 0),
                'b': stats_b.get('total_packets', 0)
            },
            'total_bytes': {
                'a': stats_a.get('total_bytes', 0),
                'b': stats_b.get('total_bytes', 0)
            },
            'unique_ports': {
                'a': stats_a.get('unique_ports', 0),
                'b': stats_b.get('unique_ports', 0)
            }
        }
    }

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
