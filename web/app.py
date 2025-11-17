"""
Flask web application for real-time scan monitoring
"""

import sys
from pathlib import Path
import asyncio
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import threading

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.framework import PentestFramework
from core.config import Config, Target
from core.logger import Logger
from core.session import SessionManager


app = Flask(__name__)
app.config['SECRET_KEY'] = 'pentest-framework-secret-key'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global framework instance
current_framework = None
current_thread = None


@app.route('/')
def index():
    """Dashboard page"""
    return render_template('dashboard.html')


@app.route('/api/plugins', methods=['GET'])
def get_plugins():
    """Get list of available plugins"""
    from core.plugin_loader import PluginLoader

    loader = PluginLoader()
    loader.discover_plugins()
    loader.load_all_plugins()

    return jsonify({
        'plugins': loader.get_plugin_info()
    })


@app.route('/api/sessions', methods=['GET'])
def get_sessions():
    """Get list of sessions"""
    manager = SessionManager()
    sessions = manager.list_sessions()

    return jsonify({
        'sessions': sessions[:20]  # Last 20 sessions
    })


@app.route('/api/session/<session_id>', methods=['GET'])
def get_session(session_id):
    """Get specific session details"""
    manager = SessionManager()
    session = manager.load_session(session_id)

    if not session:
        return jsonify({'error': 'Session not found'}), 404

    return jsonify(session.to_dict())


@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Start a new scan"""
    global current_framework, current_thread

    data = request.json

    target = data.get('target')
    mode = data.get('mode', 'normal')
    session_name = data.get('name')

    if not target:
        return jsonify({'error': 'Target is required'}), 400

    # Create configuration
    cfg = Config()
    cfg.set_scan_mode(mode)

    target_type = 'url' if target.startswith('http') else 'host'
    cfg.add_target(Target(
        name=target,
        type=target_type,
        value=target
    ))

    # Create logger
    logger = Logger()

    # Create framework
    framework = PentestFramework(config=cfg, logger=logger, session_name=session_name)
    framework.initialize()

    current_framework = framework

    # Run scan in background thread
    def run_scan():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(framework.run())
        loop.close()

        # Emit completion event
        socketio.emit('scan_complete', {
            'session_id': framework.session.session_id,
            'status': framework.session.status.value
        })

    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()

    current_thread = thread

    return jsonify({
        'status': 'started',
        'session_id': framework.session.session_id
    })


@app.route('/api/scan/status', methods=['GET'])
def get_scan_status():
    """Get current scan status"""
    global current_framework

    if not current_framework:
        return jsonify({'status': 'no_scan_running'})

    stats = current_framework.get_statistics()

    return jsonify({
        'status': 'running' if current_framework.is_running else 'idle',
        'session_id': current_framework.session.session_id,
        'statistics': stats
    })


@app.route('/api/scan/pause', methods=['POST'])
def pause_scan():
    """Pause the current scan"""
    global current_framework

    if not current_framework:
        return jsonify({'error': 'No scan running'}), 400

    current_framework.pause()

    return jsonify({'status': 'paused'})


@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    emit('connected', {'data': 'Connected to scan server'})


@socketio.on('request_status')
def handle_status_request():
    """Handle status request via WebSocket"""
    global current_framework

    if current_framework:
        stats = current_framework.get_statistics()
        emit('status_update', stats)
    else:
        emit('status_update', {'status': 'no_scan_running'})


def create_templates():
    """Create basic HTML template"""
    template_dir = Path(__file__).parent / 'templates'
    template_dir.mkdir(exist_ok=True)

    dashboard_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pentest Framework - Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #1a1a2e; color: #eee; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        h1 { font-size: 2em; }
        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 20px 0; }
        .card { background: #16213e; padding: 25px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
        .card h2 { color: #667eea; margin-bottom: 15px; }
        button { background: #667eea; color: white; border: none; padding: 12px 24px; border-radius: 6px; cursor: pointer; font-size: 1em; margin: 5px; }
        button:hover { background: #5568d3; }
        input, select { padding: 10px; border-radius: 6px; border: 1px solid #333; background: #0f1419; color: #eee; width: 100%; margin: 5px 0; }
        .stat { font-size: 2.5em; color: #667eea; font-weight: bold; }
        .status { padding: 8px 16px; border-radius: 20px; display: inline-block; margin: 10px 0; }
        .status.running { background: #28a745; }
        .status.idle { background: #6c757d; }
        .vuln-list { max-height: 400px; overflow-y: auto; }
        .vuln-item { background: #0f1419; padding: 15px; margin: 10px 0; border-left: 4px solid #dc3545; border-radius: 4px; }
        .severity { padding: 4px 12px; border-radius: 12px; color: white; font-size: 0.85em; font-weight: bold; }
        .severity.critical { background: #dc3545; }
        .severity.high { background: #fd7e14; }
        .severity.medium { background: #ffc107; color: #333; }
    </style>
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 Penetration Testing Framework</h1>
            <p>Real-time Security Assessment Dashboard</p>
        </header>

        <div class="dashboard">
            <div class="card">
                <h2>Start New Scan</h2>
                <input type="text" id="target" placeholder="Enter target URL or IP">
                <select id="mode">
                    <option value="safe">Safe Mode</option>
                    <option value="normal" selected>Normal Mode</option>
                    <option value="aggressive">Aggressive Mode</option>
                    <option value="stealth">Stealth Mode</option>
                </select>
                <input type="text" id="sessionName" placeholder="Session name (optional)">
                <button onclick="startScan()">Start Scan</button>
            </div>

            <div class="card">
                <h2>Scan Status</h2>
                <div class="status idle" id="status">Idle</div>
                <p><strong>Session:</strong> <span id="sessionId">-</span></p>
                <p><strong>Targets:</strong> <span class="stat" id="targets">0</span></p>
                <p><strong>Vulnerabilities:</strong> <span class="stat" id="vulns">0</span></p>
                <button onclick="pauseScan()">Pause Scan</button>
                <button onclick="refreshStatus()">Refresh</button>
            </div>

            <div class="card">
                <h2>Statistics</h2>
                <p><strong>Plugins Executed:</strong> <span id="plugins">0</span></p>
                <p><strong>Critical:</strong> <span style="color:#dc3545" id="critical">0</span></p>
                <p><strong>High:</strong> <span style="color:#fd7e14" id="high">0</span></p>
                <p><strong>Medium:</strong> <span style="color:#ffc107" id="medium">0</span></p>
            </div>
        </div>

        <div class="card">
            <h2>Recent Sessions</h2>
            <div id="sessions"></div>
            <button onclick="loadSessions()">Load Sessions</button>
        </div>
    </div>

    <script>
        const socket = io();

        socket.on('connect', () => {
            console.log('Connected to server');
        });

        socket.on('status_update', (data) => {
            updateDashboard(data);
        });

        socket.on('scan_complete', (data) => {
            alert('Scan completed! Session: ' + data.session_id);
            refreshStatus();
        });

        function startScan() {
            const target = document.getElementById('target').value;
            const mode = document.getElementById('mode').value;
            const name = document.getElementById('sessionName').value;

            if (!target) {
                alert('Please enter a target');
                return;
            }

            fetch('/api/scan/start', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({target, mode, name})
            })
            .then(res => res.json())
            .then(data => {
                document.getElementById('sessionId').textContent = data.session_id;
                document.getElementById('status').textContent = 'Running';
                document.getElementById('status').className = 'status running';
                setInterval(refreshStatus, 5000);
            })
            .catch(err => alert('Error starting scan: ' + err));
        }

        function refreshStatus() {
            fetch('/api/scan/status')
                .then(res => res.json())
                .then(updateDashboard);
        }

        function updateDashboard(data) {
            if (data.statistics) {
                document.getElementById('targets').textContent = data.statistics.total_targets || 0;
                document.getElementById('vulns').textContent = data.statistics.total_vulnerabilities || 0;
                document.getElementById('plugins').textContent = data.statistics.completed_plugins || 0;
                document.getElementById('critical').textContent = data.statistics.severity_counts?.critical || 0;
                document.getElementById('high').textContent = data.statistics.severity_counts?.high || 0;
                document.getElementById('medium').textContent = data.statistics.severity_counts?.medium || 0;
            }
        }

        function pauseScan() {
            fetch('/api/scan/pause', {method: 'POST'})
                .then(res => res.json())
                .then(data => alert('Scan paused'));
        }

        function loadSessions() {
            fetch('/api/sessions')
                .then(res => res.json())
                .then(data => {
                    const sessionsDiv = document.getElementById('sessions');
                    sessionsDiv.innerHTML = '';
                    data.sessions.forEach(session => {
                        const div = document.createElement('div');
                        div.className = 'vuln-item';
                        div.innerHTML = `
                            <strong>${session.name || session.session_id}</strong><br>
                            Status: ${session.status} | Vulns: ${session.total_vulnerabilities || 0}<br>
                            ${session.created_at}
                        `;
                        sessionsDiv.appendChild(div);
                    });
                });
        }

        // Auto-refresh status every 5 seconds
        setInterval(() => socket.emit('request_status'), 5000);
    </script>
</body>
</html>
    """

    with open(template_dir / 'dashboard.html', 'w') as f:
        f.write(dashboard_html)


def run_server(host='0.0.0.0', port=5000):
    """Run the web server"""
    create_templates()
    print(f"Starting web server on http://{host}:{port}")
    socketio.run(app, host=host, port=port, debug=False)


if __name__ == '__main__':
    run_server()
