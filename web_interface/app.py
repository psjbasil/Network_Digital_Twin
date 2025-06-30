import os
import sys
import requests
import json
import threading
import time
import logging

# Add project root directory to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from flask import Flask, render_template, send_from_directory, jsonify
from flask_socketio import SocketIO, emit
from werkzeug.serving import WSGIRequestHandler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# Set log levels to suppress frequent access logs - simple approach
logging.getLogger('werkzeug').setLevel(logging.WARNING)  # Only warnings/errors
logging.getLogger('engineio').setLevel(logging.WARNING)
logging.getLogger('socketio').setLevel(logging.WARNING)
logging.getLogger('geventwebsocket').setLevel(logging.WARNING)

app = Flask(__name__, 
            static_folder='static',
            static_url_path='/static')

# Optimize SocketIO configuration
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='gevent',  # Use gevent as async mode
    ping_timeout=10,
    ping_interval=5,
    max_http_buffer_size=1024 * 1024,  # Increase buffer size
    logger=False,  # Disable SocketIO internal logging
    engineio_logger=False  # Disable Engine.IO internal logging
)

# Ensure static directory exists
os.makedirs('web_interface/static', exist_ok=True)

# Controller configuration
controller_base_url = "http://localhost:8080"

class TopologyUpdater:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
            return cls._instance
    
    def __init__(self):
        if not hasattr(self, 'initialized'):
            self.error_count = 0
            self.max_errors = 3
            self.base_interval = 0.1
            self.max_interval = 0.5
            self.current_interval = self.base_interval
            self.controller_url = "http://localhost:8080/topology"
            self.last_topology = None
            self.last_topology_hash = None
            self.last_hosts_state = {}  # Add host state tracking
            self._lock = threading.Lock()
            self.initialized = True
            
            self.update_thread = threading.Thread(target=self._update_loop, daemon=True)
            self.update_thread.start()
            
            self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
            self.heartbeat_thread.start()

    def _get_topology(self):
        try:
            response = requests.get(self.controller_url, timeout=1)  # Reduce timeout
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 204 and self.last_topology:
                return self.last_topology
            else:
                response = requests.get(self.controller_url + "?force=true", timeout=1)
                return response.json() if response.status_code == 200 else None
        except Exception as e:
            logger.error(f"Error getting topology data: {str(e)}")
            return None

    def _get_topology_hash(self, topology):
        """Calculate hash of topology data, excluding host IP addresses"""
        if not topology:
            return None
        
        # Create a copy of topology data, remove host IP information
        topology_copy = json.loads(json.dumps(topology))
        if 'hosts' in topology_copy:
            for host in topology_copy['hosts']:
                if 'ip' in host:
                    del host['ip']
        
        return hash(json.dumps(topology_copy, sort_keys=True))

    def _check_hosts_changes(self, topology):
        """Check if host IPs have changed"""
        if not topology or 'hosts' not in topology:
            return False
        
        current_hosts_state = {
            host['mac']: host.get('ip', '')
            for host in topology['hosts']
        }
        
        has_changes = current_hosts_state != self.last_hosts_state
        self.last_hosts_state = current_hosts_state
        return has_changes

    def _emit_topology_update(self, topology_data, current_hash):
        """Thread-safe topology update emission"""
        with self._lock:
            hosts_changed = self._check_hosts_changes(topology_data)
            topology_changed = current_hash != self.last_topology_hash
            
            if topology_changed or hosts_changed:
                socketio.emit('topology_update', {
                    'topology': topology_data,
                    'timestamp': time.time()
                }, namespace='/')
                self.last_topology = topology_data
                self.last_topology_hash = current_hash

    def _update_loop(self):
        while True:
            try:
                topology_data = self._get_topology()
                if topology_data:
                    current_hash = self._get_topology_hash(topology_data)
                    self._emit_topology_update(topology_data, current_hash)
                time.sleep(self.base_interval)
            except Exception as e:
                logger.error(f"Update loop error: {str(e)}")
                time.sleep(self.current_interval)

    def _heartbeat_loop(self):
        """Keep WebSocket connection alive"""
        while True:
            try:
                socketio.sleep(5)
                if self.last_topology:
                    socketio.emit('heartbeat', {'timestamp': time.time()})
                    # Removed frequent heartbeat log
            except Exception as e:
                logger.error(f"Heartbeat error: {str(e)}")
                time.sleep(1)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    # Client connection events are too frequent for logging
    try:
        updater = TopologyUpdater()
        topology = updater._get_topology()
        if topology:
            current_hash = updater._get_topology_hash(topology)
            updater._emit_topology_update(topology, current_hash)
        else:
            # Try to force get topology
            response = requests.get(updater.controller_url + "?force=true")
            if response.status_code == 200:
                topology = response.json()
                updater._emit_topology_update(topology, updater._get_topology_hash(topology))
                updater.last_topology = topology
                logger.info("Initial topology sent to client (forced)")
            else:
                logger.error("Failed to get initial topology")
    except Exception as e:
        logger.error(f"Error sending initial topology data: {str(e)}")

@app.route('/topology')
def get_topology():
    """Get topology data"""
    try:
        updater = TopologyUpdater()
        topology = updater._get_topology()
        if topology:
            return jsonify(topology)
        else:
            # Try to force get topology
            response = requests.get(updater.controller_url + "?force=true")
            if response.status_code == 200:
                topology = response.json()
                updater._emit_topology_update(topology, updater._get_topology_hash(topology))
                updater.last_topology = topology
                return jsonify(topology)
            else:
                return jsonify({'error': 'Failed to get topology'}), 404
    except Exception as e:
        logger.error(f"Error getting topology: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/traffic')
def get_traffic():
    """Get traffic statistics data"""
    try:
        response = requests.get(f"{controller_base_url}/traffic", timeout=5)
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            logger.error(f"Controller traffic API returned status {response.status_code}")
            return jsonify({'error': f'Controller returned status {response.status_code}'}), response.status_code
    except requests.exceptions.RequestException as e:
        logger.error(f"Error connecting to controller traffic API: {str(e)}")
        return jsonify({'error': 'Failed to connect to controller', 'details': str(e)}), 503
    except Exception as e:
        logger.error(f"Error getting traffic data: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/traffic/summary')
def get_traffic_summary():
    """Get traffic summary statistics"""
    try:
        response = requests.get(f"{controller_base_url}/traffic/summary", timeout=5)
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            logger.error(f"Controller traffic summary API returned status {response.status_code}")
            return jsonify({'error': f'Controller returned status {response.status_code}'}), response.status_code
    except requests.exceptions.RequestException as e:
        logger.error(f"Error connecting to controller traffic summary API: {str(e)}")
        return jsonify({'error': 'Failed to connect to controller', 'details': str(e)}), 503
    except Exception as e:
        logger.error(f"Error getting traffic summary: {str(e)}")
        return jsonify({'error': str(e)}), 500

@socketio.on('request_topology')
def handle_topology_request():
    """Handle client topology request"""
    try:
        updater = TopologyUpdater()
        topology = updater._get_topology()
        if topology:
            current_hash = updater._get_topology_hash(topology)
            updater._emit_topology_update(topology, current_hash)
        else:
            # Try to force get topology
            response = requests.get(updater.controller_url + "?force=true")
            if response.status_code == 200:
                topology = response.json()
                updater._emit_topology_update(topology, updater._get_topology_hash(topology))
                updater.last_topology = topology
                logger.info("Initial topology sent to client (forced)")
            else:
                logger.error("Failed to get initial topology")
    except Exception as e:
        logger.error(f"Error handling topology request: {str(e)}")
        emit('topology_error', {'message': str(e)})

if __name__ == '__main__':
    WSGIRequestHandler.protocol_version = "HTTP/1.1"
    updater = TopologyUpdater()
    # Run server with gevent
    socketio.run(
        app,
        host='0.0.0.0',
        port=5000,
        debug=False,  # Disable debug mode
        use_reloader=False,
        log_output=False  # Disable HTTP request logging
    ) 