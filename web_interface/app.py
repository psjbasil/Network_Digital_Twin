from flask import Flask, render_template
from flask_socketio import SocketIO
from digital_twin.network_model import NetworkModel
from digital_twin.visualizer import NetworkVisualizer
import threading
import time

app = Flask(__name__)
socketio = SocketIO(app)
network_model = NetworkModel()
visualizer = NetworkVisualizer()

def update_topology_periodically():
    while True:
        if network_model.update_topology():
            visualizer.visualize(
                network_model.graph,
                'web_interface/static/topology.png'
            )
            socketio.emit('topology_updated')
        time.sleep(10)

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    update_thread = threading.Thread(target=update_topology_periodically)
    update_thread.daemon = True
    update_thread.start()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000) 