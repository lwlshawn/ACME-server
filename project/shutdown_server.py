from flask import Flask

app = Flask(__name__)

@app.route('/')
def homepage():
    return "shutdown server lives"

@app.route('/shutdown', methods=['GET'])
def shutdown():
    SHUTDOWN_EVENT.set()
    return "shutting down"

def start_shutdown_server(shutdown_event, address):
    global SHUTDOWN_EVENT
    SHUTDOWN_EVENT = shutdown_event
    print("SHUTDOWN SERVER IS RUNNING ON: ", address)
    print("AT PORT: ", 5003)
    app.run(host=address, debug=False, port=5003)
