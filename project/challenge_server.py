import threading
from flask import Flask

app = Flask(__name__)

@app.route('/.well-known/acme-challenge/<challenge_token>', methods=['GET'])
def acme_challenge(challenge_token):
    return RESOURCES[challenge_token]

@app.route('/')
def homepage():
    return "challenge server lives"

def start_challenge_server(event, event_queue, address):
    global EVENT_QUEUE, RESOURCES
    EVENT_QUEUE = event_queue
    RESOURCES = {}

    worker_thread = threading.Thread(target=handle_update, args=(event,), daemon=True)
    worker_thread.start()
    
    print("CHALLENGE SERVER IS RUNNING ON: ", address)
    print("AT PORT: ", 5002)
    app.run(host=address, debug=False, port=5002)


def handle_update(event):
    while True:
        event.wait()
        print("http update event received!")
        while not EVENT_QUEUE.empty():
            (token, resource) = EVENT_QUEUE.get()
            RESOURCES[token] = resource
        print("http updates complete!")
        event.clear()