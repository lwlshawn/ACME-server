from flask import Flask
import ssl, requests

app = Flask(__name__)

@app.route('/', methods=['GET'])
def homepage():
    return "CERTIFICATE SERVER LIVESSSSS"

def start_certificate_server(key_path, certificate_path, address):
    loc = "pebble" # change to pebble when pushing to server for tests

    r = requests.get(f"https://{loc}:15000/intermediates/0", verify="pebble.minica.pem")
    print(r.content)

    with open("intermediate.pem", 'w') as output:
        output.write(r.content.decode())

    r = requests.get(f"https://{loc}:15000/roots/0", verify="pebble.minica.pem")
    print(r.content)

    with open("root.pem", 'w') as output:
        output.write(r.content.decode())

    # combine the four certificates into a single certificate
    certificates = [certificate_path, "pebble.minica.pem", "intermediate.pem", "root.pem"]
    combined_cert = ""
    for certificate in certificates:
        with open(certificate, 'r') as file:
            combined_cert += file.read()
    
    with open("combined_certificate.pem", 'w') as output:
        output.write(combined_cert)

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="combined_certificate.pem", keyfile=key_path)
    print("CERTIFICATE SERVER IS RUNNING ON: ", address)
    print("AT PORT: ", 5001)

    app.run(host=address, port=5001, debug=False, ssl_context=context)