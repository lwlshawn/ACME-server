import requests, json, threading, time, queue, click
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from challenge_server import start_challenge_server
from certificate_server import start_certificate_server
from shutdown_server import start_shutdown_server
from dns_server import start_dns_server
from cryptography.hazmat.backends import default_backend

def urlsafe_b64decode_helper(s):
    return urlsafe_b64decode(s + '=' * (4 - len(s) % 4))

# Generating the key and jwk at the beginning
PRIVATE_KEY = ec.generate_private_key(
    ec.SECP256R1
)
PUBLIC_KEY = PRIVATE_KEY.public_key()
PUBLIC_KEY_NUMBERS = PUBLIC_KEY.public_numbers()
CONST_X = PUBLIC_KEY_NUMBERS.x
CONST_Y = PUBLIC_KEY_NUMBERS.y

# Take the integer, convert it to bytes, strip trailing '=', then convert to a string to put into structure
CONST_X_STR = urlsafe_b64encode(CONST_X.to_bytes(32, 'big')).rstrip(b'=').decode()
CONST_Y_STR = urlsafe_b64encode(CONST_Y.to_bytes(32, 'big')).rstrip(b'=').decode()
CONST_JWK = {"crv":"P-256","kty":"EC","x":CONST_X_STR,"y":CONST_Y_STR}

NONCE = ''
CONST_KID = ''
ORDER_LOCATION = ''
EVENT_QUEUE = queue.Queue()

def request_nonce(nonce_url):
    global NONCE
    nonce_request = requests.head(nonce_url, verify="pebble.minica.pem")
    NONCE = nonce_request.headers['Replay-Nonce']

def create_jws(header_json, payload):
    ### JSON inputs should be created with separators=(',', ':') to remove whitespace and newlines
    jws_header_bytes = urlsafe_b64encode(header_json.encode()).rstrip(b'=')
    jws_payload_bytes = urlsafe_b64encode(payload.encode()).rstrip(b'=')

    # ##### SIGNING
    data = jws_header_bytes + b'.' + jws_payload_bytes
    signature = PRIVATE_KEY.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )
    (r, s) = decode_dss_signature(signature)
    r_bytes = r.to_bytes(32, 'big')
    s_bytes = s.to_bytes(32, 'big')
    rs = r_bytes + s_bytes
    rs_encoded = urlsafe_b64encode(rs).rstrip(b'=')

    rs_str = rs_encoded.decode()
    header_str = jws_header_bytes.decode()
    payload_str = jws_payload_bytes.decode()
    final_payload = json.dumps({"payload":payload_str,"protected":header_str,"signature":rs_str},
                            separators=(',',':'))
    
    return final_payload

def generate_jws_header_with_jwk(url):
    global NONCE

    header_json = json.dumps(
        {
        "alg":"ES256",
        "jwk":CONST_JWK,
        "nonce":NONCE,
        "url":url,
        },separators=(',', ':')
        )
    return header_json

def generate_jws_header_with_kid(url):
    global NONCE, CONST_KID

    header_json = json.dumps(
        {
        "alg":"ES256",
        "kid":CONST_KID,
        "nonce":NONCE,
        "url":url,
        },separators=(',', ':')
        )
    return header_json

def create_new_account(newaccount_url):
    global CONST_KID
    ##### HEADER
    header_json = generate_jws_header_with_jwk(newaccount_url)
    
    ##### PAYLOAD
    payload = json.dumps(
        {"termsOfServiceAgreed":True}, separators=(',', ':'))

    r = send_post_request(header_json, payload, newaccount_url)
    CONST_KID = r.headers['Location']

    return r.json()

def create_new_order(neworder_url, domains):
    global ORDER_LOCATION
    ##### HEADER
    header_json = generate_jws_header_with_kid(neworder_url)

    ##### PAYLOAD
    ## have to figure out how to programmatically create this payload_json later
    identifiers = []
    for domain in domains:
        identifiers.append({"type":"dns", "value":domain})
    payload = json.dumps(
        {
            "identifiers":identifiers
        }, separators=(',', ':'))
    r = send_post_request(header_json, payload, neworder_url)
    ORDER_LOCATION = r.headers['Location']
    return r.json()

def send_post_request(header_json, payload, target_url, log=False):
    global NONCE

    jws_payload = create_jws(header_json, payload)
    headers = {'Content-Type':'application/jose+json'}
    r = requests.post(target_url, data=jws_payload, headers=headers, verify="pebble.minica.pem")

    NONCE = r.headers['Replay-Nonce']

    if log:
        print("LOGGING REQUEST")
        print(r.headers)
        print()
        print(r.content)
        print()
    return r

def compute_key_authorization(token):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(json.dumps(CONST_JWK,separators=(',',':')).encode())
    thumbprint = digest.finalize()
    key_authorization = token.encode() + b'.' + urlsafe_b64encode(thumbprint).rstrip(b'=')
    return key_authorization

def complete_http_challenge(challenge, event):
    print("COMPLETE HTTP CHALLENGE CALLED")
    # takes in a challenge object
    response_url = challenge['url']
    token = challenge['token']

    # first i generate the resource and the path to it
    challenge_resource = compute_key_authorization(token).decode()

    # update the http-challenge-server
    EVENT_QUEUE.put((token, challenge_resource))
    event.set()
    time.sleep(2)

    # respond to the response_url to tell the ACME server to check
    header_json = generate_jws_header_with_kid(response_url)    
    payload = json.dumps({})
    send_post_request(header_json, payload, response_url)

    # check the status of the challenge? -> post as get to the response url
    print("CHECKING STATUS OF CHALLENGE")
    header_json = generate_jws_header_with_kid(response_url)
    payload = ''
    challenge_json = send_post_request(header_json, payload, response_url).json()

    while challenge_json['status'] == 'processing':
        time.sleep(1)
        header_json = generate_jws_header_with_kid(response_url)
        payload = ''
        challenge_json = send_post_request(header_json, payload, response_url).json()


def complete_http_challenges(order_json, event):
    print("COMPLETING HTTP CHALLENGES")
    # takes in an Order Object from the ACME server
    for i in range(len(order_json["authorizations"])):
        # for each Authorization URL and the corresponding identifier
        url = order_json["authorizations"][i]
        header_json = generate_jws_header_with_kid(url)
        payload = ""
        r = send_post_request(header_json, payload, url)
        authorization_json = r.json()

        identifier = authorization_json['identifier']
        
        # now we find the http-01 challenge from the Authorization Object, and complete it
        for challenge in authorization_json['challenges']:
            if challenge['type'] == 'http-01':
                complete_http_challenge(challenge, event)


def finalize_order(order, domains):
    print("FINALISING ORDER")
    jws_header = generate_jws_header_with_kid(ORDER_LOCATION)
    payload = ''
    order_json = send_post_request(jws_header, payload, ORDER_LOCATION).json()

    while order_json['status'] != 'ready':
        if order_json['status'] == 'invalid':
            break

        jws_header = generate_jws_header_with_kid(ORDER_LOCATION)
        payload = ''
        order_json = send_post_request(jws_header, payload, ORDER_LOCATION).json()       

    if order_json['status'] == 'invalid':
        return

    test_private_key = ec.generate_private_key(
        ec.SECP256R1
    )

    SANS = [x509.DNSName(domain) for domain in domains]

    # creating the csr
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).add_extension(
        x509.SubjectAlternativeName(SANS),
        critical=False,
    # Sign the CSR with our private key.
    ).sign(test_private_key, hashes.SHA256())
    
    # csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).add_extension(
    #     x509.SubjectAlternativeName([
    #         # Describe what sites we want this certificate for.
    #         x509.DNSName("www.example.org"),
    #     ]),
    #     critical=False,
    # # Sign the CSR with our private key.
    # ).sign(test_private_key, hashes.SHA256())

    der_csr = csr.public_bytes(serialization.Encoding.DER)
    encoded_der_csr = urlsafe_b64encode(der_csr).rstrip(b'=')

    order_finalize_url = order['finalize']

    jws_header = generate_jws_header_with_kid(order_finalize_url)
    payload = json.dumps({"csr":encoded_der_csr.decode()})
    send_post_request(jws_header, payload, order_finalize_url)

    with open("private_key.pem", "wb") as private_key_file:
        private_key_pem = test_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key_file.write(private_key_pem)
    

def download_certificates():
    global CERTIFICATE
    print("CHECKING UPDATED ORDER")
    header_json = generate_jws_header_with_kid(ORDER_LOCATION)
    payload = ''
    ## so this correctly locates the order
    ## now we just have to download the cert
    r = send_post_request(header_json, payload, ORDER_LOCATION)
    updated_order = r.json()
    time.sleep(2)

    while 'certificate' not in updated_order:
        if updated_order['status'] == 'invalid':
            return

        header_json = generate_jws_header_with_kid(ORDER_LOCATION)
        payload = ''
        r = send_post_request(header_json, payload, ORDER_LOCATION)
        updated_order = r.json()
        time.sleep(2)

    certificate_url = updated_order['certificate']
    jws_header = generate_jws_header_with_kid(certificate_url)
    payload = ''
    r = send_post_request(jws_header, payload, certificate_url)
    # r.content is the certificate in bytes

    CERTIFICATE = x509.load_pem_x509_certificate(r.content, default_backend())
    with open("certificate.pem", "wb") as certificate_file:
        certificate_pem = CERTIFICATE.public_bytes(encoding=serialization.Encoding.PEM)
        certificate_file.write(certificate_pem)
    

def process_dns_challenge(dns_challenge, event, domain): 
    # takes in a challenge object and computes update to dns server
    token = dns_challenge['token']

    # first i generate the resource
    key_authorization = compute_key_authorization(token)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(key_authorization)
    
    # now i need to tell my dns server to update its text record with this resource.
    dns_txt_record = urlsafe_b64encode(digest.finalize()).rstrip(b'=')
    # i need to also put the domain associated with the resource
    EVENT_QUEUE.put((domain, dns_txt_record))
    event.set()
    return

def complete_dns_challenges(order_json, event):
    # takes in an Order Object from the ACME server
    for i in range(len(order_json["authorizations"])):
        # for each Authorization URL and the corresponding identifier
        url = order_json["authorizations"][i]
        header_json = generate_jws_header_with_kid(url)
        payload = ""
        r = send_post_request(header_json, payload, url, False)
        authorization_json = r.json()

        identifier = authorization_json['identifier']
        if ('wildcard' in authorization_json) and authorization_json['wildcard']:
            print("WILDCARD DETECTED")
            identifier['value'] = '*.' + identifier['value']
        
        # now we find the DNS-01 challenge from the Authorization Object, and complete it
        for challenge in authorization_json['challenges']:
            if challenge['type'] == 'dns-01':
                complete_dns_challenge(challenge, event, identifier)

def complete_dns_challenge(challenge, event, identifier):
    print("SANITY CHECKS: ")
    print("complete_dns_challenge called with: ", challenge, ' ', event, ' ', identifier)
    process_dns_challenge(challenge, event, identifier)
    time.sleep(1)

    print("TELL SERVER TO VALIDATE CHALLENGE")
    response_url = challenge['url']
    header_json = generate_jws_header_with_kid(response_url)    
    payload = json.dumps({})
    send_post_request(header_json, payload, response_url, False)

    # check the status of the challenge? -> post as get to the response url
    print("CHECKING STATUS OF CHALLENGE")
    header_json = generate_jws_header_with_kid(response_url)
    payload = ''
    challenge_json = send_post_request(header_json, payload, response_url, False).json()

    while challenge_json['status'] == 'processing':
        time.sleep(1)
        header_json = generate_jws_header_with_kid(response_url)
        payload = ''
        challenge_json = send_post_request(header_json, payload, response_url, True).json()

def revoke_certificate(revoke_url):
    print("REVOKING CERTIFICATE")
    # certificate is stored in certificate.pem
    pem_certificate_file = 'certificate.pem'

    # Load the PEM certificate from the file
    with open(pem_certificate_file, 'rb') as pem_file:
        pem_certificate_data = pem_file.read()
    certificate = x509.load_pem_x509_certificate(pem_certificate_data, default_backend())

    # Convert the certificate to DER format
    der_certificate = certificate.public_bytes(encoding=serialization.Encoding.DER)

    # then encode in base64url and convert to string
    der_certificate_str = urlsafe_b64encode(der_certificate).rstrip(b'=').decode()

    header = generate_jws_header_with_kid(revoke_url)
    payload = json.dumps({"certificate":der_certificate_str}, separators=(',', ':'))
    r = send_post_request(header, payload, revoke_url)
    print("revoke response is: ", r)


@click.command()
@click.argument('challenge', type=str)
@click.option('--dir', type=str, help='Specify a directory')
@click.option('--record', type=str, help='Specify an IP address')
@click.option('--domain', type=str, multiple=True, help='Specify one or more domains')
@click.option('--revoke', type=bool, default=False, is_flag=True, help='Revoke access')
def obtain_certificate(challenge, dir, record, domain, revoke):
    # Your script logic here
    click.echo(f'Type of Challenge: {challenge}')
    click.echo(f'ACME Directory: {dir}')
    click.echo(f'IPv4 Record: {record}')
    click.echo(f'Domains: {domain}')
    click.echo(f'Revoke access: {revoke}')

    # starting up the dns_server, http_challenge_server, and shutdown_server
    dns_update_event = threading.Event()
    dns_server_thread = threading.Thread(target=start_dns_server, args=(dns_update_event, EVENT_QUEUE, record, domain), daemon=True)
    dns_server_thread.start()

    http_update_event = threading.Event()
    http_challenge_server_thread = threading.Thread(target=start_challenge_server, args=(http_update_event, EVENT_QUEUE, record), daemon=True)
    http_challenge_server_thread.start()

    shutdown_event = threading.Event()
    shutdown_thread = threading.Thread(target=start_shutdown_server, args=(shutdown_event, record,), daemon=True)
    shutdown_thread.start()

    time.sleep(3)

    ACME_DIR = dir
    ACME_URLS = requests.get(ACME_DIR, verify="pebble.minica.pem").json()

    NEWNONCE_URL = ACME_URLS['newNonce']
    NEWACCOUNT_URL = ACME_URLS['newAccount']
    NEWORDER_URL = ACME_URLS['newOrder']
    REVOKE_URL = ACME_URLS['revokeCert']
    KEYCHANGE_URL = ACME_URLS['keyChange']

    request_nonce(NEWNONCE_URL) 
    ACME_ACCOUNT = create_new_account(NEWACCOUNT_URL)

    # the order json object returned by ACME
    ORDER = create_new_order(NEWORDER_URL, domain) # i'm not sure if we actually need multiple orders to pass all testcases

    if challenge == 'dns01':
        complete_dns_challenges(ORDER, dns_update_event)
    elif challenge == 'http01':
        complete_http_challenges(ORDER, http_update_event)
    else:
        print("error")

    finalize_order(ORDER, domain)
    download_certificates() # downloads the certificate in a file called "certificate.pem"

    server_thread = threading.Thread(target=start_certificate_server, args=("private_key.pem", "certificate.pem", record), daemon=True)
    server_thread.start()

    if revoke:
        revoke_certificate(REVOKE_URL)

    shutdown_event.wait()


if __name__ == "__main__":
    obtain_certificate()