import dnslib.server
import dnslib, socket, struct, threading, ipaddress

class DNSResolver(dnslib.server.BaseResolver):
    def __init__(self, local_ip, domains, txt_response=''):
        self.local_ip = local_ip
        self.txt_response = txt_response
        self.domains = domains

    def resolve(self, request, handler):
        reply = request.reply()
        qname = request.q.qname
        qtype = request.q.qtype

        for domain in self.domains:
            if qname == domain: 
                if qtype == dnslib.QTYPE.A:
                    reply.add_answer(dnslib.RR(qname, dnslib.QTYPE.A, rdata=dnslib.A(self.local_ip)))
                else:
                    print('are we here?')
                    reply.header.rcode = dnslib.RCODE.NXDOMAIN
            
            if qname == "_acme-challenge." + domain or qname == "_acme-challenge." + domain[2:]:
                if qtype == dnslib.QTYPE.TXT:
                    reply.add_answer(dnslib.RR(qname, dnslib.QTYPE.TXT, rdata=dnslib.TXT(self.txt_response)))
                else:
                    reply.header.rcode = dnslib.RCODE.NXDOMAIN

        return reply

def start_dns_server(event, event_queue, record, domains):
    global EVENT_QUEUE, RESOLVER
    EVENT_QUEUE = event_queue
    local_ip = record 

    RESOLVER = DNSResolver(local_ip, domains)
    server = dnslib.server.DNSServer(RESOLVER, port=10053, address=record)

    server_thread = threading.Thread(target=server.start_thread, daemon=True)
    server_thread.start()

    worker_thread = threading.Thread(target=handle_update, args=(event,), daemon=True)
    worker_thread.start()

    print("DNS server is running...")
    print("THE DNS SERVER IS RESOLVING ALL RECORDS TO: ", local_ip)


def handle_update(event):
    while True:
        event.wait()
        print("dns update event received!")
        while not EVENT_QUEUE.empty():
            (identifier, resource) = EVENT_QUEUE.get()
            print("update is: ", (identifier, resource))
            domain = identifier['value']
            print("domain is; ", domain)
            RESOLVER.txt_response = resource
        event.clear()
        print("dns update complete")
