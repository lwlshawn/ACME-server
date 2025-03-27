import socket

def ipv4_to_ipv6_mapped(ipv4_address):
    try:
        # Convert the IPv4 address to its 32-bit integer representation
        ipv4_int = int(socket.inet_aton(ipv4_address).hex(), 16)

        # Create the equivalent IPv6 address in the ::ffff:IPv4 format
        ipv6_address = f"::ffff:{ipv4_int:04X}"

        return ipv6_address
    except (socket.error, ValueError):
        return None

# Example usage:
ipv4_address = "127.0.0.1"
ipv6_mapped_address = ipv4_to_ipv6_mapped(ipv4_address)

if ipv6_mapped_address:
    print(f"IPv4 Address: {ipv4_address}")
    print(f"IPv6 Mapped Address: {ipv6_mapped_address}")
else:
    print("Invalid IPv4 address.")