import socket
import struct
import argparse
import logging
import sys

# Configure logging to output to the console
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def calculate_checksum(data):
    """Calculate the standard IP/ICMP checksum."""
    if len(data) % 2 == 1:
        data += b'\0'
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def create_icmp_frag_needed_packet(mtu=1200):
    """
    Crafts an ICMP Type 3 (Destination Unreachable),
    Code 4 (Fragmentation Needed) packet.
    """
    icmp_type = 3
    icmp_code = 4
    checksum = 0
    unused = 0

    # RFC 1191: Next-Hop MTU is placed in the last 16 bits of the header
    # Format: ! (network byte order), B (1 byte), B (1 byte), H (2 bytes), H (2 bytes), H (2 bytes)
    header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, unused, mtu)

    # RFC 792 dictates ICMP error messages should contain the original IP header
    # and first 8 bytes of the original datagram. Because a standard UDP socket
    # doesn't capture the IP header, we append a 28-byte dummy payload to satisfy
    # the structural requirement of the protocol.
    dummy_original_packet = b'\x00' * 28

    # Calculate checksum with header and data
    checksum = calculate_checksum(header + dummy_original_packet)

    # Repack the header with the correct checksum
    header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, unused, mtu)

    return header + dummy_original_packet

def main():
    parser = argparse.ArgumentParser(description="UDP Listener that responds with ICMP Fragment Needed.")
    parser.add_argument('-p', '--port', type=int, required=True, help="UDP port to bind and listen on.")
    parser.add_argument('-m', '--mtu', type=int, default=1200, help="Next-Hop MTU to advertise in the ICMP packet (default: 1200).")
    args = parser.parse_args()

    # 1. Set up the UDP listening socket
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        udp_sock.bind(('0.0.0.0', args.port))
        logging.info(f"Successfully bound to UDP 0.0.0.0:{args.port}")
    except PermissionError:
        logging.error(f"Permission denied binding to port {args.port}. Try a port > 1024.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Failed to bind UDP socket: {e}")
        sys.exit(1)

    # 2. Set up the RAW socket for sending ICMP
    try:
        # IPPROTO_ICMP allows us to send raw ICMP packets
        icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        logging.info("Raw ICMP socket created successfully.")
    except PermissionError:
        logging.error("Permission denied creating raw socket. You MUST run this script as root/sudo.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Failed to create raw ICMP socket: {e}")
        sys.exit(1)

    logging.info(f"Listening for incoming UDP traffic... Advertising MTU {args.mtu} on error.")

    # 3. Main Loop
    try:
        while True:
            # Wait for incoming UDP traffic
            data, addr = udp_sock.recvfrom(4096)
            sender_ip = addr[0]
            sender_port = addr[1]

            logging.info(f"Received {len(data)} bytes from {sender_ip}:{sender_port}. Sending ICMP Frag Needed...")

            # Craft and send the ICMP response
            icmp_packet = create_icmp_frag_needed_packet(mtu=args.mtu)

            try:
                # Send the raw packet to the source IP
                icmp_sock.sendto(icmp_packet, (sender_ip, 1)) # The port parameter (1) is ignored for raw sockets
                logging.info(f"ICMP Fragment Needed (Type 3, Code 4) sent to {sender_ip}")
            except Exception as e:
                logging.error(f"Failed to send ICMP packet to {sender_ip}: {e}")

    except KeyboardInterrupt:
        logging.info("Shutting down gracefully...")
    finally:
        udp_sock.close()
        icmp_sock.close()

if __name__ == "__main__":
    main()
