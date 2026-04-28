import socket
import struct
import argparse
import logging
import sys
import select

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)

SO_BINDTODEVICE = 25
ETH_P_IPV6 = 0x86DD

def craft_icmpv6_error(mtu, original_ipv6_packet):
    # ICMPv6 Packet Too Big must not make the total packet exceed min IPv6 MTU (1280)
    # 40 bytes (IPv6 header) + 8 bytes (ICMPv6 header) = 48 bytes.
    # 1280 - 48 = 1232 bytes maximum for the original packet payload.
    safe_payload = original_ipv6_packet[:1232]
    
    icmp_type = 2  # Packet Too Big
    icmp_code = 0
    checksum = 0   # The kernel calculates the ICMPv6 pseudo-header checksum for us!
    
    # Pack: Type (1 byte), Code (1 byte), Checksum (2 bytes), MTU (4 bytes)
    header = struct.pack('!BBHI', icmp_type, icmp_code, checksum, mtu)
    
    return header + safe_payload

def main():
    parser = argparse.ArgumentParser(description="Raw UDPv6 Sniffer and ICMPv6 Packet Too Big Responder.")
    parser.add_argument('-i', '--interface', required=True, help="Network interface to bind to (e.g., eth0).")
    parser.add_argument('-m', '--mtu', type=int, default=1280, help="Next-Hop MTU to advertise (default: 1280, the IPv6 minimum).")
    parser.add_argument('-p', '--port', type=int, help="Optional: UDPv6 port to bind and silently absorb traffic.")
    args = parser.parse_args()

    # 1. Set up the RAW receiving socket (L2 AF_PACKET to retain the IPv6 header)
    try:
        raw_recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_IPV6))
        raw_recv_sock.bind((args.interface, 0))
        logging.info(f"Listening for IPv6 traffic on L2 interface: {args.interface}")
    except PermissionError:
        logging.error("Permission denied. You MUST run this script as root/sudo.")
        sys.exit(1)
    except OSError as e:
        logging.error(f"Failed to bind to interface {args.interface}: {e}")
        sys.exit(1)

    # 2. Set up the RAW sending socket (L3 AF_INET6)
    try:
        icmp_send_sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
        icmp_send_sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, args.interface.encode('utf-8'))
    except Exception as e:
        logging.error(f"Failed to create raw ICMPv6 socket: {e}")
        sys.exit(1)

    # 3. Set up the Dummy absorbing socket (if requested)
    dummy_sock = None
    sockets_to_monitor = [raw_recv_sock]
    
    if args.port:
        try:
            dummy_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            dummy_sock.bind(('::', args.port))
            sockets_to_monitor.append(dummy_sock)
            logging.info(f"Bound dummy UDPv6 socket on port {args.port} to suppress 'Port Unreachable' messages.")
        except Exception as e:
            logging.error(f"Failed to bind dummy socket on port {args.port}: {e}")
            sys.exit(1)

    logging.info(f"Monitoring... Advertising MTU {args.mtu} on UDPv6 intercept.")

    # 4. Main Event Loop using Select
    try:
        while True:
            readable, _, _ = select.select(sockets_to_monitor, [], [])
            
            for sock in readable:
                if sock is dummy_sock:
                    sock.recvfrom(65535)
                    
                elif sock is raw_recv_sock:
                    packet, addr = raw_recv_sock.recvfrom(65535)
                    
                    # Strip the 14-byte Ethernet header to isolate the IPv6 packet
                    ipv6_packet = packet[14:]
                    
                    if len(ipv6_packet) < 40: # Ignore malformed/tiny packets
                        continue
                        
                    # Check if the IP version is 6
                    version = ipv6_packet[0] >> 4
                    if version != 6:
                        continue

                    # Check Next Header field (Byte 6). 
                    # Note: This assumes no IPv6 Extension Headers are present before the UDP header for simplicity.
                    next_header = ipv6_packet[6]
                    if next_header != 17: # 17 is UDP
                        continue

                    # Extract the Source IPv6 address (Bytes 8-23)
                    sender_ip_bytes = ipv6_packet[8:24]
                    sender_ip = socket.inet_ntop(socket.AF_INET6, sender_ip_bytes)
                    
                    logging.info(f"Intercepted UDPv6 packet from {sender_ip}. Crafting ICMPv6 reply...")
                    
                    icmp_packet = craft_icmpv6_error(args.mtu, ipv6_packet)
                    
                    try:
                        # Flowinfo and Scope ID are set to 0 in the address tuple
                        icmp_send_sock.sendto(icmp_packet, (sender_ip, 0, 0, 0))
                        logging.info(f"-> Sent ICMPv6 Packet Too Big to {sender_ip}")
                    except Exception as e:
                        logging.error(f"Failed to send ICMPv6 to {sender_ip}: {e}")
                        
    except KeyboardInterrupt:
        logging.info("\nShutting down gracefully...")
    finally:
        raw_recv_sock.close()
        icmp_send_sock.close()
        if dummy_sock:
            dummy_sock.close()

if __name__ == "__main__":
    main()
