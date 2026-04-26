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

def calculate_checksum(data):
    if len(data) % 2 == 1:
        data += b'\0'
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def craft_icmp_error(mtu, original_packet):
    # if len(original_packet) < mtu:
    #     return None

    icmp_type = 3
    icmp_code = 4
    checksum = 0
    unused = 0
    
    # Slice the original packet headers for the ICMP payload
    ihl = (original_packet[0] & 0x0F) * 4
    rfc792_data = original_packet[:ihl + 8]
    
    header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, unused, mtu)
    checksum = calculate_checksum(header + rfc792_data)
    header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, unused, mtu)
    
    return header + rfc792_data

def main():
    parser = argparse.ArgumentParser(description="Raw UDP Sniffer and ICMP Frag Needed Responder.")
    parser.add_argument('-i', '--interface', required=True, help="Network interface to bind to (e.g., br0testvm).")
    parser.add_argument('-m', '--mtu', type=int, default=1200, help="Next-Hop MTU to advertise (default: 1200).")
    parser.add_argument('-p', '--port', type=int, help="Optional: UDP port to bind and silently absorb traffic (prevents Port Unreachable errors).")
    args = parser.parse_args()

    # 1. Set up the RAW receiving socket
    try:
        raw_recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        raw_recv_sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, args.interface.encode('utf-8'))
        logging.info(f"Listening for UDP traffic on interface: {args.interface}")
    except PermissionError:
        logging.error("Permission denied. You MUST run this script as root/sudo.")
        sys.exit(1)
    except OSError as e:
        logging.error(f"Failed to bind to interface {args.interface}: {e}")
        sys.exit(1)

    # 2. Set up the RAW sending socket
    try:
        icmp_send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except Exception as e:
        logging.error(f"Failed to create raw ICMP socket: {e}")
        sys.exit(1)

    # 3. Set up the Dummy absorbing socket (if requested)
    dummy_sock = None
    sockets_to_monitor = [raw_recv_sock]
    
    if args.port:
        try:
            dummy_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            dummy_sock.bind(('0.0.0.0', args.port))
            sockets_to_monitor.append(dummy_sock)
            logging.info(f"Bound dummy UDP socket on port {args.port} to suppress 'Port Unreachable' messages.")
        except Exception as e:
            logging.error(f"Failed to bind dummy socket on port {args.port}: {e}")
            sys.exit(1)

    logging.info(f"Monitoring... Advertising MTU {args.mtu} on UDP intercept.")

    # 4. Main Event Loop using Select
    try:
        while True:
            # select() blocks until one or more of our sockets actually has data to read
            readable, _, _ = select.select(sockets_to_monitor, [], [])
            
            for sock in readable:
                if sock is dummy_sock:
                    # We don't care about this data. We just read it to empty the kernel buffer 
                    # so it doesn't overflow, and silently discard it.
                    sock.recvfrom(65535)
                    
                elif sock is raw_recv_sock:
                    # Process the actual raw packet for our ICMP reply
                    packet, addr = raw_recv_sock.recvfrom(65535)
                    sender_ip = addr[0]
                    
                    logging.info(f"Intercepted UDP packet from {sender_ip}. Crafting ICMP reply...")
                    
                    icmp_packet = craft_icmp_error(args.mtu, packet)
                    if icmp_packet is None:
                        logging.info("Skipped sending ICMP response")
                        continue
                    
                    try:
                        icmp_send_sock.sendto(icmp_packet, (sender_ip, 1))
                        logging.info(f"-> Sent ICMP Fragment Needed to {sender_ip}")
                    except Exception as e:
                        logging.error(f"Failed to send ICMP to {sender_ip}: {e}")
                        
    except KeyboardInterrupt:
        logging.info("\nShutting down gracefully...")
    finally:
        raw_recv_sock.close()
        icmp_send_sock.close()
        if dummy_sock:
            dummy_sock.close()

if __name__ == "__main__":
    main()
