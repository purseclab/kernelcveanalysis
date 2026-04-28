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

ETH_P_IPV6 = 0x86DD

def calculate_checksum(data):
    """Standard internet checksum (RFC 1071) used for ICMPv6."""
    if len(data) % 2 == 1:
        data += b'\0'
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def craft_l2_icmpv6_error(mtu, original_eth_frame):
    # 1. Parse original Ethernet header (14 bytes)
    eth_hdr = original_eth_frame[:14]
    orig_dst_mac, orig_src_mac, ethertype = struct.unpack('!6s6sH', eth_hdr)
    
    if ethertype != ETH_P_IPV6:
        return None
        
    original_ipv6_packet = original_eth_frame[14:]
    if len(original_ipv6_packet) < 40:
        return None
        
    # 2. Extract original IPs
    orig_src_ip = original_ipv6_packet[8:24]
    orig_dst_ip = original_ipv6_packet[24:40]
    
    # 3. Craft new Ethernet header (Swap MAC addresses)
    # The new destination MAC is the original sender's MAC.
    # The new source MAC is the original destination MAC.
    new_eth_hdr = struct.pack('!6s6sH', orig_src_mac, orig_dst_mac, ETH_P_IPV6)
    
    # 4. Craft ICMPv6 Payload (Max 1232 bytes of original IPv6 packet)
    safe_payload = original_ipv6_packet[:1232]
    
    # 5. Craft ICMPv6 Header (Type 2, Code 0)
    icmp_type = 2
    icmp_code = 0
    checksum = 0
    
    # Pack without checksum first
    icmp_hdr_no_csum = struct.pack('!BBHI', icmp_type, icmp_code, checksum, mtu)
    icmp_packet = icmp_hdr_no_csum + safe_payload
    
    # 6. Calculate ICMPv6 Checksum
    # ICMPv6 requires a pseudo-header for the checksum:
    # Src IP (16), Dst IP (16), Upper-Layer Packet Length (4), Next Header (3 bytes padding + 1 byte)
    icmp_len = len(icmp_packet)
    pseudo_hdr = orig_dst_ip + orig_src_ip + struct.pack('!I', icmp_len) + b'\x00\x00\x00\x3a' # 0x3a = 58 (ICMPv6)
    
    checksum = calculate_checksum(pseudo_hdr + icmp_packet)
    
    # Repack with the calculated checksum
    icmp_hdr = struct.pack('!BBHI', icmp_type, icmp_code, checksum, mtu)
    final_icmp = icmp_hdr + safe_payload
    
    # 7. Craft new IPv6 Header
    # Version 6, Traffic Class 0, Flow Label 0 -> 0x60000000
    vtc_flow = 0x60000000
    payload_len = len(final_icmp)
    next_header = 58 # ICMPv6
    hop_limit = 255
    
    # Notice the IPs are swapped: Source is the original Dest IP, Dest is the original Src IP
    new_ipv6_hdr = struct.pack('!IHBB16s16s', vtc_flow, payload_len, next_header, hop_limit, orig_dst_ip, orig_src_ip)
    
    # Combine L2, L3, and L4+ payloads
    return new_eth_hdr + new_ipv6_hdr + final_icmp

def main():
    parser = argparse.ArgumentParser(description="L2 UDPv6 Sniffer and ICMPv6 Packet Too Big Responder.")
    parser.add_argument('-i', '--interface', required=True, help="Network interface to bind to (e.g., br0).")
    parser.add_argument('-m', '--mtu', type=int, default=1280, help="Next-Hop MTU to advertise (default: 1280).")
    parser.add_argument('-p', '--port', type=int, help="Optional: UDPv6 port to bind and silently absorb traffic.")
    args = parser.parse_args()

    # 1. Set up a single AF_PACKET socket for both receiving and sending
    try:
        # ETH_P_IPV6 ensures the kernel filters out non-IPv6 traffic (like ARP/NDP noise) before it hits python
        raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_IPV6))
        raw_sock.bind((args.interface, 0))
        logging.info(f"Listening/Injecting raw L2 IPv6 frames on interface: {args.interface}")
    except PermissionError:
        logging.error("Permission denied. You MUST run this script as root/sudo.")
        sys.exit(1)
    except OSError as e:
        logging.error(f"Failed to bind to interface {args.interface}: {e}")
        sys.exit(1)

    # 2. Set up the Dummy absorbing socket (if requested)
    dummy_sock = None
    sockets_to_monitor = [raw_sock]
    
    if args.port:
        try:
            dummy_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            dummy_sock.bind(('::', args.port))
            sockets_to_monitor.append(dummy_sock)
            logging.info(f"Bound dummy UDPv6 socket on port {args.port} to suppress internal 'Port Unreachable' messages.")
        except Exception as e:
            logging.error(f"Failed to bind dummy socket on port {args.port}: {e}")
            sys.exit(1)

    logging.info(f"Monitoring... Advertising MTU {args.mtu} on UDPv6 intercept.")

    # 3. Main Event Loop
    try:
        while True:
            readable, _, _ = select.select(sockets_to_monitor, [], [])
            
            for sock in readable:
                if sock is dummy_sock:
                    sock.recvfrom(65535)
                    
                elif sock is raw_sock:
                    eth_frame, addr = raw_sock.recvfrom(65535)
                    
                    # Outbound packets injected by this very socket will be looped back to recvfrom().
                    # addr[2] contains the PACKET_TYPE. 4 is PACKET_OUTGOING. Ignore them.
                    if addr[2] == socket.PACKET_OUTGOING:
                        continue
                        
                    ipv6_packet = eth_frame[14:]
                    if len(ipv6_packet) < 40:
                        continue
                        
                    # Check Next Header (Byte 6) for UDP (17)
                    if ipv6_packet[6] != 17:
                        continue

                    sender_ip_bytes = ipv6_packet[8:24]
                    sender_ip = socket.inet_ntop(socket.AF_INET6, sender_ip_bytes)
                    
                    logging.info(f"Intercepted UDPv6 frame from {sender_ip}. Injecting forged L2 reply...")
                    
                    reply_frame = craft_l2_icmpv6_error(args.mtu, eth_frame)
                    
                    if reply_frame:
                        try:
                            # Send the raw Ethernet frame right back out the same interface
                            raw_sock.send(reply_frame)
                            logging.info(f"-> Injected L2 ICMPv6 Packet Too Big back to {sender_ip}")
                        except Exception as e:
                            logging.error(f"Failed to inject L2 frame: {e}")
                            
    except KeyboardInterrupt:
        logging.info("\nShutting down gracefully...")
    finally:
        raw_sock.close()
        if dummy_sock:
            dummy_sock.close()

if __name__ == "__main__":
    main()
