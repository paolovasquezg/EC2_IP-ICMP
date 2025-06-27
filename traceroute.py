from socket import (
    getprotobyname,
    gethostbyname,
    gaierror,
    socket,
    AF_INET,
    SOCK_RAW,
    IPPROTO_IP,
    IP_TTL,
    timeout,
    htons,
)
import os
import struct
import time
import select

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 10
TIMEOUT = 2.0
TRIES = 2

def checksum(source_string):
    csum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0

    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        csum += this_val
        csum &= 0xffffffff
        count += 2

    if count_to < len(source_string):
        csum += source_string[-1]
        csum &= 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum += (csum >> 16)
    answer = ~csum
    answer &= 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def build_packet():
    my_checksum = 0
    my_id = os.getpid() & 0xFFFF
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, my_id, 1)
    data = struct.pack("d", time.time())
    my_checksum = checksum(header + data)

    if os.name == 'posix':
        my_checksum = htons(my_checksum) & 0xFFFF
    else:
        my_checksum = htons(my_checksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, my_id, 1)
    return header + data

def get_route(hostname):
    try:
        dest_addr = gethostbyname(hostname)
        print(f"Traceroute to {hostname} [{dest_addr}], {MAX_HOPS} hops max:\n")
    except gaierror as e:
        print(f"Unable to resolve hostname {hostname}: {e}")
        return

    for ttl in range(1, MAX_HOPS + 1):
        for _ in range(TRIES):
            with socket(AF_INET, SOCK_RAW, getprotobyname("icmp")) as my_socket:
                my_socket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack("I", ttl))
                my_socket.settimeout(TIMEOUT)

                try:
                    packet = build_packet()
                    my_socket.sendto(packet, (dest_addr, 0))
                    t = time.time()

                    ready = select.select([my_socket], [], [], TIMEOUT)
                    if ready[0] == []:
                        print(f"{ttl:<3} * * * Request timed out.")
                        continue

                    rec_packet, addr = my_socket.recvfrom(1024)
                    time_received = time.time()

                    icmp_header = rec_packet[20:28]
                    types, code, checksum_recv, p_id, sequence = struct.unpack("bbHHh", icmp_header)

                    rtt = (time_received - t) * 1000
                    ip = addr[0]

                    if types == 11:
                        print(f"{ttl:<3} {ip:<15} rtt={rtt:.2f} ms")
                        break
                    elif types == 3:
                        print(f"{ttl:<3} {ip:<15} rtt={rtt:.2f} ms (Destination unreachable)")
                        break
                    elif types == 0:
                        print(f"{ttl:<3} {ip:<15} rtt={rtt:.2f} ms (Reached destination)")
                        return
                    else:
                        print(f"{ttl:<3} Unexpected ICMP type {types}")
                        break

                except timeout:
                    print(f"{ttl:<3} * * * Request timed out.")
                    continue
                except Exception as e:
                    print(f"{ttl:<3} Error: {e}")
                    break

if __name__ == "__main__":
    hosts = ["google.com", "bbc.co.uk", "iitb.ac.in"]
    for h in hosts:
        print(f"\n--- Traceroute to {h} ---")
        get_route(h)
