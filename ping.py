from socket import *
import os
import struct
import time
import select

ICMP_ECHO_REQUEST = 8 # ICMP type code for echo request
def checksum(source_string):
    """Calculate the checksum of the input string."""
    csum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0
    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        csum = csum + this_val
        csum = csum & 0xFFFFFFFF
        count += 2
    if count_to < len(source_string):
        csum = csum + source_string[-1]
        csum = csum & 0xFFFFFFFF
    csum = (csum >> 16) + (csum & 0xFFFF)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xFFFF
    answer = answer >> 8 | (answer << 8 & 0xFF00)
    return answer


def receive_one_ping(my_socket, ID, timeout, dest_addr):
    """Receive the ping response and compute RTT."""
    time_left = timeout
    while True:
        started_select = time.time()
        ready = select.select([my_socket], [], [], time_left)
        select_duration = (time.time() - started_select)

        if ready[0] == []:
            return "Request timed out."

        time_received = time.time()
        rec_packet, addr = my_socket.recvfrom(1024)

        ip_header = rec_packet[:20]
        ttl = struct.unpack("!BBHHHBBH4s4s", ip_header)[5]  # índice 5 = TTL

        icmp_header = rec_packet[20:28]
        icmp_type, code, checksum, packet_id, sequence = struct.unpack(
            "bbHHh", icmp_header
        )

        if icmp_type == 0 and packet_id == ID:
            bytes_in_double = struct.calcsize("d")
            time_sent = struct.unpack(
                "d", rec_packet[28: 28 + bytes_in_double]
            )[0]

            rtt = (time_received - time_sent) * 1000  # ms
            return (
                f"{len(rec_packet)} bytes from {addr[0]}: "
                f"icmp_seq={sequence} ttl={ttl} time={rtt:.3f} ms"
            )

        time_left -= select_duration
        if time_left <= 0:
            return "Request timed out."


def send_one_ping(my_socket, dest_addr, ID):
    """Send an ICMP echo request."""
    my_checksum = 0
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, ID, 1)
    data = struct.pack("d", time.time())
    my_checksum = checksum(header + data)
    if os.name == 'posix':
        my_checksum = htons(my_checksum) & 0xFFFF
    else:
        my_checksum = htons(my_checksum)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, ID, 1)
    packet = header + data
    my_socket.sendto(packet, (dest_addr, 1))


def do_one_ping(dest_addr, timeout):
    """Perform a single ping and return formatted string."""
    icmp = getprotobyname("icmp")
    # socket tipo RAW (requiere privilegios de administrador)
    with socket(AF_INET, SOCK_RAW, icmp) as my_socket:
        my_id = os.getpid() & 0xFFFF  # ID de 16 bits
        send_one_ping(my_socket, dest_addr, my_id)
        result = receive_one_ping(my_socket, my_id, timeout, dest_addr)
        return result


def ping(host, timeout=1):
    """Ping a host."""
    try:
        dest = gethostbyname(host)
        print(f"Pinging {dest} ({host}) using Python:\n")
        while True:
            delay = do_one_ping(dest, timeout)
            print(delay)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nPing stopped.")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    for host in ["google.com", "bbc.co.uk", "iitb.ac.in"]:
        print(f"\n===== Pinging {host} =====")
        try:
            ping(host)  # usa timeout por defecto = 1 s
        except PermissionError:
            print(
                "Este script necesita permisos de administrador "
                "(RAW sockets). Ejecútalo con sudo o como root."
            )
            break

