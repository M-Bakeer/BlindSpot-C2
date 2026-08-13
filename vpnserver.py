#!/usr/bin/env python3

import argparse
import fcntl
import os
import select
import socket
import ssl
import struct
import sys                                           


def open_tun_device(name):
    tun_fd = os.open("/dev/net/tun", os.O_RDWR)

    request = struct.pack("16sH", name.encode(), 0x0001 | 0x1000)
    fcntl.ioctl(tun_fd, 0x400454CA, request)

    return tun_fd


def assign_ip_to_tun(name, ip):
 
    os.system(f"ip addr add {ip}/24 dev {name}")
    os.system(f"ip link set dev {name} up")




def read_exact(sock, num_bytes):
    data = b""
    while len(data) < num_bytes:
        chunk = sock.recv(num_bytes - len(data))
        if not chunk:
            return None  # connection closed
        data += chunk
    return data


def send_framed_packet(sock, packet):
    length_header = struct.pack("!H", len(packet))
    sock.sendall(length_header + packet)


def receive_framed_packet(sock):
    length_header = read_exact(sock, 2)
    if length_header is None:
        return None
    (length,) = struct.unpack("!H", length_header)
    return read_exact(sock, length)


def forward_traffic(tun_fd, tls_socket):
    watched = [tun_fd, tls_socket]

    while True:
        ready, _, _ = select.select(watched, [], [])

        for fd in ready:

            if fd == tun_fd:
                # into the tunnel -> encrypt and send it out.
                packet = os.read(tun_fd, 2048)
                if not packet:
                    return
                try:
                    send_framed_packet(tls_socket, packet)
                except (BrokenPipeError, ssl.SSLError, OSError):
                    return

            else:
                # from the tunnel -> decrypt 
                try:
                    packet = receive_framed_packet(tls_socket)
                except (ssl.SSLError, OSError):
                    return
                if packet is None:
                    return
                os.write(tun_fd, packet)


def tls_conf(server_cert, server_private, ca_public):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    ctx.load_cert_chain(certfile=server_cert, keyfile=server_private)

    if ca_public: #Mutual TLS
        ctx.load_verify_locations(cafile=ca_public)
        ctx.verify_mode = ssl.CERT_REQUIRED
        print("[+] Mutual TLS enabled")
    else:
        ctx.verify_mode = ssl.CERT_NONE

    return ctx


def main():
    parser = argparse.ArgumentParser(description="TLS VPN server")
    parser.add_argument("--port", type=int, default=55555)
    parser.add_argument("--tun-name", default="tun0")
    parser.add_argument("--tun-ip", default="192.168.53.1")
    parser.add_argument("--server-cert", default="server-cert.pem")
    parser.add_argument("--server-private", default="server-private.pem")
    parser.add_argument("--ca-public", default=None, help="CA file to require+verify client certs (mutual TLS)")
    args = parser.parse_args()

    if os.geteuid() != 0: #check root
        sys.exit("Must run as root")

    # --- set up the virtual network interface ---
    tun_fd = open_tun_device(args.tun_name)
    assign_ip_to_tun(args.tun_name, args.tun_ip)
    print(f"[+] {args.tun_name} up with {args.tun_ip}")

    # --- set up TLS ---
    conf = tls_conf(args.server_cert, args.server_private, args.ca_public)

    # --- listen for a client connection ---
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", args.port))
    listener.listen(1)
    print(f"[+] Listening on TCP :{args.port}")

    while True:
        plain_socket, addr = listener.accept()
        print(f"[+] Connection from {addr}")

        try:
            tls_socket = conf.wrap_socket(plain_socket, server_side=True)
        except ssl.SSLError as e:
            print(f"[-] TLS handshake failed: {e}")
            plain_socket.close()
            continue

        print(f"[+] TLS handshake complete ({tls_socket.version()})")
        print(f"[+] Negotiated cipher: {tls_socket.cipher()}")
        try:
            forward_traffic(tun_fd, tls_socket)
        finally:
            print("[-] Client disconnected, waiting for new connection")
            tls_socket.close()


if __name__ == "__main__":
    main()
