#!/usr/bin/env python3
"""
Usage:
    sudo python3 vpnserver.py --tun-ip 192.168.53.1 --certfile server-cert.pem --keyfile server-key.pem
"""

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


def run_forwarding_loop(tun_fd, tls_socket):
    watched = [tun_fd, tls_socket]

    while True:
        ready_to_read, _, _ = select.select(watched, [], [])

        for fd in ready_to_read:

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


def build_tls_context(certfile, keyfile, cafile):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)


    if cafile:
        ctx.load_verify_locations(cafile=cafile)
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.verify_mode = ssl.CERT_NONE


    keylog_path = os.environ.get("SSLKEYLOGFILE")
    if keylog_path:
        ctx.keylog_filename = keylog_path

    return ctx


def main():
    parser = argparse.ArgumentParser(description="TLS VPN server")
    parser.add_argument("--port", type=int, default=55555)
    parser.add_argument("--tun-name", default="tun0")
    parser.add_argument("--tun-ip", default="192.168.53.1")
    parser.add_argument("--certfile", default="server-cert.pem")
    parser.add_argument("--keyfile", default="server-key.pem")
    parser.add_argument("--cafile", default=None,
                         help="CA file to require+verify client certs (mutual TLS)")
    args = parser.parse_args()

    if os.geteuid() != 0:
        sys.exit("Must run as root (needed for /dev/net/tun and ip commands)")

    # --- set up the virtual network interface ---
    tun_fd = open_tun_device(args.tun_name)
    assign_ip_to_tun(args.tun_name, args.tun_ip)
    print(f"[+] {args.tun_name} up with {args.tun_ip}")

    # --- set up TLS ---
    tls_context = build_tls_context(args.certfile, args.keyfile, args.cafile)

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
            tls_socket = tls_context.wrap_socket(plain_socket, server_side=True)
        except ssl.SSLError as e:
            print(f"[-] TLS handshake failed: {e}")
            plain_socket.close()
            continue

        print(f"[+] TLS handshake complete ({tls_socket.version()})")
        print(f"[+] Negotiated cipher: {tls_socket.cipher()}")
        try:
            run_forwarding_loop(tun_fd, tls_socket)
        finally:
            print("[-] Client disconnected, waiting for new connection")
            tls_socket.close()


if __name__ == "__main__":
    main()
