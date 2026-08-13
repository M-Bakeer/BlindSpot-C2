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
            return None
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
                packet = os.read(tun_fd, 2048)
                if not packet:
                    return
                try:
                    send_framed_packet(tls_socket, packet)
                except (BrokenPipeError, ssl.SSLError, OSError):
                    return

            else:
                try:
                    packet = receive_framed_packet(tls_socket)
                except (ssl.SSLError, OSError):
                    return
                if packet is None:
                    return
                os.write(tun_fd, packet)



def tls_conf(ca_public, client_cert, client_private):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

   
    ctx.load_verify_locations(cafile=ca_public)
    ctx.verify_mode = ssl.CERT_REQUIRED

    if client_cert: #Mutual TLS
        ctx.load_cert_chain(certfile=client_cert, keyfile=client_private)
        print("[+] Mutual TLS enabled")

    return ctx


def main():
    parser = argparse.ArgumentParser(description="TLS VPN client")
    parser.add_argument("--server_ip", default="10.0.2.15")
    parser.add_argument("--port", type=int, default=55555)
    parser.add_argument("--tun-name", default="tun0")
    parser.add_argument("--tun-ip", default="192.168.53.5")
    parser.add_argument("--ca_public", default="ca-public.pem")
    parser.add_argument("--client_cert", default=None)
    parser.add_argument("--client_private", default=None)
    args = parser.parse_args()

    if os.geteuid() != 0:
        sys.exit("Must run as root")

    # --- set up the virtual network interface ---
    tun_fd = open_tun_device(args.tun_name)
    assign_ip_to_tun(args.tun_name, args.tun_ip)
    print(f"[+] {args.tun_name} up with {args.tun_ip}")

    # --- set up TLS and connect ---
    conf = tls_conf(args.ca_public, args.client_cert, args.client_private)

    plain_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    plain_socket.connect((args.server_ip, args.port))

    tls_socket = conf.wrap_socket(plain_socket)
    print(f"[+] TLS handshake complete ({tls_socket.version()})")
    print(f"[+] Negotiated cipher: {tls_socket.cipher()}")

    forward_traffic(tun_fd, tls_socket)


if __name__ == "__main__":
    main()
