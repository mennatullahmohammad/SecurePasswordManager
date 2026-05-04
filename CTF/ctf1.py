from scapy.all import rdpcap, IP, TCP, Raw
import base64


def solve(filepath):
    pkts = rdpcap(filepath)

    payload_chunks = []
    collecting = False

    for p in pkts:
        if TCP not in p or Raw not in p:
            continue
        if p[TCP].sport != 4444 and p[TCP].dport != 4444:
            continue

        chunk = p[Raw].load.decode("utf-8", errors="replace")

        if chunk == "MSG:":
            collecting = True
            payload_chunks = []
        elif chunk == ":EOF":
            break
        elif collecting:
            payload_chunks.append(chunk)

    b64 = "".join(payload_chunks)
    flag = base64.b64decode(b64).decode("utf-8")
    print(f"FLAG: {flag}")
    return flag


if __name__ == "__main__":
    import sys
    filepath = sys.argv[1] if len(sys.argv) > 1 else r"..\CTF_DATA\CTF_DATA\CTF1\traffic.pcapng"
    solve(filepath)
