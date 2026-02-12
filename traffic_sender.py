import socket
import subprocess

#SERVER_IP = "200.17.212.233"
SERVER_IP = "10.254.237.221"
PORT = 90
INTERFACE = "enp4s0"
PCAP = "pcaps/8M__00004_20260210170812"

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((SERVER_IP, PORT))
print("[+] Connected to Snort controller")

while True:
    data = sock.recv(1024)
    if not data:
        break

    if data.decode().strip() == "START":
        print("[*] Starting tcpreplay")

        subprocess.run([
            "sudo", "tcpreplay",
            "-i", INTERFACE,
            "--loop", "2",
            "-K",
            "--mbps", "10000",
            PCAP
        ])

        sock.sendall(b"FINISHED\n")
        print("[+] Traffic finished")

