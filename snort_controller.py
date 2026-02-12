import socket
import subprocess
import time
import re
import csv
import os
import signal

#CLIENT_IP = "10.254.237.200"
#SERVER_IP = "200.17.212.233"
SERVER_IP = "10.254.237.221"
PORT = 90
MY_PATH = "/home/cloudstack/raphael/snort3"
INTERFACE = "enp3s0"
RULES = f"{MY_PATH}/rules/oi.rules"
CONF = f"{MY_PATH}/etc/snort/snort.lua"

RESULTS_FILE = "snort_results.csv"
LOG_DIR = "snort_stdout"
os.makedirs(LOG_DIR, exist_ok=True)

def start_snort(threads, run_id):
    stdout_file = open(f"{LOG_DIR}/snort_t{threads}_r{run_id}.out", "w")

    cmd = [
        "sudo", f"{MY_PATH}/bin/snort",
        "--daq", "afpacket",
        "--daq-var", "fanout_type=cpu",
        "-c", CONF,
        "-R", RULES,
        "-i", INTERFACE,
        "-k", "none",
        "-z", str(threads)
    ]

    print(f"[+] Starting Snort T={threads} Run={run_id}")
    proc = subprocess.Popen(
        cmd,
        stdout=stdout_file,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    time.sleep(5)
    return proc, stdout_file.name

def stop_snort(proc):
    print("[*] Sending SIGINT to Snort")
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()

def parse_stdout(file_path):
    packets = 0
    alerts = 0

    with open(file_path, "r") as f:
        data = f.read()

    m = re.search(r"analyzed:\s+(\d+)", data)
    if m:
        packets = int(m.group(1))

    m = re.search(r"alerts:\s+(\d+)", data)
    if m:
        alerts = int(m.group(1))

    return packets, alerts

# SOCKET SERVER
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((SERVER_IP, PORT))
server.listen(1)
print("[*] Waiting for traffic client...")
conn, addr = server.accept()
print(f"[+] Client connected from {addr}")

# CSV header
with open(RESULTS_FILE, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["threads", "run", "packets_analyzed", "alerts"])

# EXPERIMENT LOOP
for threads in range(1, 17):
    for run_id in range(1, 11):

        proc, outfile = start_snort(threads, run_id)

        conn.sendall(b"START\n")

        msg = conn.recv(1024).decode().strip()
        if msg != "FINISHED":
            print("[-] Unexpected client msg:", msg)

        stop_snort(proc)
        time.sleep(2)

        packets, alerts = parse_stdout(outfile)
        print(f"[RESULT] T={threads} Run={run_id} Packets={packets} Alerts={alerts}")

        with open(RESULTS_FILE, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([threads, run_id, packets, alerts])

        time.sleep(3)

conn.close()
server.close()
print("[+] All experiments completed.")

