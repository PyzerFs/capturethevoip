#!/usr/bin/env python3
import subprocess
import shutil
import pathlib
import datetime
from flask import Flask, render_template, request, redirect, session, url_for, jsonify
import config
import socket

app = Flask(__name__)
app.secret_key = "voipkey"

ALERTS = []


def check_tshark():
    if shutil.which("tshark") is None:
        raise RuntimeError("tshark não encontrado")


def timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def detect_sip_attacks(pcap_file):
    cmd = [
        "tshark", "-r", pcap_file,
        "-Y", "sip",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "sip.Method"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    counter = {}

    for line in result.stdout.splitlines():
        if not line.strip(): continue
        ip, method = line.split("\t")
        counter[(ip, method)] = counter.get((ip, method), 0) + 1

    for (ip, method), count in counter.items():
        if count > 50:
            ALERTS.append({"time": timestamp(), "ip": ip, "type": "SIP Flood", "detail": f"{method} x{count}"})
        if method == "REGISTER" and count > 20:
            ALERTS.append({"time": timestamp(), "ip": ip, "type": "Brute Force", "detail": f"{method} x{count}"})
        if method == "OPTIONS" and count > 30:
            ALERTS.append({"time": timestamp(), "ip": ip, "type": "SIP Scan", "detail": f"{method} x{count}"})


def capture_packets(interface):
    pathlib.Path(config.CAPTURE_DIR).mkdir(exist_ok=True)
    filename = f"voip_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pcapng"
    filepath = pathlib.Path(config.CAPTURE_DIR) / filename

    filter_expr = f"(host {config.PBX_IP}) and (udp port 5060 or udp portrange 10000-20000)"

    cmd = [
        "tshark",
        "-i", interface,
        "-f", filter_expr,
        "-w", str(filepath),
        "-a", "duration:60",
        "-p"
    ]

    subprocess.call(cmd)
    detect_sip_attacks(str(filepath))

    
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

print("IP usado para conexão:", get_local_ip())


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form["username"] == config.USERNAME and request.form["password"] == config.PASSWORD:
            session["logged"] = True
            capture_packets("eth0")
            return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if not session.get("logged"):
        return redirect(url_for("login"))
    return render_template("dashboard.html", alerts=ALERTS)


@app.route("/api/alerts")
def api_alerts():
    return jsonify(ALERTS)

if __name__ == "__main__":
    check_tshark()
    app.run(host="0.0.0.0", port=5000)
    
    