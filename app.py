import os
import threading
import time
from datetime import datetime
from collections import deque, defaultdict
from flask import Flask, render_template, request, jsonify
from scapy.all import sniff, IP, TCP, UDP, Raw, Ether, ICMP, DNS, DNSQR, DNSRR, wrpcap, rdpcap, Packet
import socket
import re
import binascii
import traceback
import tempfile

app = Flask(__name__)

# --- Configuration ---
OUTPUT_FLAGGED_PCAP_FILE = "flagged_packets.pcap"

# --- Intrusion Detection Configuration ---
# Signature-based detection patterns (regex for raw bytes payload)
# (?i) makes the regex case-insensitive
DETECTION_PATTERNS = [
    # --- Default Credentials ---
    re.compile(b'(?i)admin:admin'),
    re.compile(b'(?i)root:toor'),
    re.compile(b'(?i)ftp:ftp'),
    re.compile(b'(?i)user:password'),
    re.compile(b'(?i)guest:guest'),

    # --- SQL Injection Patterns ---
    re.compile(b'(?i)union\\s+select'),
    re.compile(b'(?i)or\\s+1=1'),
    re.compile(b'(?i)select\\s+.+from'),
    re.compile(b'(?i)information_schema'),
    re.compile(b'(?i)benchmark\\('),
    re.compile(b'(?i)pg_sleep\\('),
    re.compile(b'(?i)xp_cmdshell'),
    re.compile(b'(?i)--\\s*|#\\s*'), # SQL comments
    re.compile(b'(?i)cast\\(|convert\\('), # Type conversion often in SQLi
    re.compile(b'(?i)exec\\(|sp_executesql'), # SQL command execution

    # --- Command Injection Patterns ---
    re.compile(b'(?i)\\&system'),
    re.compile(b'(?i)\\|\\|cmd'),
    re.compile(b'(?i);\\s*(?:cat|ls|pwd|id|whoami|echo|rm|mkdir|nc|python|perl|php|bash|sh)'),
    re.compile(b'(?i)\\$\\([a-zA-Z0-9_\\-]+'), # Basic command substitution $(command)
    re.compile(b'`[^`]+`'), # Backtick command substitution `command`
    re.compile(b'(?i)phpinfo\\(\\)'), # PHP info disclosure
    re.compile(b'(?i)eval\\s*\\('), # Code evaluation
    re.compile(b'(?i)shell_exec\\s*\\('), # PHP shell execution
    re.compile(b'(?i)system\\s*\\('), # PHP system command execution
    re.compile(b'(?i)passthru\\s*\\('), # PHP passthru command execution

    # --- Path Traversal / Local File Inclusion (LFI) / Remote File Inclusion (RFI) ---
    re.compile(b'(?i)\\.\\./|\\.\\.\\\\'), # Directory traversal
    re.compile(b'(?i)file://'),
    re.compile(b'(?i)php://filter'),
    re.compile(b'(?i)etc/passwd'),
    re.compile(b'(?i)windows/win.ini'),

    # --- Cross-Site Scripting (XSS) - Basic ---
    re.compile(b'(?i)<script[^>]*>.*?</script>'),
    re.compile(b'(?i)javascript:'),
    re.compile(b'(?i)onerror='),
    re.compile(b'(?i)onmouseover='),
    re.compile(b'(?i)alert\\('),

    # --- Common Shells / Backdoors / Remote Access Tools (basic) ---
    re.compile(b'(?i)nc\\s+-(?:l|L)vp'), # Netcat listener
    re.compile(b'(?i)bash\\s+-i\\s+>&'), # Basic reverse shell
    re.compile(b'(?i)python\\s+-c\\s+[\'"].*?socket'), # Python reverse shell
    re.compile(b'(?i)powershell\\s+-e'), # Base64 encoded PowerShell
    re.compile(b'(?i)meterpreter'),
    re.compile(b'(?i)cobaltstrike'),

    # --- Malware Communication / C2 (Command and Control) Indicators (basic) ---
    re.compile(b'(?i)c2server'),
    re.compile(b'(?i)beacon'),
    re.compile(b'(?i)upload_file'),
    re.compile(b'(?i)download_file'),
    re.compile(b'(?i)execute_cmd'),

    # --- Obfuscation / Encoding Indicators (basic) ---
    re.compile(b'(?i)%u[0-9a-fA-F]{4}'), # Unicode encoding
    re.compile(b'(?i)%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}'), # Double URL encoding
    re.compile(b'(?i)base64(?:_decode)?\\('), # Base64 function call

    # --- Scanning Tools / Reconnaissance ---
    re.compile(b'(?i)nmap'),
    re.compile(b'(?i)nikto'),
    re.compile(b'(?i)wpscan'),
    re.compile(b'(?i)dirb|gobuster|ffuf'), # Directory bruteforcing tools
]

# Keyword-based detection (case-insensitive string matching for text payload)
DETECTION_KEYWORDS = [
    # --- Generic Attack/Malware Terms ---
    "password", "exploit", "malware", "shell", "attack", "vulnerable",
    "unauthorized", "inject", "credential", "phishing", "ransom", "cryptolocker",
    "virus", "worm", "trojan", "rootkit", "botnet", "ddos", "zero-day",
    "backdoor", "keylogger", "spyware", "adware",

    # --- SQL Injection Keywords ---
    "sql error", "syntax error", "mysql_fetch", "pg_query", "sqli",
    "mssql", "postgres", "oracle", "sqlmap",

    # --- Command Injection Keywords ---
    "cmd.exe", "/bin/bash", "/bin/sh", "cmdline", "systeminfo", "whoami", "id",
    "ifconfig", "ipconfig", "netstat", "route", "tasklist", "ps aux", "cat /etc/passwd",
    "wget", "curl", "certutil", "powershell",

    # --- File/Directory Access Keywords ---
    "htpasswd", "shadow", "config.php", "web.config", "database.yml",
    "robots.txt", "sitemap.xml", ".git/config", ".env",

    # --- Sensitive Data Keywords (use with high caution for false positives) ---
    "api_key", "secret_key", "private_key", "bearer token", "sessionid",
    "access_token", "jwt", "client_secret", "credit card", "social security number",
    "passport number", "bank_account", "cvv", "expiration_date",

    # --- Web Attack Specifics ---
    "csrf_token", "jwt", "cookie", "referer", "user-agent", # Could be legitimate, but suspicious if combined with other indicators
    "admin", "login", "auth", "session", # General web terms, context is key

    # --- Remote Access / Scanning ---
    "rdp", "ssh", "vnc", "teamviewer", "anydesk", "splashtop",
    "portscan", "reconnaissance", "vulnerability scan", "penetration test",
]


METADATA_THRESHOLDS = {
    "max_ip_len": 1500, # Max IP packet length
    "suspicious_ttl_min": 5, # Low TTL, indicative of short hops/local network/traceroute
    "suspicious_tcp_flags_all": True, # Xmas Scan (URG, ACK, PSH, RST, SYN, FIN all set)
    "suspicious_tcp_flags_syn_fin": True # SYN and FIN set together (stealth scan/malformed)
}

# --- Global Variables for Packet Capture and Analysis ---
MAX_PACKETS_DISPLAY = 1000
MAX_LOGGED_PACKETS = 500
captured_packets_data = deque(maxlen=MAX_PACKETS_DISPLAY)
logged_flagged_packets = deque(maxlen=MAX_LOGGED_PACKETS)
flagged_pcap_packets = []
is_capturing = False
is_analyzing_pcap = False
capture_thread = None
pcap_analysis_thread = None
capture_stop_event = threading.Event()

target_domain_ips = set()
target_domain_names = set()

# --- Helper function for payload content extraction ---
def get_payload_content(packet, max_len=256):
    content = {"text": "N/A", "hex": "N/A", "raw_bytes": b''}

    if Raw in packet:
        payload_bytes = bytes(packet[Raw])
        content["raw_bytes"] = payload_bytes

        try:
            content["text"] = payload_bytes[:max_len].decode('utf-8', errors='ignore')
        except UnicodeDecodeError:
            content["text"] = payload_bytes[:max_len].decode('latin-1', errors='ignore')

        content["hex"] = binascii.hexlify(payload_bytes[:max_len]).decode('ascii')

        if len(payload_bytes) > max_len:
            content["text"] += " (truncated)"
            content["hex"] += "..."

    elif packet.haslayer(DNS):
        dns_layer = packet[DNS]
        content_lines = []
        if dns_layer.qr == 0 and dns_layer.qd:
            qname = dns_layer.qd.qname.decode('utf-8', errors='ignore').rstrip('.') if dns_layer.qd.qname else "N/A"
            content_lines.append(f"DNS Query: {qname}")
        if dns_layer.qr == 1 and dns_layer.an:
            for rr in dns_layer.an:
                rrname = rr.rrname.decode('utf-8', errors='ignore').rstrip('.') if rr.rrname else "N/A"
                rdata = str(rr.rdata) if hasattr(rr, 'rdata') else "N/A"
                content_lines.append(f"DNS Answer: {rrname} -> {rdata}")

        full_dns_content = "\n".join(content_lines)
        content["text"] = full_dns_content[:max_len]
        if len(full_dns_content) > max_len:
            content["text"] += " (truncated)"
        content["hex"] = "N/A (DNS details in text)"

    return content

# --- Domain Resolution Helper ---
def resolve_domain_to_ips(domain):
    """Resolves a single domain name to its IP addresses."""
    resolved_ips = set()
    try:
        info = socket.getaddrinfo(domain, None)
        for res in info:
            ip_address = res[4][0]
            resolved_ips.add(ip_address)
    except socket.gaierror:
        pass
    return resolved_ips

# --- Packet Processing Function ---
def process_packet(packet):
    """
    Extracts relevant information from a Scapy packet, flags targeted and
    intrusion packets, and stores flagged details and the packet itself.
    """
    packet_info = {
        # --- MODIFICATION HERE: Cast packet.time to float ---
        "timestamp": datetime.fromtimestamp(float(packet.time)).strftime('%H:%M:%S.%f')[:-3],
        "src_ip": "N/A",
        "dst_ip": "N/A",
        "protocol": "N/A",
        "length": len(packet),
        "summary": packet.summary(),
        "raw_payload": "N/A",
        "is_targeted_flagged": False,
        "targeted_reasons": [],
        "is_intrusion_flagged": False,
        "intrusion_reasons": []
    }

    global captured_packets_data
    global logged_flagged_packets
    global flagged_pcap_packets

    try:
        packet_content = get_payload_content(packet)
        packet_info["raw_payload"] = packet_content["text"] # This is the decoded text payload

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            packet_info["src_ip"] = src_ip
            packet_info["dst_ip"] = dst_ip
            packet_info["protocol"] = packet[IP].proto

            if packet[IP].proto == 6:
                packet_info["protocol"] = "TCP"
            elif packet[IP].proto == 17:
                packet_info["protocol"] = "UDP"
            elif packet[IP].proto == 1:
                packet_info["protocol"] = "ICMP"

            # --- Targeted Domain Flagging Logic ---
            try:
                global target_domain_ips, target_domain_names

                if target_domain_ips:
                    if src_ip in target_domain_ips:
                        packet_info["is_targeted_flagged"] = True
                        reason = f"Source IP ({src_ip}) matches a targeted domain's resolved IP."
                        packet_info["targeted_reasons"].append(reason)
                    if dst_ip in target_domain_ips:
                        packet_info["is_targeted_flagged"] = True
                        reason = f"Destination IP ({dst_ip}) matches a targeted domain's resolved IP."
                        if reason not in packet_info["targeted_reasons"]:
                            packet_info["targeted_reasons"].append(reason)

                if packet.haslayer(DNS) and target_domain_names:
                    dns_layer = packet[DNS]

                    if dns_layer.qr == 0 and dns_layer.qd and dns_layer.qd.qname:
                        queried_name = dns_layer.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                        for domain in target_domain_names:
                            if re.search(r'\b' + re.escape(domain) + r'\b', queried_name, re.IGNORECASE):
                                packet_info["is_targeted_flagged"] = True
                                reason = f"DNS query for '{queried_name}' (related to '{domain}')."
                                if reason not in packet_info["targeted_reasons"]:
                                    packet_info["targeted_reasons"].append(reason)
                                break

                    if dns_layer.qr == 1 and dns_layer.an:
                        for ans in dns_layer.an:
                            if ans.type == 1:
                                response_ip = str(ans.rdata)
                                response_name = ans.rrname.decode('utf-8', errors='ignore').rstrip('.')

                                if target_domain_ips and response_ip in target_domain_ips:
                                    packet_info["is_targeted_flagged"] = True
                                    reason = f"DNS response for '{response_name}' resolves to a targeted IP ({response_ip})."
                                    if reason not in packet_info["targeted_reasons"]:
                                        packet_info["targeted_reasons"].append(reason)

                                for domain in target_domain_names:
                                    if re.search(r'\b' + re.escape(domain) + r'\b', response_name, re.IGNORECASE):
                                        packet_info["is_targeted_flagged"] = True
                                        reason = f"DNS response for domain '{response_name}' (related to '{domain}')."
                                        if reason not in packet_info["targeted_reasons"]:
                                            packet_info["targeted_reasons"].append(reason)
                                        break
            except Exception as e:
                print(f"!!! Error in TARGETED flagging for packet ({packet.summary()}): {e}")
                traceback.print_exc()

            # --- Intrusion Detection Logic ---
            try:
                # 1. Pattern-based detection (on raw bytes payload)
                raw_payload_bytes = packet_content["raw_bytes"]
                if raw_payload_bytes:
                    for pattern in DETECTION_PATTERNS:
                        if pattern.search(raw_payload_bytes):
                            packet_info["is_intrusion_flagged"] = True
                            # Decode pattern for display, ignoring errors
                            reason = f"Pattern match: '{pattern.pattern.decode(errors='ignore')}' found in raw payload."
                            if reason not in packet_info["intrusion_reasons"]:
                                packet_info["intrusion_reasons"].append(reason)

                # 2. Keyword-based detection (on text payload)
                text_payload = packet_content["text"].lower()
                if text_payload != "n/a":
                    for keyword in DETECTION_KEYWORDS:
                        if keyword in text_payload:
                            packet_info["is_intrusion_flagged"] = True
                            reason = f"Keyword match: '{keyword}' found in text payload."
                            if reason not in packet_info["intrusion_reasons"]:
                                packet_info["intrusion_reasons"].append(reason)

                # 3. Metadata-based detection (on IP and TCP headers)
                # IP Length check
                if packet[IP].len > METADATA_THRESHOLDS["max_ip_len"]:
                    packet_info["is_intrusion_flagged"] = True
                    reason = f"Suspiciously large IP packet length ({packet[IP].len} > {METADATA_THRESHOLDS['max_ip_len']})."
                    if reason not in packet_info["intrusion_reasons"]:
                        packet_info["intrusion_reasons"].append(reason)

                # TTL check
                if packet[IP].ttl <= METADATA_THRESHOLDS["suspicious_ttl_min"]:
                    packet_info["is_intrusion_flagged"] = True
                    reason = f"Suspiciously low IP TTL ({packet[IP].ttl} <= {METADATA_THRESHOLDS['suspicious_ttl_min']})."
                    if reason not in packet_info["intrusion_reasons"]:
                        packet_info["intrusion_reasons"].append(reason)

                if TCP in packet:
                    tcp_flags = packet[TCP].flags

                    # TCP Flags check (Xmas Scan: URG, ACK, PSH, RST, SYN, FIN all set)
                    # Scapy flags are stored as a string like 'FSRPAU'
                    if METADATA_THRESHOLDS["suspicious_tcp_flags_all"] and \
                       'U' in tcp_flags and 'A' in tcp_flags and \
                       'P' in tcp_flags and 'R' in tcp_flags and \
                       'S' in tcp_flags and 'F' in tcp_flags:
                        packet_info["is_intrusion_flagged"] = True
                        reason = "Intrusion: Xmas Scan detected (all TCP flags set)."
                        if reason not in packet_info["intrusion_reasons"]:
                            packet_info["intrusion_reasons"].append(reason)

                    # TCP Flags check (SYN and FIN together)
                    if METADATA_THRESHOLDS["suspicious_tcp_flags_syn_fin"] and \
                       'S' in tcp_flags and 'F' in tcp_flags:
                        packet_info["is_intrusion_flagged"] = True
                        reason = "Intrusion: SYN and FIN flags set (unusual TCP behavior)."
                        if reason not in packet_info["intrusion_reasons"]:
                            packet_info["intrusion_reasons"].append(reason)

            except Exception as e:
                print(f"!!! Error in INTRUSION detection for packet ({packet.summary()}): {e}")
                traceback.print_exc()

        captured_packets_data.append(packet_info)

        if packet_info["is_targeted_flagged"] or packet_info["is_intrusion_flagged"]:
            logged_flagged_packets.append(packet_info)
            flagged_pcap_packets.append(packet)

    except Exception as e:
        print(f"!!! CRITICAL ERROR processing packet ({packet.summary() if 'packet' in locals() else 'unknown packet'}): {e}")
        traceback.print_exc()

# --- Scapy Capture Function (runs in a separate thread) ---
def start_capture_scapy(interface=None, pkt_count=0, BPF_filter=""):
    global is_capturing
    print(f"Starting capture on interface: {interface if interface else 'any'}, filter: '{BPF_filter}'")
    is_capturing = True
    try:
        sniff(iface=interface, prn=process_packet, store=0, count=pkt_count,
              filter=BPF_filter, stop_filter=lambda x: capture_stop_event.is_set())
    except Exception as e:
        print(f"Error during capture: {e}")
    finally:
        is_capturing = False
        print("Live capture stopped.")

# --- PCAP Analysis Function (runs in a separate thread) ---
def analyze_pcap_file(filepath, domains_input_raw):
    global is_analyzing_pcap, \
               target_domain_ips, target_domain_names, \
               captured_packets_data, logged_flagged_packets, flagged_pcap_packets

    print(f"Starting analysis of PCAP file: {filepath}")
    is_analyzing_pcap = True

    target_domain_ips.clear()
    target_domain_names.clear()
    captured_packets_data.clear()
    logged_flagged_packets.clear()
    flagged_pcap_packets.clear()

    if domains_input_raw:
        domains_list = [
            d.strip() for d in re.split(r'[,\n]', domains_input_raw) if d.strip()
        ]
        resolved_count = 0
        failed_domains = []
        for domain in set(domains_list):
            target_domain_names.add(domain)
            resolved_ips_for_domain = resolve_domain_to_ips(domain)
            if resolved_ips_for_domain:
                target_domain_ips.update(resolved_ips_for_domain)
                resolved_count += 1
            else:
                failed_domains.append(domain)

        print(f"[*] Target domains for PCAP analysis: {len(target_domain_names)}, Successfully resolved: {resolved_count}")
        if failed_domains:
            print(f"[-] Failed to resolve IPs for domains during PCAP analysis: {', '.join(failed_domains)}. These domains will only be flagged via DNS queries/responses.")

    try:
        packets = rdpcap(filepath)
        print(f"[*] Loaded {len(packets)} packets from {filepath}")
        for i, packet in enumerate(packets):
            if capture_stop_event.is_set():
                print("PCAP analysis stopped by user request.")
                break
            process_packet(packet)
        print("[*] PCAP analysis complete.")
    except Exception as e:
        print(f"Error during PCAP file analysis: {e}")
        traceback.print_exc()
    finally:
        is_analyzing_pcap = False
        write_flagged_data_to_pcap_file()
        # Clean up the temporary file after analysis
        if os.path.exists(filepath):
            os.unlink(filepath)
            print(f"[*] Cleaned up temporary PCAP file: {filepath}")
        print("PCAP analysis finished.")

# --- PCAP File Writing Function ---
def write_flagged_data_to_pcap_file():
    """Writes all collected flagged Scapy packets to a PCAP file."""
    global flagged_pcap_packets, OUTPUT_FLAGGED_PCAP_FILE

    if not flagged_pcap_packets:
        print("[*] No flagged packets to write to PCAP file.")
        return

    try:
        wrpcap(OUTPUT_FLAGGED_PCAP_FILE, flagged_pcap_packets)
        print(f"[+] Flagged packets saved to '{OUTPUT_FLAGGED_PCAP_FILE}'")
    except Exception as e:
        print(f"[-] Error writing flagged packets to PCAP file: {e}")
        traceback.print_exc()

# --- Flask Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_capture', methods=['POST'])
def start_capture():
    global is_capturing, capture_thread, capture_stop_event, \
               target_domain_ips, target_domain_names, \
               captured_packets_data, logged_flagged_packets, flagged_pcap_packets, \
               is_analyzing_pcap

    if is_capturing:
        return jsonify({"status": "already_capturing", "message": "Capture is already active."}), 200
    if is_analyzing_pcap:
        return jsonify({"status": "analysis_in_progress", "message": "PCAP analysis is in progress. Please wait."}), 200

    interface = request.form.get('interface', 'any')
    bpf_filter = request.form.get('filter', '')
    domains_input_raw = request.form.get('domain_filter', '').strip()

    target_domain_ips.clear()
    target_domain_names.clear()
    captured_packets_data.clear()
    logged_flagged_packets.clear()
    flagged_pcap_packets.clear()

    if domains_input_raw:
        domains_list = [
            d.strip() for d in re.split(r'[,\n]', domains_input_raw) if d.strip()
        ]

        resolved_count = 0
        failed_domains = []
        for domain in set(domains_list):
            target_domain_names.add(domain)
            resolved_ips_for_domain = resolve_domain_to_ips(domain)
            if resolved_ips_for_domain:
                target_domain_ips.update(resolved_ips_for_domain)
                resolved_count += 1
            else:
                failed_domains.append(domain)

        print(f"[*] Total target domains to flag: {len(target_domain_names)}, Successfully resolved: {resolved_count}")
        if failed_domains:
            print(f"[-] Failed to resolve IPs for domains: {', '.join(failed_domains)}. These domains will only be flagged via DNS queries/responses.")

    capture_stop_event.clear()

    capture_thread = threading.Thread(
        target=start_capture_scapy,
        args=(interface, 0, bpf_filter),
        daemon=True
    )
    capture_thread.start()

    return jsonify({"status": "success", "message": "Live capture started successfully."}), 200

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    global is_capturing, capture_stop_event, capture_thread, is_analyzing_pcap, pcap_analysis_thread
    if not is_capturing and not is_analyzing_pcap:
        return jsonify({"status": "not_active", "message": "No active capture or analysis to stop."}), 200

    print("Stopping active operation...")
    capture_stop_event.set()

    if capture_thread and capture_thread.is_alive():
        print("Waiting for live capture thread to finish...")
        capture_thread.join(timeout=5)
        if capture_thread.is_alive():
            print("Warning: Live capture thread did not stop gracefully within timeout.")

    if pcap_analysis_thread and pcap_analysis_thread.is_alive():
        print("Waiting for PCAP analysis thread to finish...")
        pcap_analysis_thread.join(timeout=5)
        if pcap_analysis_thread.is_alive():
            print("Warning: PCAP analysis thread did not stop gracefully within timeout.")

    write_flagged_data_to_pcap_file()
    capture_stop_event.clear()

    return jsonify({"status": "success", "message": "Active operation stopped."}), 200

@app.route('/upload_pcap', methods=['POST'])
def upload_pcap():
    global is_capturing, is_analyzing_pcap, pcap_analysis_thread, capture_stop_event

    if is_capturing:
        return jsonify({"status": "capture_in_progress", "message": "Live capture is active. Please stop it before uploading a PCAP."}), 400
    if is_analyzing_pcap:
        return jsonify({"status": "analysis_in_progress", "message": "Another PCAP analysis is in progress. Please wait."}), 400

    if 'pcap_file' not in request.files:
        return jsonify({"status": "error", "message": "No file part in the request."}), 400

    file = request.files['pcap_file']
    if file.filename == '':
        return jsonify({"status": "error", "message": "No selected file."}), 400

    if not file.filename.lower().endswith('.pcap') and not file.filename.lower().endswith('.pcapng'):
        return jsonify({"status": "error", "message": "Invalid file type. Please upload a .pcap or .pcapng file."}), 400

    domains_input_raw = request.form.get('domain_filter', '').strip()

    temp_filepath = None # Initialize outside try-block for finally access
    try:
        # Use NamedTemporaryFile to ensure unique filename and automatic cleanup on close/delete
        # delete=False is crucial here, as we need the file to persist for the analysis thread
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as temp_file_obj:
            file.save(temp_file_obj.name)
            temp_filepath = temp_file_obj.name # Get the actual path

        capture_stop_event.clear()

        # Start analysis in a separate thread, passing the path to the temp file
        pcap_analysis_thread = threading.Thread(
            target=analyze_pcap_file,
            args=(temp_filepath, domains_input_raw),
            daemon=True
        )
        pcap_analysis_thread.start()

        return jsonify({"status": "success", "message": f"PCAP file '{file.filename}' uploaded and analysis started. Results will appear shortly."}), 202
    except Exception as e:
        print(f"Error handling PCAP upload: {e}")
        traceback.print_exc()
        # If an error occurs before the thread starts, or during file saving, clean up
        if temp_filepath and os.path.exists(temp_filepath):
            os.unlink(temp_filepath)
            print(f"[*] Cleaned up failed temporary PCAP file: {temp_filepath}")
        return jsonify({"status": "error", "message": f"Failed to process PCAP file: {e}"}), 500
    # Removed the 'finally' block from here. Cleanup is now in analyze_pcap_file

@app.route('/clear_packets', methods=['POST'])
def clear_packets():
    """Clears the captured packets data from the display buffer."""
    global captured_packets_data, logged_flagged_packets, flagged_pcap_packets
    captured_packets_data.clear()
    logged_flagged_packets.clear()
    flagged_pcap_packets.clear()
    print("[*] All captured/analyzed packet data cleared from display and export buffer.")
    return jsonify({"status": "success", "message": "All packet data cleared."}), 200

# NEW ROUTE: To get only flagged packets for a separate log display
@app.route('/get_flagged_packets')
def get_flagged_packets():
    """Returns only the captured packets that were flagged as targeted or intrusion."""
    return jsonify(list(logged_flagged_packets))

@app.route('/get_packets')
def get_packets():
    # Return the currently captured packets for display in the UI
    return jsonify(list(captured_packets_data))

@app.route('/get_status')
def get_status():
    # Return the current capture status
    return jsonify({
        "is_capturing": is_capturing,
        "is_analyzing_pcap": is_analyzing_pcap
    })

if __name__ == '__main__':
    # Important warning for running with root privileges
    print("WARNING: You must run this Flask app with sudo for packet capture privileges.")
    print("Example: sudo python3 app.py")
    # Run the Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)
