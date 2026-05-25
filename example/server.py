#!/usr/bin/env python3

"""
VoidPWN Dashboard Server
Simple Flask server to provide API endpoints for the dashboard
"""

from flask import Flask, jsonify, send_from_directory, request
import subprocess
import shlex
import os
import glob
import json
import csv
import fcntl
import shutil
import socket
from datetime import datetime
import re
import urllib.request
import urllib.parse
import urllib.error

try:
    import psutil
except ImportError:
    psutil = None
import time
import uuid
import collections
import threading

# --- Circular Log for Live HUD ---
LIVE_LOGS = collections.deque(maxlen=100)

def add_live_log(msg, type="info"):
    timestamp = datetime.now().strftime('%H:%M:%S')
    LIVE_LOGS.append({'time': timestamp, 'msg': msg, 'type': type})

def parse_inventory_info(line):
    """Parse a line of output for device info and update inventory"""
    # Look for Nmap patterns: "Nmap scan report for 192.168.1.1" or "Nmap scan report for host (192.168.1.1)"
    if "Nmap scan report for" in line:
        match = re.search(r"for ([\d\.]+)", line)
        ip = match.group(1) if match else None
        if not ip:
            match = re.search(r"for (.*) \(([\d\.]+)\)", line)
            if match:
                hostname = match.group(1)
                ip = match.group(2)
                device_manager.add_device(ip, hostname=hostname)
                return
        if ip:
            device_manager.add_device(ip)

    # Look for pure IP patterns in typical tool outputs
    # e.g., "[+] Host: 192.168.1.1" or "IP: 192.168.1.1"
    ip_match = re.search(r"(?:Host|IP|Target):\s*([\d\.]+)", line, re.I)
    if ip_match:
        device_manager.add_device(ip_match.group(1))

    # Look for MAC patterns
    mac_match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", line)
    if mac_match:
        # If we have a MAC but no IP on this line, it's hard to attribute without more context,
        # but we can look for specific tools like airodump or nmap
        pass

ERROR_KEYWORDS = ('command not found', 'no such file', 'not found', 'error:', 'permission denied',
                  'fatal:', 'failed', 'cannot', 'unable to', 'operation not permitted')

def run_proc_and_capture(cmd_str, log_file=None, report_id=None):
    """Run a process in the background and capture its output to LIVE_LOGS and optionally a file"""
    try:
        if not cmd_str.startswith('stdbuf'):
            cmd_str = f"stdbuf -oL -eL {cmd_str}"
            
        proc = subprocess.Popen(
            cmd_str,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        def capture():
            log_path = os.path.join(LOGS_DIR, log_file) if log_file else None
            f_log = open(log_path, 'w') if log_path else None
            
            for line in iter(proc.stdout.readline, ""):
                if line:
                    clean_line = line.strip()
                    # Detect error keywords and surface them as error type
                    line_lower = clean_line.lower()
                    if any(kw in line_lower for kw in ERROR_KEYWORDS):
                        add_live_log(clean_line, "error")
                    else:
                        add_live_log(clean_line)
                    parse_inventory_info(clean_line)
                    if f_log:
                        f_log.write(line)
                        f_log.flush()
            
            proc.stdout.close()
            proc.wait()
            
            if f_log:
                f_log.close()
            
            # Extract mission name from command string
            parts = cmd_str.split()
            mission_name = "Mission"
            for p in parts:
                if not p.startswith('-') and p not in ['sudo', 'stdbuf', '-oL', '-eL']:
                    mission_name = p.split('/')[-1].replace('"','')
                    break
            
            if proc.returncode != 0:
                add_live_log(f"❌ ATTACK FAILED (exit {proc.returncode}): {mission_name.upper()}", "error")
                if report_id:
                    reporter.update_status(report_id, "Failed")
            else:
                add_live_log(f"✅ MISSION COMPLETE: {mission_name.upper()}", "success")
                if report_id:
                    reporter.update_status(report_id, "Completed")
            
        t = threading.Thread(target=capture, daemon=True)
        t.start()
        return proc
    except Exception as e:
        add_live_log(f"Error starting process: {str(e)}", "error")
        return None

def gen_log_name(action):
    """Generate a unique filename for a mission log"""
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    clean_action = action.lower().replace(' ', '_')
    return f"{clean_action}_{ts}.txt"

def check_tool(name_or_path):
    """Return True if the tool/binary is available, False otherwise"""
    if name_or_path.startswith('/'):
        return os.path.exists(name_or_path)
    return shutil.which(name_or_path) is not None

def check_internet(host="8.8.8.8", port=53, timeout=3):
    """Quick TCP connectivity check — does not require DNS"""
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except (socket.error, OSError):
        return False

# --- Reporting System ---
class ReportManager:
    def __init__(self, filepath):
        self.filepath = filepath
        self.reports = self._load()

    def _load(self):
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, 'r') as f:
                    return json.load(f)
            except:
                return []
        return []

    def _save(self):
        try:
            with open(self.filepath, 'w') as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                json.dump(self.reports, f, indent=2)
                fcntl.flock(f, fcntl.LOCK_UN)
        except Exception as e:
            print(f"Failed to save report: {e}")

    def add_report(self, action_type, target, status="Running", details="", log_file=None):
        report = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now().isoformat(),
            "type": action_type,
            "target": target,
            "status": status,
            "details": details,
            "log_file": log_file
        }
        self.reports.insert(0, report) # Prepend
        self._save()
        return report

    def update_status(self, report_id, new_status):
        for r in self.reports:
            if r['id'] == report_id:
                r['status'] = new_status
                self._save()
                break

    def get_all(self):
        return self.reports

# --- Device Management System ---
class DeviceManager:
    def __init__(self, filepath):
        self.filepath = filepath
        self.devices = self._load()
        self.selected_device = None

    def _load(self):
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, 'r') as f:
                    return json.load(f)
            except:
                return []
        return []

    def _save(self):
        try:
            with open(self.filepath, 'w') as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                json.dump(self.devices, f, indent=2)
                fcntl.flock(f, fcntl.LOCK_UN)
        except Exception as e:
            print(f"Failed to save devices: {e}")

    def add_device(self, ip, mac="", hostname="", device_type="unknown", ports=None, notes="", tags=None):
        # Check if device already exists
        for device in self.devices:
            if device['ip'] == ip:
                # Update existing
                device['mac'] = mac or device.get('mac', '')
                device['hostname'] = hostname or device.get('hostname', '')
                device['device_type'] = device_type
                device['ports'] = ports or device.get('ports', [])
                device['notes'] = notes or device.get('notes', '')
                device['tags'] = tags if tags is not None else device.get('tags', [])
                device['last_seen'] = datetime.now().isoformat()
                self._save()
                return device
        
        # Add new device
        device = {
            "id": str(uuid.uuid4()),
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "device_type": device_type,
            "ports": ports or [],
            "notes": notes,
            "tags": tags or [],
            "first_seen": datetime.now().isoformat(),
            "last_seen": datetime.now().isoformat()
        }
        self.devices.append(device)
        self._save()
        return device

    def update_metadata(self, device_id, notes=None, tags=None):
        for device in self.devices:
            if device['id'] == device_id or device['ip'] == device_id:
                if notes is not None: device['notes'] = notes
                if tags is not None: device['tags'] = tags
                self._save()
                return device
        return None

    def get_all(self):
        return self.devices

    def clear(self):
        self.devices = []
        self._save()

    def select(self, device_id):
        for device in self.devices:
            if device['id'] == device_id or device['ip'] == device_id:
                self.selected_device = device
                return device
        return None

    def get_selected(self):
        return self.selected_device

app = Flask(__name__, static_folder='.', static_url_path='')

# Configuration
# Dynamic path: server.py is in /dashboard/ -> Project root is one level up
VOIDPWN_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ['VOIDPWN_DIR'] = VOIDPWN_DIR

# Paths to data
CAPTURES_DIR = os.path.join(VOIDPWN_DIR, 'output', 'captures')
RECON_DIR = os.path.join(VOIDPWN_DIR, 'output', 'recon')
LOGS_DIR = os.path.join(VOIDPWN_DIR, 'output', 'logs')

# Ensure directories exist
os.makedirs(CAPTURES_DIR, exist_ok=True)
os.makedirs(RECON_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

# Initialize Reporter
REPORTS_FILE = os.path.join(VOIDPWN_DIR, 'output', 'reports.json')
reporter = ReportManager(REPORTS_FILE)

# Initialize Device Manager
DEVICES_FILE = os.path.join(VOIDPWN_DIR, 'output', 'devices.json')
device_manager = DeviceManager(DEVICES_FILE)

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/api/reports')
def get_reports():
    return jsonify({'reports': reporter.get_all()})

@app.route('/api/system')
def get_system_info():
    """Get system information"""
    try:
        # Get IP address
        try:
            ip_result = subprocess.run(['hostname', '-I'], capture_output=True, text=True, timeout=2)
            ip = ip_result.stdout.strip().split()[0] if ip_result.stdout else 'N/A'
        except:
            ip = 'N/A'
        
        # Get uptime
        try:
            uptime_result = subprocess.run(['uptime', '-p'], capture_output=True, text=True, timeout=2)
            uptime = uptime_result.stdout.strip().replace('up ', '') if uptime_result.stdout else 'N/A'
        except:
            uptime = 'N/A'
        
        # Get temperature — try Pi-specific first, fall back to thermal zone
        try:
            temp_result = subprocess.run(['vcgencmd', 'measure_temp'], capture_output=True, text=True, timeout=3)
            if temp_result.returncode == 0 and temp_result.stdout:
                temp = temp_result.stdout.strip().replace('temp=', '')
            else:
                raise FileNotFoundError
        except:
            try:
                with open('/sys/class/thermal/thermal_zone0/temp', 'r') as tf:
                    temp = f"{int(tf.read().strip()) / 1000:.1f}'C"
            except:
                temp = 'N/A'
        
        # Check WiFi adapter using iw (works with any naming convention)
        try:
            iw_result = subprocess.run(['iw', 'dev'], capture_output=True, text=True, timeout=3)
            ifaces = [l.split()[-1] for l in iw_result.stdout.splitlines() if 'Interface' in l]
            adapter = 'DETECTED' if ifaces else 'NOT FOUND'
        except:
            # Fallback to iwconfig
            try:
                iw_result = subprocess.run(['iwconfig'], capture_output=True, text=True, stderr=subprocess.STDOUT, timeout=3)
                adapter = 'DETECTED' if re.search(r'IEEE 802\.11', iw_result.stdout) else 'NOT FOUND'
            except:
                adapter = 'UNKNOWN'
        
        if psutil:
            # Get CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Get memory info
            mem = psutil.virtual_memory()
            memory = f"{mem.used // (1024**2)} MB / {mem.total // (1024**2)} MB"
            mem_percent = mem.percent
            
            # Get disk info
            disk = psutil.disk_usage('/')
            disk_info = f"{disk.used // (1024**3)} GB / {disk.total // (1024**3)} GB"
            disk_percent = disk.percent
        else:
            cpu_percent = 0
            memory = "psutil missing"
            mem_percent = 0
            disk_info = "psutil missing"
            disk_percent = 0
        
        return jsonify({
            'ip': ip,
            'uptime': uptime,
            'temp': temp,
            'adapter': adapter,
            'cpu': round(cpu_percent, 1),
            'memory': memory,
            'memPercent': round(mem_percent, 1),
            'disk': disk_info,
            'diskPercent': round(disk_percent, 1)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats')
def get_stats():
    """Get attack statistics"""
    try:
        # Count capture files
        cap_files = glob.glob(os.path.join(CAPTURES_DIR, '*.cap'))
        handshakes = len(cap_files)
        
        # Count recon files
        recon_files = glob.glob(os.path.join(RECON_DIR, '*'))
        net_scans = len([f for f in recon_files if os.path.isfile(f)])
        
        # Parse recon results for hosts and ports (simplified)
        hosts = 0
        ports = 0
        vulns = 0
        
        for recon_file in recon_files:
            if os.path.isfile(recon_file):
                try:
                    with open(recon_file, 'r') as f:
                        content = f.read()
                        # Simple counting (can be improved with proper parsing)
                        hosts += content.count('Nmap scan report')
                        ports += content.count('open')
                        vulns += content.count('VULNERABLE')
                except:
                    pass
        
        return jsonify({
            'wifiScans': len(glob.glob(os.path.join(CAPTURES_DIR, '*'))),
            'handshakes': handshakes,
            'netScans': net_scans,
            'hosts': hosts,
            'ports': ports,
            'vulns': vulns
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs')
def get_logs():
    """Get recent activity logs"""
    # This is a placeholder - in a real implementation,
    # you would read from actual log files
    logs = []
    return jsonify({'logs': logs})

@app.route('/api/captures')
def get_captures():
    """List capture files"""
    try:
        files = []
        for f in glob.glob(os.path.join(CAPTURES_DIR, '*')):
            if os.path.isfile(f):
                stat = os.stat(f)
                files.append({
                    'name': os.path.basename(f),
                    'size': stat.st_size,
                    'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                })
        return jsonify({'files': files})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/recon')
def get_recon():
    """List recon files"""
    try:
        files = []
        for f in glob.glob(os.path.join(RECON_DIR, '*')):
            if os.path.isfile(f):
                stat = os.stat(f)
                files.append({
                    'name': os.path.basename(f),
                    'size': stat.st_size,
                    'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                })
        return jsonify({'files': files})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/networks')
def get_networks():
    """Get scanned networks (placeholder)"""
    # This would parse airodump-ng output files
    return jsonify({'networks': []})

# --- Device Management Endpoints ---
@app.route('/api/devices/list')
def list_devices():
    return jsonify({'devices': device_manager.get_all()})

@app.route('/api/devices/scan', methods=['POST'])
def scan_devices():
    """Discover hosts on the network using nmap"""
    try:
        data = request.get_json() or {}
        mode = data.get('mode', 'quick') # quick or full
        
        # Get target network/subnet
        target_subnet = data.get('subnet')
        interface = data.get('interface')
        
        if not target_subnet:
            if interface:
                # Get IP of interface
                ip_cmd = "ip -4 addr show " + shlex.quote(interface) + r" | grep -oP '(?<=inet\s)\d+(\.\d+){3}'"
                ip_res = subprocess.run(ip_cmd, shell=True, capture_output=True, text=True)
                local_ip = ip_res.stdout.strip()
                if not local_ip:
                    return jsonify({'error': f'No IP on {interface}'}), 400
                target_subnet = '.'.join(local_ip.split('.')[:-1]) + '.0/24'
            else:
                # Fallback to hostname -I
                ip_result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
                if not ip_result.stdout:
                    return jsonify({'error': 'No local IP found'}), 400
                local_ip = ip_result.stdout.strip().split()[0]
                target_subnet = '.'.join(local_ip.split('.')[:-1]) + '.0/24'
        
        # Perform nmap scan via background capture
        log_file = gen_log_name(f"discovery_{mode}")
        if mode == 'full':
            cmd_list = ['sudo', 'nmap', '-sV', '-T4', target_subnet]
        else:
            cmd_list = ['sudo', 'nmap', '-sn', target_subnet]
        
        cmd = " ".join(cmd_list)
        run_proc_and_capture(cmd, log_file=log_file)
        
        reporter.add_report(f"SCAN ({mode.upper()})", target_subnet, "Started", f"Network discovery ({mode})", log_file=log_file)
        add_live_log(f"NETWORK DISCOVERY STARTED: {target_subnet}", "info")
        
        return jsonify({'status': 'success', 'message': f'Discovery started on {target_subnet}'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/devices/update', methods=['POST'])
def update_device():
    data = request.get_json()
    device_id = data.get('id')
    notes = data.get('notes')
    tags = data.get('tags')
    
    device = device_manager.update_metadata(device_id, notes, tags)
    if device:
        return jsonify({'status': 'success', 'device': device})
    return jsonify({'error': 'Device not found'}), 404

@app.route('/api/devices/select', methods=['POST'])
def select_device():
    data = request.get_json()
    device_id = data.get('id')
    device = device_manager.select(device_id)
    if device:
        return jsonify({'status': 'success', 'device': device})
    return jsonify({'error': 'Device not found'}), 404

@app.route('/api/devices/selected')
def get_selected_device():
    return jsonify({'device': device_manager.get_selected()})

@app.route('/api/devices/clear', methods=['POST'])
def clear_devices():
    device_manager.clear()
    return jsonify({'status': 'success'})

# State
CURRENT_TARGET = None
SCAN_RUNNING = False

@app.route('/api/interfaces')
def list_interfaces():
    """List UP network interfaces and their IPs"""
    try:
        if not psutil:
            return jsonify({'error': 'psutil dependency missing. Please run build_voidpwn.sh again.'}), 500
            
        interfaces = []
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        
        for name, stat in stats.items():
            if stat.isup and name != 'lo':
                ip = "N/A"
                if name in addrs:
                    for addr in addrs[name]:
                        if addr.family == 2: # AF_INET
                            ip = addr.address
                            break
                interfaces.append({
                    'name': name,
                    'ip': ip,
                    'speed': stat.speed
                })
        return jsonify({'interfaces': interfaces})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/wifi/status')
def wifi_status():
    """Check if connected to internet/network"""
    try:
        # Simplified: just return primary default interface IP
        result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
        ips = result.stdout.strip().split()
        return jsonify({'connected': len(ips) > 0, 'ip': ips[0] if ips else "N/A"})
    except:
        return jsonify({'connected': False, 'ip': "N/A"})

@app.route('/api/target/subnet', methods=['POST'])
def select_subnet_target():
    """Set the current active target to a subnet"""
    global CURRENT_TARGET
    data = request.get_json()
    subnet = data.get('subnet')
    interface = data.get('interface')
    if subnet:
        CURRENT_TARGET = {
            'type': 'subnet', 
            'cidr': subnet, 
            'ssid': subnet, 
            'interface': interface
        }
        return jsonify({'status': 'success', 'target': CURRENT_TARGET})
    return jsonify({'error': 'Subnet required'}), 400

@app.route('/api/target/select', methods=['POST'])
def select_target():
    """Set the current active target"""
    global CURRENT_TARGET
    data = request.get_json()
    CURRENT_TARGET = data
    return jsonify({'status': 'success', 'target': CURRENT_TARGET})

@app.route('/api/logs/live')
def get_live_logs():
    """Get the latest logs for the HUD"""
    return jsonify({'logs': list(LIVE_LOGS)})

@app.route('/api/logs/view/<filename>')
def view_full_log(filename):
    """Read the content of a specific log file (truncated)"""
    # Security: strip any path traversal attempts
    safe_name = os.path.basename(filename)
    log_path = os.path.join(LOGS_DIR, safe_name)
    
    if os.path.exists(log_path):
        try:
            # Read only last 2000 lines for performance
            cmd = f"tail -n 2000 \"{log_path}\""
            result = subprocess.check_output(cmd, shell=True).decode('utf-8', errors='replace')
            return jsonify({'content': result})
        except Exception as e:
            return jsonify({'error': f"Failed to read log: {str(e)}"}), 500
    return jsonify({'error': 'Log file not found'}), 404

@app.route('/api/logs/download/<filename>')
def download_log(filename):
    """Download the full raw log file"""
    safe_name = os.path.basename(filename)
    log_path = os.path.join(LOGS_DIR, safe_name)
    if os.path.exists(log_path):
        return send_from_directory(LOGS_DIR, safe_name, as_attachment=True)
    return jsonify({'error': 'File not found'}), 404

@app.route('/api/action/tft', methods=['POST'])
def action_switch_tft():
    """Switch to TFT output (install_lcd.sh)"""
    try:
        cmd = f"sudo {VOIDPWN_DIR}/scripts/core/install_lcd.sh"
        subprocess.Popen(cmd, shell=True)
        
        reporter.add_report(
            "SYSTEM", 
            "Display", 
            "Rebooting", 
            "Switching to TFT output"
        )
        
        return jsonify({'status': 'success', 'message': 'Switching to TFT & Rebooting...'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/action/hdmi', methods=['POST'])
def action_switch_hdmi():
    """Switch to HDMI output"""
    try:
        script = os.path.join(VOIDPWN_DIR, 'scripts', 'core', 'restore_hdmi.sh')
        os.chmod(script, 0o755)
        subprocess.Popen(['bash', script])
        
        reporter.add_report(
            "SYSTEM", 
            "Display", 
            "Rebooting", 
            "Switching to HDMI output"
        )
        
        return jsonify({'status': 'success', 'message': 'Switching to HDMI & Rebooting...'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/action/stop', methods=['POST'])
def action_stop_all():
    """Stop all active attacks and scans"""
    global SCAN_RUNNING
    try:
        # Kill common attack tools
        tools = ['aireplay-ng', 'airodump-ng', 'airbase-ng', 'wifite', 'bettercap', 'hcxdumptool', 'mdk4', 'nmap', 'reaver', 'bully']
        for tool in tools:
            subprocess.run(['sudo', 'killall', tool], stderr=subprocess.DEVNULL)
            
        SCAN_RUNNING = False
        add_live_log("🛑 STOPPED ALL ATTACKS", "error")
        return jsonify({'status': 'success', 'message': 'All active attacks stopped.'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/target/current')
def get_target():
    """Get current target"""
    return jsonify({'target': CURRENT_TARGET})

@app.route('/api/scan/start')
def start_scan():
    """Start a background airodump scan for attacks"""
    global SCAN_RUNNING
    try:
        # Use wifi_tools.sh to perform scan
        output_dir = os.path.join(VOIDPWN_DIR, 'output', 'captures')
        os.makedirs(output_dir, exist_ok=True)
        
        # Kill any existing scans
        subprocess.run(['sudo', 'killall', 'airodump-ng'], stderr=subprocess.DEVNULL)
        
        # Clean old scan results
        output_base = os.path.join(output_dir, 'scan_results')
        subprocess.run(f"sudo rm -f {output_base}*", shell=True, stderr=subprocess.DEVNULL)
        
        # Start scan using wifi_tools.sh --scan (15 second scan)
        cmd = f"sudo {VOIDPWN_DIR}/scripts/network/wifi_tools.sh --scan"
        subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        SCAN_RUNNING = True
        
        reporter.add_report(
            "SCAN", 
            "WiFi Networks", 
            "Running", 
            "15-second network scan started"
        )
        
        return jsonify({'status': 'success', 'message': 'Scan started', 'duration': 15})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/stop')
def stop_scan():
    """Stop the background airodump scan"""
    global SCAN_RUNNING
    try:
        subprocess.run(['sudo', 'killall', 'airodump-ng'], stderr=subprocess.DEVNULL)
        SCAN_RUNNING = False
        reporter.add_report("SCAN", "WiFi Networks", "Stopped", "Network scan stopped")
        return jsonify({'status': 'success', 'message': 'Scan stopped'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/results')
def get_scan_results():
    """Parse airodump CSV and return networks"""
    output_dir = os.path.join(VOIDPWN_DIR, 'output', 'captures')
    
    # Return empty if scan is running but no file yet
    try:
        files = glob.glob(os.path.join(output_dir, '*.csv'))
        if not files:
            if SCAN_RUNNING:
                return jsonify({'networks': [], 'message': 'Scan running, no results yet.'})
            return jsonify({'networks': []})
            
        latest = max(files, key=os.path.getctime)
        
        networks = []
        with open(latest, 'r', encoding='utf-8', errors='replace') as f:
            reader = csv.reader(f)
            # Airodump CSV format is messy, simplified parsing:
            section = 0 # 0=header, 1=networks, 2=stations
            for row in reader:
                if not row or len(row) < 2: continue
                if row[0].strip() == 'BSSID':
                    section = 1
                    continue
                if row[0].strip() == 'Station MAC':
                    section = 2
                    continue
                    
                if section == 1:
                    # BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
                    if len(row) >= 14:
                        networks.append({
                            'bssid': row[0].strip(),
                            'channel': row[3].strip(),
                            'privacy': row[5].strip(),
                            'power': row[8].strip(),
                            'essid': row[13].strip()
                        })
                        
        return jsonify({'networks': networks})
    except Exception as e:
        return jsonify({'error': str(e), 'networks': []})


@app.route('/api/action/monitor/on')
def action_monitor_on():
    """Enable monitor mode"""
    try:
        cmd = f"sudo {VOIDPWN_DIR}/scripts/network/wifi_tools.sh --monitor-on"
        subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        reporter.add_report("WIFI (MONITOR-ON)", "Interface", "Success", "Enabled Monitor Mode")
        return jsonify({'status': 'success', 'message': 'Monitor mode enabling...'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/action/monitor/off')
def action_monitor_off():
    """Disable monitor mode"""
    try:
        cmd = f"sudo {VOIDPWN_DIR}/scripts/network/wifi_tools.sh --monitor-off"
        subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        reporter.add_report("WIFI (MONITOR-OFF)", "Interface", "Success", "Disabled Monitor Mode")
        return jsonify({'status': 'success', 'message': 'Monitor mode disabling...'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/action/evil_twin', methods=['POST'])
def action_evil_twin():
    """Start Evil Twin attack on current target"""
    for tool in ('hostapd', 'dnsmasq', 'iptables', 'python3'):
        if not check_tool(tool):
            return jsonify({'error': f'{tool} is not installed. Run: sudo apt install {tool}'}), 400
    if not CURRENT_TARGET:
        return jsonify({'status': 'error', 'message': 'No target selected!'}), 400
        
    ssid = CURRENT_TARGET.get('essid', 'Free WiFi')
    channel = CURRENT_TARGET.get('channel', '6')
    
    try:
        log_file = gen_log_name(f"eviltwin_{ssid}")
        cmd = f"sudo {VOIDPWN_DIR}/scripts/network/wifi_tools.sh --evil-twin \"{ssid}\" {channel}"
        
        report = reporter.add_report(
            "WIFI (EVIL TWIN)", 
            ssid, 
            "Started", 
            f"Launched Evil Twin on Ch {channel}",
            log_file=log_file
        )
        
        run_proc_and_capture(cmd, log_file=log_file, report_id=report['id'])
        
        return jsonify({'status': 'success', 'message': f'Starting Evil Twin on {ssid}...'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/action/deauth', methods=['POST'])
def action_display_deauth():
    """Deauth current target"""
    if not check_tool('aireplay-ng'):
        return jsonify({'error': 'aireplay-ng not installed. Run: sudo apt install aircrack-ng'}), 400
    if not CURRENT_TARGET:
        return jsonify({'status': 'error', 'message': 'No target selected!'}), 400
        
    bssid = CURRENT_TARGET.get('bssid')
    ssid = CURRENT_TARGET.get('essid', 'Unknown')
    
    channel = CURRENT_TARGET.get('channel', '')
    
    try:
        log_file = gen_log_name(f"deauth_{ssid}")
        cmd = f"sudo {VOIDPWN_DIR}/scripts/network/wifi_tools.sh --deauth {shlex.quote(str(bssid))} 0 {shlex.quote(str(channel))}"
        
        report = reporter.add_report(
            "WIFI (DEAUTH)", 
            ssid, 
            "Running", 
            f"Deauthing BSSID {bssid} (Ch {channel})",
            log_file=log_file
        )
        
        run_proc_and_capture(cmd, log_file=log_file, report_id=report['id'])
        
        return jsonify({'status': 'success', 'message': f'Deauthing {bssid}...'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/action/reboot')
def action_reboot():
    """Reboot system"""
    try:
        subprocess.Popen(['sudo', 'reboot'])
        return jsonify({'status': 'success', 'message': 'System rebooting...'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/action/shutdown')
def action_shutdown():
    """Shutdown system"""
    try:
        subprocess.Popen(['sudo', 'shutdown', 'now'])
        return jsonify({'status': 'success', 'message': 'System shutting down...'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/action/restore_hdmi')
def action_restore_hdmi():
    """Switch to HDMI output"""
    try:
        script = os.path.join(VOIDPWN_DIR, 'scripts', 'core', 'restore_hdmi.sh')
        os.chmod(script, 0o755)
        subprocess.Popen(['bash', script])
        
        reporter.add_report(
            "SYSTEM", 
            "Display", 
            "Rebooting", 
            "Switching to HDMI output"
        )
        
        return jsonify({'status': 'success', 'message': 'Switching to HDMI & Rebooting...'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/action/handshake', methods=['POST'])
def action_handshake():
    """Capture WPA Handshake"""
    if not check_tool('airodump-ng'):
        return jsonify({'error': 'airodump-ng not installed. Run: sudo apt install aircrack-ng'}), 400
    if not CURRENT_TARGET:
        return jsonify({'status': 'error', 'message': 'No target selected!'}), 400

    bssid = CURRENT_TARGET.get('bssid')
    channel = CURRENT_TARGET.get('channel')
    ssid = CURRENT_TARGET.get('essid', 'Unknown')
    
    try:
        log_file = gen_log_name(f"handshake_{ssid}")
        cmd = f"sudo {VOIDPWN_DIR}/scripts/network/wifi_tools.sh --handshake {shlex.quote(str(bssid))} {shlex.quote(str(channel))} {shlex.quote(str(ssid))}"
        
        report = reporter.add_report(
            "WIFI (HANDSHAKE)", 
            ssid, 
            "Started", 
            f"Capturing Handshake on Ch {channel}",
            log_file=log_file
        )
        
        run_proc_and_capture(cmd, log_file=log_file, report_id=report['id'])
        
        return jsonify({'status': 'success', 'message': f'Capturing handshake for {ssid}...'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/action/crack', methods=['POST'])
def action_crack():
    """Crack latest handshake"""
    if not check_tool('aircrack-ng'):
        return jsonify({'error': 'aircrack-ng not installed. Run: sudo apt install aircrack-ng'}), 400
    # Find latest .cap file
    try:
        files = glob.glob(os.path.join(CAPTURES_DIR, '*.cap'))
        if not files:
            return jsonify({'status': 'error', 'message': 'No capture files found!'}), 400
            
        latest_cap = max(files, key=os.path.getctime)
        filename = os.path.basename(latest_cap)
        log_file = gen_log_name("crack")
        
        report = reporter.add_report(
            "WIFI (CRACK)",
            filename,
            "Running",
            "Wordlist attack initiated",
            log_file=log_file
        )
        cmd = f"sudo {VOIDPWN_DIR}/scripts/network/wifi_tools.sh --crack \"{latest_cap}\""
        run_proc_and_capture(cmd, log_file=log_file, report_id=report['id'])
        add_live_log(f"CRACKING STARTED: {filename}", "info")
        return jsonify({'status': 'success', 'message': f'Cracking {filename}...'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/action/wifite', methods=['POST'])
def action_wifite():
    """Launch automated Wifite attack"""
    if not check_tool('wifite'):
        return jsonify({'error': 'wifite not installed. Run: sudo apt install wifite'}), 400
    log_file = gen_log_name("wifite")
    try:
        report = reporter.add_report(
            "WIFI (AUTO-ATTACK)", 
            "ALL", 
            "Started", 
            "Automated Wifite Attack",
            log_file=log_file
        )
        
        cmd = f"sudo {VOIDPWN_DIR}/scripts/network/wifi_tools.sh --auto-attack"
        run_proc_and_capture(cmd, log_file=log_file, report_id=report['id'])
        add_live_log("WIFITE AUTO-ATTACK STARTED", "info")
        return jsonify({'status': 'success', 'message': 'Launched Wifite Auto-Attack'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/action/recon', methods=['POST'])
def action_recon():
    """Run Nmap Recon"""
    data = request.get_json()
    target = data.get('target')
    mode = data.get('mode', 'quick') # quick, full, stealth, vuln
    
    if not target:
        return jsonify({'error': 'Target required'}), 400

    # Sanitize target: allow only IPs, CIDRs, and simple domain names
    if not re.match(r'^[a-zA-Z0-9\.\-\/: ]+$', target) or len(target) > 100:
        return jsonify({'error': 'Invalid target format'}), 400
        
    # Sanitize mode to whitelist only
    allowed_modes = {'quick', 'full', 'stealth', 'vuln', 'web', 'smb', 'dns', 'discover', 'comprehensive'}
    if mode not in allowed_modes:
        return jsonify({'error': 'Invalid mode'}), 400
        
    try:
        log_file = gen_log_name(f"recon_{mode}")
        flag = f"--{mode}"
        cmd = f"sudo {VOIDPWN_DIR}/scripts/network/recon.sh {flag} \"{target}\""
        
        report = reporter.add_report(
            f"RECON ({mode.upper()})", 
            target, 
            "Started", 
            f"Mode: {mode.upper()}",
            log_file=log_file
        )
        
        run_proc_and_capture(cmd, log_file=log_file, report_id=report['id'])
        return jsonify({'status': 'success', 'message': f'Starting {mode} scan on {target}...'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/action/pmkid', methods=['POST'])
def action_pmkid():
    """Capture PMKID (Clientless)"""
    if not check_tool('hcxdumptool'):
        return jsonify({'error': 'hcxdumptool not installed. Run: sudo apt install hcxdumptool'}), 400
    data = request.get_json() or {}
    duration = data.get('duration', 300)
    try:
        duration = int(duration)
    except (ValueError, TypeError):
        return jsonify({'error': 'duration must be an integer (seconds)'}), 400

    log_file = gen_log_name("pmkid")
    try:
        report = reporter.add_report(
            "WIFI (PMKID)",
            "ALL",
            "Running",
            f"Capture running for {duration}s",
            log_file=log_file
        )
        cmd = f"sudo {VOIDPWN_DIR}/scripts/network/wifi_tools.sh --pmkid {shlex.quote(str(duration))}"
        run_proc_and_capture(cmd, log_file=log_file, report_id=report['id'])
        return jsonify({'status': 'success', 'message': f'PMKID capture started ({duration}s)...'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/action/beacon', methods=['POST'])
def action_beacon():
    """MDK4 Beacon Flood"""
    if not check_tool('mdk4'):
        return jsonify({'error': 'mdk4 not installed. Run: sudo apt install mdk4'}), 400
    data = request.get_json() or {}
    ssid_file = data.get('ssid_file', '')

    log_file = gen_log_name("beacon")
    try:
        report = reporter.add_report(
            "WIFI (BEACON)",
            "CHAOS",
            "Running",
            "MDK4 Beacon Flooding active",
            log_file=log_file
        )
        if ssid_file:
            ssid_file_abs = os.path.realpath(ssid_file)
            if not ssid_file_abs.startswith(VOIDPWN_DIR):
                return jsonify({'error': 'Invalid ssid_file path'}), 400
            cmd = f"sudo {VOIDPWN_DIR}/scripts/network/wifi_tools.sh --beacon {shlex.quote(ssid_file_abs)}"
        else:
            cmd = f"sudo {VOIDPWN_DIR}/scripts/network/wifi_tools.sh --beacon"
        run_proc_and_capture(cmd, log_file=log_file, report_id=report['id'])
        return jsonify({'status': 'success', 'message': 'Beacon flood started...'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/action/auth', methods=['POST'])
def action_auth_flood():
    """MDK4 Auth Flood"""
    if not check_tool('mdk4'):
        return jsonify({'error': 'mdk4 not installed. Run: sudo apt install mdk4'}), 400
    data = request.get_json() or {}
    target = data.get('target', '')

    log_file = gen_log_name("auth_flood")
    try:
        report = reporter.add_report(
            "WIFI (AUTH)",
            target or "ALL",
            "Running",
            "MDK4 Authentication Flooding active",
            log_file=log_file
        )
        cmd = f"sudo {VOIDPWN_DIR}/scripts/network/wifi_tools.sh --auth \"{target}\""
        run_proc_and_capture(cmd, log_file=log_file, report_id=report['id'])
        return jsonify({'status': 'success', 'message': f'Auth flood against {target or "ALL"} started...'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/action/pixie', methods=['POST'])
def action_pixie():
    """WPS Pixie-Dust attack"""
    if not check_tool('reaver'):
        return jsonify({'error': 'reaver not installed. Run: sudo apt install reaver'}), 400
    data = request.get_json() or {}
    target = data.get('target', '')

    if not target:
        return jsonify({'error': 'Target BSSID required'}), 400

    log_file = gen_log_name("pixie")
    try:
        report = reporter.add_report(
            "WIFI (PIXIE)",
            target,
            "Running",
            "WPS Pixie-Dust attack initiated",
            log_file=log_file
        )
        cmd = f"sudo {VOIDPWN_DIR}/scripts/network/wifi_tools.sh --pixie \"{target}\""
        run_proc_and_capture(cmd, log_file=log_file, report_id=report['id'])
        return jsonify({'status': 'success', 'message': f'Pixie-Dust attack launched on {target}...'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- MITM & Credential Intercept Endpoints ---
MITM_TOOLS_SCRIPT = os.path.join(VOIDPWN_DIR, 'scripts', 'network', 'mitm_tools.sh')

@app.route('/api/action/bettercap', methods=['POST'])
def action_bettercap():
    """Bettercap full MITM (ARP poison + credential sniff)"""
    if not check_tool('bettercap'):
        return jsonify({'error': 'bettercap not installed. Run: sudo apt install bettercap'}), 400
    data = request.get_json() or {}
    target = data.get('target', '')
    interface = data.get('interface', '')

    # Validate optional target IP
    if target and not re.match(r'^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$', target):
        return jsonify({'error': 'Invalid target IP'}), 400

    log_file = gen_log_name("bettercap_mitm")
    try:
        report = reporter.add_report("MITM (BETTERCAP)", target or "SUBNET", "Running",
                            "ARP poison + credential sniff active", log_file=log_file)
        cmd = f"sudo {MITM_TOOLS_SCRIPT} --bettercap"
        if interface:
            cmd += f" --interface {shlex.quote(interface)}"
        if target:
            cmd += f" --target {shlex.quote(target)}"
        run_proc_and_capture(cmd, log_file=log_file, report_id=report['id'])
        return jsonify({'status': 'success', 'message': 'Bettercap MITM started...'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/action/dnsspoof', methods=['POST'])
def action_dnsspoof():
    """Bettercap DNS spoofing"""
    data = request.get_json() or {}
    domain = data.get('domain', '').strip()
    redirect_ip = data.get('redirect_ip', '').strip()
    interface = data.get('interface', '')

    # Both fields required
    if not domain or not redirect_ip:
        return jsonify({'error': 'Both domain and redirect_ip are required'}), 400

    # Validate domain (alphanumeric, dots, hyphens only)
    if not re.match(r'^[a-zA-Z0-9.\-]+$', domain):
        return jsonify({'error': 'Invalid domain format'}), 400

    # Validate redirect IP
    if not re.match(r'^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$', redirect_ip):
        return jsonify({'error': 'Invalid redirect IP'}), 400

    log_file = gen_log_name("dnsspoof")
    try:
        report = reporter.add_report("MITM (DNS-SPOOF)", f"{domain} → {redirect_ip}", "Running",
                            f"Spoofing {domain} to {redirect_ip}", log_file=log_file)
        cmd = f"sudo {MITM_TOOLS_SCRIPT} --dnsspoof --domain {domain} --redirect {redirect_ip}"
        if interface:
            cmd += f" --interface {interface}"
        run_proc_and_capture(cmd, log_file=log_file, report_id=report['id'])
        return jsonify({'status': 'success', 'message': f'DNS Spoof started: {domain} → {redirect_ip}'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/action/eaphammer', methods=['POST'])
def action_eaphammer():
    """WPA Enterprise rogue AP via eaphammer"""
    if not check_tool('/opt/eaphammer/eaphammer'):
        return jsonify({'error': 'eaphammer not found at /opt/eaphammer. Run: sudo scripts/core/build_voidpwn.sh'}), 400
    data = request.get_json() or {}
    ssid = data.get('ssid', 'Corporate-WiFi').strip()
    interface = data.get('interface', '')

    # Basic SSID sanitization
    if not re.match(r'^[a-zA-Z0-9 .\-_]{1,32}$', ssid):
        return jsonify({'error': 'Invalid SSID (max 32 chars, alphanumeric/space/.-_)'}), 400

    log_file = gen_log_name("eaphammer")
    try:
        report = reporter.add_report("WIFI (ENTERPRISE)", ssid, "Running",
                            f"WPA Enterprise rogue AP broadcasting as '{ssid}'", log_file=log_file)
        cmd = f"sudo {MITM_TOOLS_SCRIPT} --eaphammer --ssid \"{ssid}\""
        if interface:
            cmd += f" --interface {interface}"
        run_proc_and_capture(cmd, log_file=log_file, report_id=report['id'])
        return jsonify({'status': 'success', 'message': f'Enterprise AP \"{ssid}\" started...'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/action/pcredz', methods=['POST'])
def action_pcredz():
    """Parse credentials from capture files via PCredz"""
    if not check_tool('/opt/pcredz/Pcredz.py'):
        return jsonify({'error': 'PCredz not found at /opt/pcredz. Run: sudo scripts/core/build_voidpwn.sh'}), 400
    data = request.get_json() or {}
    capture_file = data.get('capture_file', '').strip()

    # If a specific file is provided, validate it (basename only, no path traversal)
    safe_file_path = ''
    if capture_file:
        safe_name = os.path.basename(capture_file)
        # Only allow valid capture file extensions
        if not re.match(r'^[\w\-. ]+\.(cap|pcap|pcapng)$', safe_name):
            return jsonify({'error': 'Invalid capture file name'}), 400
        safe_file_path = os.path.join(CAPTURES_DIR, safe_name)
        if not os.path.isfile(safe_file_path):
            return jsonify({'error': f'Capture file not found: {safe_name}'}), 404

    log_file = gen_log_name("pcredz")
    try:
        report = reporter.add_report("FORENSIC (PCREDZ)", safe_file_path or "LATEST CAPTURE", "Running",
                            "Parsing capture for plaintext credentials", log_file=log_file)
        cmd = f"sudo {MITM_TOOLS_SCRIPT} --pcredz"
        if safe_file_path:
            cmd += f" --file \"{safe_file_path}\""
        run_proc_and_capture(cmd, log_file=log_file, report_id=report['id'])
        return jsonify({'status': 'success', 'message': 'PCredz analysis started...'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/action/throttle', methods=['POST'])
def action_throttle():
    if not check_tool('tc'):
        return jsonify({'error': 'tc not installed. Run: sudo apt install iproute2'}), 400
    if not check_tool('arpspoof'):
        return jsonify({'error': 'arpspoof not installed. Run: sudo apt install dsniff'}), 400
    data = request.get_json() or {}
    target = data.get('target')
    speed = data.get('speed', '1mbit')
    if not target: return jsonify({'error': 'Target required'}), 400
    
    log_file = gen_log_name("throttle")
    try:
        cmd = f"sudo {VOIDPWN_DIR}/scripts/network/wifi_throttle.sh {shlex.quote(str(target))} {shlex.quote(str(speed))}"
        run_proc_and_capture(cmd, log_file=log_file)
        reporter.add_report("NETWORK (THROTTLE)", target, "Running", f"Limiting to {speed}", log_file=log_file)
        return jsonify({'status': 'success', 'message': f'Throttling {target} to {speed}'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- Configuration / Settings ---
CONFIG_FILE = os.path.join(VOIDPWN_DIR, 'output', 'config.json')

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    return {}

def save_config(data):
    try:
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        print(f"Failed to save config: {e}")
        return False

@app.route('/api/settings', methods=['GET'])
def get_settings():
    """Return current settings - API key is masked, never returned in plaintext"""
    cfg = load_config()
    api_key = cfg.get('api_key', '')
    masked = ('*' * (len(api_key) - 4) + api_key[-4:]) if len(api_key) > 4 else ('*' * len(api_key))
    return jsonify({
        'provider': cfg.get('provider', 'gemini'),
        'api_key_masked': masked,
        'has_key': bool(api_key)
    })

@app.route('/api/settings', methods=['POST'])
def save_settings():
    """Save LLM provider and API key to config file"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    cfg = load_config()
    if 'provider' in data:
        cfg['provider'] = data['provider']
    if 'api_key' in data and data['api_key']:
        cfg['api_key'] = data['api_key']
    if save_config(cfg):
        return jsonify({'status': 'success'})
    return jsonify({'error': 'Failed to save configuration'}), 500


# --- AI Analysis ---
def summarize_log(content, max_lines=3000):
    """
    Pre-process raw log content into a structured summary before sending to LLM.
    Extracts key findings: open ports, services, vulnerabilities, OS, errors.
    Returns a condensed structured text block.
    """
    lines = content.splitlines()[:max_lines]

    open_ports = []
    services = []
    vulnerabilities = []
    os_detected = []
    hosts = []
    errors = []
    wifi_networks = []
    handshakes = []
    misc_findings = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        # Nmap open ports
        if re.search(r'\d+/(tcp|udp)\s+open', stripped, re.I):
            open_ports.append(stripped)
        # Service/version lines
        elif re.search(r'\d+/(tcp|udp)\s+open\s+\S+\s+.+', stripped, re.I):
            services.append(stripped)
        # VULNERABLE findings
        elif 'VULNERABLE' in stripped or re.search(r'CVE-\d{4}-\d+', stripped):
            vulnerabilities.append(stripped)
        # OS detection
        elif re.search(r'OS (details|guess|CPE):', stripped, re.I) or re.search(r'Running:', stripped):
            os_detected.append(stripped)
        # Nmap host up
        elif 'Nmap scan report for' in stripped:
            hosts.append(stripped)
        # Handshake captures
        elif re.search(r'(handshake|WPA|PMKID|\.cap)', stripped, re.I):
            handshakes.append(stripped)
        # WiFi networks
        elif re.search(r'(ESSID|BSSID|beacon|channel|privacy)', stripped, re.I):
            wifi_networks.append(stripped)
        # Errors/warnings
        elif re.search(r'\b(error|warning|failed|denied|timeout)\b', stripped, re.I):
            errors.append(stripped)
        # NSE script output / interesting lines
        elif stripped.startswith('|') and len(stripped) > 4:
            misc_findings.append(stripped)

    # Cap each category to avoid token bloat
    def cap(lst, n): return lst[:n]

    summary_parts = [
        "=== STRUCTURED SCAN SUMMARY ===",
        f"Total log lines processed: {len(lines)}",
        "",
    ]

    if hosts:
        summary_parts += [f"--- DISCOVERED HOSTS ({len(hosts)}) ---"] + cap(hosts, 50) + [""]
    if open_ports:
        summary_parts += [f"--- OPEN PORTS ({len(open_ports)}) ---"] + cap(open_ports, 100) + [""]
    if services:
        summary_parts += [f"--- SERVICES & VERSIONS ({len(services)}) ---"] + cap(services, 60) + [""]
    if vulnerabilities:
        summary_parts += [f"--- VULNERABILITIES & CVEs ({len(vulnerabilities)}) ---"] + cap(vulnerabilities, 80) + [""]
    if os_detected:
        summary_parts += [f"--- OS DETECTION ({len(os_detected)}) ---"] + cap(os_detected, 20) + [""]
    if wifi_networks:
        summary_parts += [f"--- WIFI NETWORKS ({len(wifi_networks)}) ---"] + cap(wifi_networks, 40) + [""]
    if handshakes:
        summary_parts += [f"--- HANDSHAKES / CAPTURES ({len(handshakes)}) ---"] + cap(handshakes, 20) + [""]
    if misc_findings:
        summary_parts += [f"--- SCRIPT OUTPUT / FINDINGS ({len(misc_findings)}) ---"] + cap(misc_findings, 60) + [""]
    if errors:
        summary_parts += [f"--- ERRORS & WARNINGS ({len(errors)}) ---"] + cap(errors, 20) + [""]

    if not any([hosts, open_ports, vulnerabilities, wifi_networks]):
        # Fallback: send first 300 lines if nothing structured found
        summary_parts += ["--- RAW LOG EXCERPT (first 300 lines) ---"] + lines[:300]

    return "\n".join(summary_parts)


GEMINI_MODELS = ['gemini-2.5-flash', 'gemini-2.5-flash-lite', 'gemini-2.0-flash']

def call_gemini(api_key, prompt):
    """Call Gemini API with model fallback chain"""
    last_err = None
    for model in GEMINI_MODELS:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        payload = json.dumps({
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.3, "maxOutputTokens": 4096}
        }).encode('utf-8')
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=90) as resp:
                result = json.loads(resp.read().decode('utf-8'))
            return result['candidates'][0]['content']['parts'][0]['text']
        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8', errors='replace')
            if e.code == 404 or 'not found' in body.lower() or 'not supported' in body.lower():
                last_err = e
                continue  # Try next model
            raise  # Re-raise non-model-not-found errors (auth, etc.)
    raise last_err or Exception(f"No working Gemini model found. Tried: {', '.join(GEMINI_MODELS)}")


def call_groq(api_key, prompt):
    url = "https://api.groq.com/openai/v1/chat/completions"
    payload = json.dumps({
        "model": "llama-3.3-70b-versatile",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
        "max_tokens": 4096
    }).encode('utf-8')
    req = urllib.request.Request(url, data=payload, headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }, method="POST")
    with urllib.request.urlopen(req, timeout=60) as resp:
        result = json.loads(resp.read().decode('utf-8'))
    return result['choices'][0]['message']['content']


def call_openai(api_key, prompt):
    url = "https://api.openai.com/v1/chat/completions"
    payload = json.dumps({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
        "max_tokens": 4096
    }).encode('utf-8')
    req = urllib.request.Request(url, data=payload, headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }, method="POST")
    with urllib.request.urlopen(req, timeout=60) as resp:
        result = json.loads(resp.read().decode('utf-8'))
    return result['choices'][0]['message']['content']


@app.route('/api/ai/analyze', methods=['POST'])
def ai_analyze():
    """
    Analyze a scan report using an LLM.
    Reads the log file, pre-processes it into a structured summary,
    then sends to the configured LLM with a checklist-driven prompt.
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    log_filename = data.get('log_filename')
    checklist = data.get('checklist', [])
    report_type = data.get('report_type', 'network scan')

    if not checklist:
        return jsonify({'error': 'Select at least one analysis section'}), 400

    # Load config
    cfg = load_config()
    api_key = cfg.get('api_key', '').strip()
    provider = cfg.get('provider', 'gemini')

    if not api_key:
        return jsonify({'error': 'No API key configured. Go to System > AI Configuration to add your key.'}), 400

    # Load log file content
    log_content = ""
    if log_filename:
        safe_name = os.path.basename(log_filename)
        log_path = os.path.join(LOGS_DIR, safe_name)
        if os.path.exists(log_path):
            try:
                with open(log_path, 'r', errors='replace') as f:
                    log_content = f.read()
            except Exception as e:
                return jsonify({'error': f'Failed to read log file: {str(e)}'}), 500

    # Pre-process into structured summary
    if log_content:
        structured_summary = summarize_log(log_content)
    else:
        structured_summary = f"No log file available. Report type: {report_type}"

    # Build sections string from checklist
    sections = "\n".join(f"- {item}" for item in checklist)

    # Build LLM prompt
    system_context = (
        "You are a senior penetration tester and security analyst with 15 years of experience. "
        "You have been given a structured summary of a pentest/network scan. "
        "Produce a professional, clear security report covering ONLY the sections requested. "
        "For each vulnerability or finding, include: description, severity (Critical/High/Medium/Low/Info), "
        "and specific actionable remediation steps. Use markdown formatting."
    )

    prompt = f"""{system_context}

SCAN TYPE: {report_type}

STRUCTURED SCAN DATA:
{structured_summary}

REQUESTED REPORT SECTIONS:
{sections}

Write the full professional security report now, covering each requested section. Be specific and actionable."""

    # Pre-flight: check internet connectivity before attempting API call
    if not check_internet():
        return jsonify({'error': 'No internet connection. AI Analysis requires internet access to reach the LLM API. Connect the Pi to the internet and try again.'}), 502

    try:
        if provider == 'gemini':
            analysis = call_gemini(api_key, prompt)
        elif provider == 'groq':
            analysis = call_groq(api_key, prompt)
        elif provider == 'openai':
            analysis = call_openai(api_key, prompt)
        else:
            return jsonify({'error': f'Unknown provider: {provider}'}), 400

        return jsonify({'analysis': analysis})
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='replace')
        # Try to extract a clean message from the JSON error body
        clean_msg = None
        try:
            err_json = json.loads(body)
            # Gemini: {"error": {"message": "..."}}
            # OpenAI/Groq: {"error": {"message": "..."}}
            clean_msg = (err_json.get('error') or {}).get('message')
        except Exception:
            pass

        # Classify by status code + message content
        body_lower = (clean_msg or body).lower()
        if 'expired' in body_lower or 'api key expired' in body_lower:
            return jsonify({'error': f'Your {provider} API key has expired. Go to System > AI Configuration and update it.'}), 502
        if e.code in (401, 403) or 'invalid' in body_lower or 'unauthorized' in body_lower or 'api key' in body_lower:
            return jsonify({'error': f'Invalid or rejected API key for {provider}. Go to System > AI Configuration and check your key.'}), 502
        if e.code == 429 or 'quota' in body_lower or 'rate limit' in body_lower:
            return jsonify({'error': f'Rate limit / quota exceeded on {provider}. Wait a moment and try again.'}), 502
        if clean_msg:
            return jsonify({'error': f'{provider} error: {clean_msg}'}), 502
        return jsonify({'error': f'LLM API error (HTTP {e.code}): {body[:200]}'}), 502
    except (socket.gaierror, socket.timeout, OSError) as e:
        return jsonify({'error': 'No internet connection. AI Analysis requires internet access to reach the LLM API. Connect the Pi to the internet and try again.'}), 502
    except Exception as e:
        err_str = str(e)
        if 'Name or service not known' in err_str or 'Temporary failure' in err_str or 'Errno -3' in err_str or 'urlopen error' in err_str:
            return jsonify({'error': 'No internet connection. AI Analysis requires internet access to reach the LLM API. Connect the Pi to the internet and try again.'}), 502
        return jsonify({'error': f'LLM request failed: {err_str}'}), 502


# ============================================================
# HexStrike AI Bridge
# ============================================================
HEXSTRIKE_URL = os.environ.get('HEXSTRIKE_URL', 'http://127.0.0.1:8888')
HEXSTRIKE_SCRIPT = os.path.join(VOIDPWN_DIR, 'hexstrike-ai', 'hexstrike_server.py')
TOOL_PROFILE_PATH = os.path.join(VOIDPWN_DIR, 'hexstrike-ai', 'voidpwn_tool_profile.json')
_hexstrike_proc = None  # subprocess.Popen handle


def load_tool_profile():
    """Load the VoidPWN tool whitelist profile."""
    try:
        with open(TOOL_PROFILE_PATH, 'r') as f:
            return json.load(f)
    except Exception:
        return {"available_tools": ["nmap", "gobuster", "nikto", "sqlmap", "hydra", "john", "hashcat", "bettercap", "wifite"]}


def hexstrike_get(path, timeout=5):
    """Proxy a GET to HexStrike server."""
    req = urllib.request.Request(f"{HEXSTRIKE_URL}{path}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode('utf-8'))


def hexstrike_post(path, body, timeout=30):
    """Proxy a POST to HexStrike server."""
    payload = json.dumps(body).encode('utf-8')
    req = urllib.request.Request(
        f"{HEXSTRIKE_URL}{path}",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode('utf-8'))


@app.route('/api/hexstrike/status')
def hexstrike_status():
    """Check if HexStrike server is running."""
    try:
        data = hexstrike_get('/health', timeout=3)
        tool_count = len(data.get('tools', data.get('available_tools', [])))
        return jsonify({'online': True, 'tool_count': tool_count, 'version': data.get('version', 'unknown')})
    except Exception:
        return jsonify({'online': False, 'tool_count': 0, 'version': 'N/A'})


@app.route('/api/hexstrike/start', methods=['POST'])
def hexstrike_start():
    """Start the HexStrike server subprocess."""
    global _hexstrike_proc
    if _hexstrike_proc and _hexstrike_proc.poll() is None:
        return jsonify({'status': 'already_running'})
    if not os.path.isfile(HEXSTRIKE_SCRIPT):
        return jsonify({'error': f'hexstrike_server.py not found at {HEXSTRIKE_SCRIPT}'}), 404
    try:
        # Capture stderr so import/startup errors surface in the dashboard log
        _hexstrike_proc = subprocess.Popen(
            ['python3', HEXSTRIKE_SCRIPT],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE
        )
        # Give it 3 seconds — if it crashes immediately we capture why
        import threading
        def _log_stderr(proc):
            try:
                err = proc.stderr.read(4096).decode('utf-8', errors='replace').strip()
                if err:
                    add_live_log(f'⬡ HexStrike stderr: {err[:500]}', 'error')
            except Exception:
                pass
        threading.Thread(target=_log_stderr, args=(_hexstrike_proc,), daemon=True).start()
        add_live_log('⬡ HexStrike AI Engine starting (PID {})...'.format(_hexstrike_proc.pid), 'info')
        return jsonify({'status': 'started', 'pid': _hexstrike_proc.pid})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/hexstrike/stop', methods=['POST'])
def hexstrike_stop():
    """Stop the HexStrike server subprocess."""
    global _hexstrike_proc
    if _hexstrike_proc and _hexstrike_proc.poll() is None:
        _hexstrike_proc.terminate()
        _hexstrike_proc = None
        add_live_log('⬡ HexStrike AI Engine stopped.', 'info')
        return jsonify({'status': 'stopped'})
    return jsonify({'status': 'not_running'})


@app.route('/api/hexstrike/analyze', methods=['POST'])
def hexstrike_analyze():
    """
    Ask HexStrike DecisionEngine to profile the target and build an attack chain.
    Constrains tool selection to VoidPWN's installed toolset via the profile whitelist.
    """
    data = request.get_json() or {}
    target = data.get('target', '').strip()
    objective = data.get('objective', 'comprehensive').strip()

    if not target:
        return jsonify({'error': 'Target is required'}), 400

    # Validate target — IP, CIDR, hostname
    if not re.match(r'^[a-zA-Z0-9.\-/:_]+$', target) or len(target) > 253:
        return jsonify({'error': 'Invalid target format'}), 400

    allowed_objectives = {'comprehensive', 'quick', 'stealth'}
    if objective not in allowed_objectives:
        return jsonify({'error': 'Invalid objective'}), 400

    tool_profile = load_tool_profile()
    allowed = set(tool_profile.get('available_tools', []))
    fallback_map = tool_profile.get('fallback_map', {})

    try:
        # Single call to the real DecisionEngine endpoint — returns target profile +
        # full AttackChain with per-tool optimized parameters from optimize_parameters()
        hs_response = hexstrike_post('/api/intelligence/create-attack-chain', {
            'target': target,
            'objective': objective
        }, timeout=60)
    except Exception as e:
        return jsonify({'error': f'HexStrike offline or unreachable: {str(e)}. Start the engine first.'}), 503

    if not hs_response.get('success'):
        return jsonify({'error': hs_response.get('error', 'DecisionEngine returned no result')}), 502

    raw_profile = hs_response.get('target_profile', {})
    attack_chain = hs_response.get('attack_chain', {})
    raw_steps = attack_chain.get('steps', [])

    # Filter attack chain to tools installed on this device (whitelist enforcement)
    chain = []
    seen = set()
    for step in raw_steps:
        tool_name = step.get('tool', '')
        params = step.get('parameters', {})
        # Substitute excluded/unavailable tools via fallback map
        if tool_name not in allowed:
            tool_name = fallback_map.get(tool_name, '')
        if not tool_name or tool_name not in allowed or tool_name in seen:
            continue
        seen.add(tool_name)
        fallback_tool = fallback_map.get(tool_name, '')
        chain.append({
            'tool': tool_name,
            'parameters': params,          # real per-tool optimized params from DecisionEngine
            'description': step.get('expected_outcome', f'Run {tool_name} against {target}'),
            'estimated_time': step.get('execution_time_estimate', 'varies'),
            'success_probability': step.get('success_probability', 0),
            'fallback': fallback_tool if fallback_tool != tool_name else ''
        })

    return jsonify({
        'target_profile': {
            'target': raw_profile.get('target', target),
            'type': raw_profile.get('target_type', 'unknown'),
            'risk_level': raw_profile.get('risk_level', 'unknown'),
            'attack_surface_score': raw_profile.get('attack_surface_score', 'N/A'),
            'confidence': raw_profile.get('confidence_score', 'N/A'),
            'technologies': raw_profile.get('technologies', [])
        },
        'chain': chain,
        'objective': objective,
        'success_probability': attack_chain.get('success_probability', 0),
        'estimated_time': attack_chain.get('estimated_time', 0)
    })


@app.route('/api/hexstrike/execute', methods=['POST'])
def hexstrike_execute():
    """
    Execute a single tool step from a HexStrike attack chain.
    Streams output to LIVE_LOGS, appends to a mission log file, and
    after the last step calls Gemini to write an AI analysis report.
    """
    data = request.get_json() or {}
    target = data.get('target', '').strip()
    tool = data.get('tool', '').strip()
    objective = data.get('objective', 'comprehensive')
    step_index = data.get('step_index', 0)
    total_steps = data.get('total_steps', 1)
    mission_id = data.get('mission_id', str(uuid.uuid4()))
    log_file = data.get('log_file', gen_log_name(f'hexstrike_mission'))
    # Optimized parameters supplied by DecisionEngine.optimize_parameters() at analyze time
    step_params = data.get('step_params', {})

    if not target or not tool:
        return jsonify({'error': 'target and tool are required'}), 400

    # Validate tool against whitelist
    profile = load_tool_profile()
    allowed = set(profile.get('available_tools', []))
    if tool not in allowed:
        return jsonify({'error': f'Tool "{tool}" is not in VoidPWN tool whitelist'}), 400

    if not re.match(r'^[a-zA-Z0-9.\-/:_]+$', target) or len(target) > 253:
        return jsonify({'error': 'Invalid target format'}), 400

    add_live_log(f'⬡ HexStrike [{step_index+1}/{total_steps}] executing: {tool} → {target}', 'info')

    # Build payload: start with DecisionEngine's optimized params, then ensure target
    # is set under the right field name (nmap/nikto use 'target', gobuster/sqlmap use 'url').
    def _build_tool_payload(t, params, tgt):
        payload = {k: v for k, v in params.items() if v is not None}
        if 'url' in payload:
            payload['url'] = tgt
        else:
            payload['target'] = tgt
        return payload

    tool_payload = _build_tool_payload(tool, step_params, target)

    try:
        result = hexstrike_post(f'/api/tools/{tool}', tool_payload, timeout=300)
        output = result.get('output', result.get('result', json.dumps(result)))
    except Exception as e:
        # Try fallback tool — use minimal safe payload
        fallback = profile.get('fallback_map', {}).get(tool)
        if fallback and fallback in allowed:
            add_live_log(f'⚡ Auto-recovery: {tool} failed, switching to fallback [{fallback}]', 'info')
            try:
                fb_payload = _build_tool_payload(fallback, step_params, target)
                result = hexstrike_post(f'/api/tools/{fallback}', fb_payload, timeout=300)
                output = result.get('output', result.get('result', json.dumps(result)))
                tool = fallback  # record actual tool used
            except Exception as e2:
                output = f'[ERROR] {tool} and fallback {fallback} both failed: {str(e2)}'
        else:
            output = f'[ERROR] {tool} failed: {str(e)}'

    add_live_log(f'⬡ {tool.upper()} step complete', 'success')

    # Write step output to mission log
    log_path = os.path.join(LOGS_DIR, os.path.basename(log_file))
    try:
        with open(log_path, 'a') as lf:
            lf.write(f'\n\n=== STEP {step_index+1}: {tool.upper()} ===\n')
            lf.write(str(output))
    except Exception:
        pass

    # On last step: generate Gemini AI summary and save full report
    ai_analysis = None
    if step_index + 1 >= total_steps:
        try:
            full_log = ''
            if os.path.exists(log_path):
                with open(log_path, 'r', errors='replace') as lf:
                    full_log = lf.read()

            cfg = load_config()
            api_key = cfg.get('api_key', '').strip()
            provider = cfg.get('provider', 'gemini')

            if api_key and check_internet():
                structured = summarize_log(full_log) if full_log else f'Target: {target}, Objective: {objective}'
                prompt = (
                    f"You are a senior penetration tester reviewing a VoidPWN AI-driven security assessment.\n"
                    f"Target: {target}\nObjective: {objective}\n\n"
                    f"Tool outputs (structured summary):\n{structured}\n\n"
                    f"Provide a professional security report with:\n"
                    f"1. Executive Summary\n"
                    f"2. Key Findings with severity (Critical/High/Medium/Low)\n"
                    f"3. CVE references where applicable\n"
                    f"4. Recommended next steps\n\n"
                    f"Be specific and actionable. Use markdown formatting."
                )
                if provider == 'gemini':
                    ai_analysis = call_gemini(api_key, prompt)
                elif provider == 'groq':
                    ai_analysis = call_groq(api_key, prompt)
                elif provider == 'openai':
                    ai_analysis = call_openai(api_key, prompt)
                add_live_log('⬡ HexStrike AI analysis complete — report saved.', 'success')
        except Exception as e:
            ai_analysis = None
            add_live_log(f'⬡ AI analysis skipped: {str(e)}', 'info')

        # Save full mission report entry
        chain_tools = data.get('chain_tools', [tool])
        report_entry = {
            'id': mission_id,
            'timestamp': datetime.now().isoformat(),
            'type': 'HEXSTRIKE MISSION',
            'target': target,
            'objective': objective,
            'status': 'Completed',
            'details': f'AI-driven {objective} assessment — {len(chain_tools)} tool(s)',
            'hexstrike_chain': chain_tools,
            'tools_executed': total_steps,
            'log_file': os.path.basename(log_file),
            'ai_analysis': ai_analysis
        }
        reporter.reports.insert(0, report_entry)
        reporter._save()

    return jsonify({
        'status': 'success',
        'tool': tool,
        'step': step_index + 1,
        'output_preview': str(output)[:500],
        'log_file': os.path.basename(log_file),
        'mission_id': mission_id,
        'ai_analysis': ai_analysis
    })


@app.route('/api/hexstrike/processes')
def hexstrike_processes():
    """Proxy active process list from HexStrike."""
    try:
        data = hexstrike_get('/api/processes/dashboard', timeout=5)
        return jsonify(data)
    except Exception:
        return jsonify({'processes': [], 'error': 'HexStrike offline'})


if __name__ == '__main__':
    print("Starting VoidPWN Dashboard Server...")
    print("Access dashboard at: http://<PI_IP>:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)
