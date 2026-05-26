"""
ĐỒ ÁN AN NINH MẠNG & HỆ THỐNG NHÚNG: SMART GATEWAY
Chức năng: Sniffer (giám sát mạng), Honeypot (bẫy mật), 
           Detection Engine (phát hiện tấn công), 
           Block Isolation (cô lập 2 tầng), Web Dashboard.
"""
import threading
import time
import os
import sqlite3
from collections import defaultdict
from flask import Flask, jsonify, render_template_string, request
import socket
import subprocess

# Cố gắng import các thư viện phần cứng và phân tích mạng, bỏ qua lỗi nếu chưa cài đặt.
try:
    from scapy.all import sniff, IP
except ImportError:
    pass 

try:
    import serial
except ImportError:
    pass

# --- 1. CẤU HÌNH HỆ THỐNG ---
THRESHOLD_PPS = 50       # Ngưỡng Packets Per Second (vượt mức này bị tính là DDoS)
HONEYPOT_PORT = 23       # Cổng Telnet giả mạo để làm bẫy
FLASK_PORT = 8080        # Cổng chạy Web Dashboard
DB_NAME = 'security_logs.db'

app = Flask(__name__)

# Từ điển đếm số gói tin tích lũy
packet_counts = defaultdict(int)
# Từ điển lưu số PPS thực tế trong chu kỳ 1 giây để hiển thị lên Dashboard
current_pps = {}
# Tập hợp chứa các IP đã bị chặn để không gọi lại iptables nhiều lần
isolated_ips = set()

# --- 2. KHỐI DATABASE (LƯU VẾT) ---
def init_db():
    """Khởi tạo cơ sở dữ liệu SQLite3 tạo bảng SecurityLogs nếu chưa có."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS SecurityLogs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            attack_type TEXT,
            status TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_attack(ip_address, attack_type, status):
    """Lưu vết tấn công vào database."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('INSERT INTO SecurityLogs (ip_address, attack_type, status) VALUES (?, ?, ?)',
              (ip_address, attack_type, status))
    conn.commit()
    conn.close()

# --- 3. KHỐI CÔ LẬP 2 TẦNG (ISOLATION) ---
def isolate_ip(ip_address, attack_type):
    """Thực thi cô lập IP vi phạm bằng cả phần mềm (iptables) và phần cứng (Relay)."""
    # Nếu IP đã bị chặn trước đó thì bỏ qua
    if ip_address in isolated_ips:
        return
    
    isolated_ips.add(ip_address)
    print(f"\n[!] PHÁT HIỆN TẤN CÔNG ({attack_type}) TỪ: {ip_address}")
    
    # Tầng 1: CÔ LẬP PHẦN MỀM (Dùng Tường lửa iptables)
    try:
        # Chèn rule vào Iptables để chặn mọi gói tin forwarding từ IP này
        os.system(f"iptables -I FORWARD -s {ip_address} -j DROP")
        print(f"[+] Tầng 1 (Software): Đã chặn IP {ip_address} bằng iptables.")
    except Exception as e:
        print(f"[-] Lỗi phần mềm (iptables): {e}")

    # Tầng 2: CÔ LẬP PHẦN CỨNG (Dùng Module Relay qua USB Serial)
    try:
        # Giao tiếp với thiết bị qua cổng Serial /dev/ttyUSB0 (baudrate 9600)
        ser = serial.Serial('/dev/ttyUSB0', 9600, timeout=1)
        # Gửi ký tự 'K' (Kill) để vi điều khiển đóng Relay ngắt nguồn hoặc mạng
        ser.write(b'K')
        ser.close()
        print(f"[+] Tầng 2 (Hardware): Đã gửi tín hiệu 'K' qua /dev/ttyUSB0.")
    except Exception as e:
        # Bọc try-except toàn khối để không crash file khi test code trên PC chưa cắm module
        print(f"[-] Lỗi phần cứng (Không tìm thấy giao tiếp tại /dev/ttyUSB0): {e}")

    # Ghi nhận log cuối cùng vào Database
    log_attack(ip_address, attack_type, "Đã cô lập")

# --- 4. KHỐI GIÁM SÁT MẠNG (SNIFFER & DETECTION) ---
def process_packet(packet):
    """Được gọi tự động mỗi khi có một gói tin đi qua interface."""
    if IP in packet:
        # Khai thác địa chỉ IP nguồn (Source IP) từ gói tin
        src_ip = packet[IP].src
        # Tăng biến đếm số lượng gói tin của IP này
        packet_counts[src_ip] += 1

def sniffer_thread():
    """Luồng chuyên trách việc nằm vùng (sniff) bắt các luồng gói tin trên interface mạng."""
    print("[*] Module Sniffer khởi động...")
    try:
        # store=0 giúp tối ưu RAM, bắt xong tính toán chứ không lưu lại
        sniff(prn=process_packet, store=0)
    except Exception as e:
        print(f"[-] Lỗi Sniffer (Lưu ý: Bạn có thể cần chạy bằng quyền sudo/root): {e}")

def pps_calculator_thread():
    """Động Cơ Suy Luận (Detection Engine) đánh giá đường cơ sở mỗi 1 giây."""
    print("[*] Module Detection Engine khởi động...")
    while True:
        # Tạo bản copy danh sách các IP đang được quét ở chu kỳ hiện tại
        keys = list(packet_counts.keys())
        for ip in keys:
            # Lấy số PPS của chu kỳ này
            pps = packet_counts[ip]
            current_pps[ip] = pps
            
            # Reset biến đếm về 0 cho chu kỳ giám sát 1 giây tiếp theo
            packet_counts[ip] = 0 
            
            # Phân tích đường cơ sở: IP vượt Ngưỡng (Threshold) => Đánh dấu DDOS
            if pps > THRESHOLD_PPS:
                isolate_ip(ip, "BOTNET_DDOS")
        
        # Ngủ 1 giây bằng đồng hồ hệ thống để tạo chu kỳ đếm PPS (Packet Per Second)
        time.sleep(1)

# --- 5. KHỐI BẪY MẬT (HONEYPOT) ---
def honeypot_thread():
    """Tạo một cổng mở giả mạo ảo, nhử kẻ tấn công quét cổng mồi (scanning phase)."""
    print(f"[*] Module Honeypot khởi động trên TCP Port {HONEYPOT_PORT}...")
    try:
        # Tạo socket TCP
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Lắng nghe mọi Request đến cổng 23
        s.bind(('0.0.0.0', HONEYPOT_PORT))
        s.listen(5)
        while True:
            conn, addr = s.accept()
            ip = addr[0] # Lấy ra IP của thiết bị cố tình gọi lệnh
            print(f"[!] Bẫy mật báo động: Đã phát hiện dò tìm bất hợp pháp từ {ip}")
            # Vi phạm quy tắc dò quét -> Lập tức Block mà không quan tâm lượng PPS
            isolate_ip(ip, "BOTNET_SCANNING")
            conn.close()
    except Exception as e:
        print(f"[-] Lỗi Honeypot: {e}")

# --- 6. KHỐI DASHBOARD (WEB INTERFACE VỚI FLASK) ---

# Giao diện Dashoard nhúng thẳng vào file Python bằng Bootstrap 5 (Dark Mode)
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="vi" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <title>Smart Gateway Dashboard</title>
    <!-- CSS Bootstrap 5 qua CDN -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style> body { padding-bottom: 50px; } </style>
</head>
<body class="container mt-5">
    <h1 class="mb-4 text-center text-primary">🛡️ Smart Gateway Dashboard</h1>
    <hr>
    
    <div class="row mt-4">
        <!-- Bảng hiển thị thông số nhảy PPS -->
        <div class="col-md-5">
            <h4 class="text-info">📡 Giám sát Phễu Mạng</h4>
            <div class="table-responsive">
                <table class="table table-dark table-hover table-bordered text-center align-middle mt-3">
                    <thead class="table-secondary">
                        <tr><th>Địa chỉ IP Nguồn</th><th>Tần suất (PPS)</th></tr>
                    </thead>
                    <tbody id="pps-body">
                        <!-- DOM inject bằng JS -->
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Bảng hiển thị dữ liệu cô lập (Security Logs) -->
        <div class="col-md-7">
            <h4 class="text-warning">⚠️ Lịch sử Tấn công</h4>
            <div class="table-responsive">
                <table class="table table-dark table-striped table-bordered text-center mt-3">
                    <thead>
                        <tr><th>ID</th><th>Thời gian</th><th>IP Vi phạm</th><th>Loại Tấn công</th><th>Trạng thái</th></tr>
                    </thead>
                    <tbody id="logs-body">
                        <!-- DOM inject bằng JS -->
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- KHỐI QUẢN LÝ FIREWALL -->
    <div class="row mt-5">
        <div class="col-md-12">
            <h4 class="text-success">🧱 Quản lý Tường lửa (Iptables - FORWARD)</h4>
            <div class="card bg-dark border-secondary mb-3 mt-3">
                <div class="card-body">
                    <form id="addRuleForm" class="row g-3 align-items-center">
                        <div class="col-auto">
                            <label class="visually-hidden" for="fwIp">Thiệt bị / IP</label>
                            <input type="text" class="form-control" id="fwIp" placeholder="Địa chỉ IP (VD: 192.168.1.100)" required>
                        </div>
                        <div class="col-auto">
                            <select class="form-select" id="fwAction">
                                <option value="DROP">DROP (Chặn)</option>
                                <option value="ACCEPT">ACCEPT (Cho phép)</option>
                            </select>
                        </div>
                        <div class="col-auto">
                            <button type="submit" class="btn btn-success">Thêm Rule</button>
                        </div>
                    </form>
                </div>
            </div>
            <div class="table-responsive">
                <table class="table table-dark table-hover table-bordered text-center align-middle">
                    <thead class="table-secondary">
                        <tr><th>Line</th><th>Hành động (Target)</th><th>Giao thức</th><th>Nguồn (Source)</th><th>Đích (Destination)</th><th>Thao tác</th></tr>
                    </thead>
                    <tbody id="firewall-body">
                        <!-- DOM inject -->
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        // Hàm gọi API mỗi giây để Render lại giao diện Data, tạo hiệu ứng Real-time Dashboard
        function updateStats() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    // Update bảng Live Traffic (PPS)
                    let ppsHtml = '';
                    for (const [ip, pps] of Object.entries(data.current_pps)) {
                        // IP nào sát ngưỡng thì cảnh báo màu đỏ
                        let rowClass = pps > 40 ? 'table-danger' : '';
                        ppsHtml += `<tr class="${rowClass}"><td>${ip}</td><td>${pps} packets/sec</td></tr>`;
                    }
                    document.getElementById('pps-body').innerHTML = ppsHtml;
                    
                    // Update bảng Security Logs quét từ CSDL
                    let logsHtml = '';
                    data.logs.forEach(log => {
                        // Cấu trúc log trả về: [ID, Timestamp, IP, Loại Tấn công, Trạng thái]
                        logsHtml += `<tr>
                            <td>${log[0]}</td>
                            <td>${log[1]}</td>
                            <td>${log[2]}</td>
                            <td><span class="badge bg-warning text-dark">${log[3]}</span></td>
                            <td><span class="badge bg-danger">${log[4]}</span></td>
                        </tr>`;
                    });
                    document.getElementById('logs-body').innerHTML = logsHtml;
                });
        }
        
        // Cập nhật bảng Tường lửa
        function loadFirewall() {
            fetch('/api/firewall')
                .then(response => response.json())
                .then(data => {
                    let html = '';
                    data.rules.forEach(rule => {
                        let targetClass = rule.target === 'DROP' ? 'bg-danger' : (rule.target === 'ACCEPT' ? 'bg-success' : 'bg-secondary');
                        html += `<tr>
                            <td>${rule.line}</td>
                            <td><span class="badge ${targetClass}">${rule.target}</span></td>
                            <td>${rule.prot}</td>
                            <td>${rule.source}</td>
                            <td>${rule.destination}</td>
                            <td>
                                <button class="btn btn-sm btn-primary m-1" onclick="editRule(${rule.line}, '${rule.source}', '${rule.target}')">Trình sửa</button>
                                <button class="btn btn-sm btn-danger m-1" onclick="deleteRule(${rule.line})">Xóa</button>
                            </td>
                        </tr>`;
                    });
                    document.getElementById('firewall-body').innerHTML = html;
                });
        }

        function deleteRule(line) {
            if(confirm('Bạn có chắc muốn xóa rule số ' + line + ' này?')) {
                fetch('/api/firewall/' + line, { method: 'DELETE' })
                    .then(() => loadFirewall());
            }
        }

        function editRule(line, ip, currentAction) {
            let newIp = prompt("Nhập IP thay thế:", ip !== '0.0.0.0/0' ? ip : '');
            if(newIp !== null && newIp.trim() !== '') {
                let newAction = prompt("Nhập Hành động (DROP/ACCEPT):", currentAction);
                if(newAction === 'DROP' || newAction === 'ACCEPT') {
                    fetch('/api/firewall/' + line, {
                        method: 'PUT',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ip: newIp.trim(), action: newAction.toUpperCase()})
                    }).then(() => loadFirewall());
                } else {
                    alert('Hành động không hợp lệ!');
                }
            }
        }

        document.getElementById('addRuleForm').addEventListener('submit', function(e) {
            e.preventDefault();
            let ip = document.getElementById('fwIp').value;
            let action = document.getElementById('fwAction').value;
            fetch('/api/firewall', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ip: ip, action: action})
            }).then(() => {
                document.getElementById('fwIp').value = '';
                loadFirewall();
            });
        });

        // Vòng lặp
        setInterval(updateStats, 1000);
        updateStats();
        
        loadFirewall();
        setInterval(loadFirewall, 5000); // Tự động làm mới danh sách rules
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    """Route UI chính, render template HTML đính kèm."""
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/firewall', methods=['GET'])
def get_firewall_rules():
    """API Webserver trả về danh sách các rules hiện tại trong chain FORWARD."""
    try:
        # Lấy output từ lệnh iptables
        result = subprocess.check_output("iptables -L FORWARD -n --line-numbers", shell=True, stderr=subprocess.STDOUT).decode()
        rules = []
        # Bỏ qua 2 dòng tiêu đề đầu tiên
        for line in result.strip().split('\n')[2:]:
            parts = line.split()
            if len(parts) >= 6:
                rules.append({
                    "line": parts[0],
                    "target": parts[1],
                    "prot": parts[2],
                    "source": parts[4],
                    "destination": parts[5]
                })
        return jsonify({"rules": rules})
    except Exception as e:
        print(f"[-] Lỗi đọc iptables: {e}")
        return jsonify({"rules": []})

@app.route('/api/firewall', methods=['POST'])
def add_firewall_rule():
    """API Webserver thêm một rule mới (Chèn vào đầu danh sách)"""
    data = request.json
    action = data.get('action', 'DROP')
    ip = data.get('ip')
    if ip:
        # -I để chèn lên đầu
        os.system(f"iptables -I FORWARD -s {ip} -j {action}")
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "message": "Thiếu thông tin IP"}), 400

@app.route('/api/firewall/<line_number>', methods=['PUT'])
def modify_firewall_rule(line_number):
    """API Webserver sửa một rule (Thay thế rule ở line chỉ định)"""
    data = request.json
    action = data.get('action', 'DROP')
    ip = data.get('ip')
    if ip:
        # -R để Replace (sửa) rule
        os.system(f"iptables -R FORWARD {line_number} -s {ip} -j {action}")
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "message": "Thiếu thông tin IP"}), 400

@app.route('/api/firewall/<line_number>', methods=['DELETE'])
def delete_firewall_rule(line_number):
    """API Webserver xóa một rule theo line number"""
    # -D để xóa rule
    os.system(f"iptables -D FORWARD {line_number}")
    return jsonify({"status": "success"})

@app.route('/api/stats')
def api_stats():
    """API Webserver trả về luồng trạng thái máy chủ (Json) theo thời gian thực."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    # Query 15 bản ghi tấn công mới nhất để vẽ UI
    c.execute('SELECT * FROM SecurityLogs ORDER BY id DESC LIMIT 15')
    logs = c.fetchall()
    conn.close()
    
    return jsonify({
        "current_pps": current_pps,
        "logs": logs
    })

def flask_thread():
    """Khởi chạy máy chủ nội bộ Flask."""
    print(f"[*] Module Web UI khởi động. Truy cập Web tại http://<IP_GATEWAY>:{FLASK_PORT} ...")
    # Tắt use_reloader để không xung đột vòng lặp đa luồng (threading)
    app.run(host='0.0.0.0', port=FLASK_PORT, debug=False, use_reloader=False)

# --- 7. CHƯƠNG TRÌNH KHỞI TẠO CHÍNH ---
if __name__ == '__main__':
    # 1. Chuẩn bị file CSDL
    init_db()
    
    print("="*60)
    print("  🚀 HỆ THỐNG PHÒNG THỦ SMART GATEWAY ĐANG ĐƯỢC CHẠY...")
    print("="*60)

    # 2. Định nghĩa luồng (Threading) - Thuộc tính daemon=True sẽ hủy luồng con nếu luồng tiến trình chính tắt
    t_sniff = threading.Thread(target=sniffer_thread, daemon=True)
    t_pps   = threading.Thread(target=pps_calculator_thread, daemon=True)
    t_honey = threading.Thread(target=honeypot_thread, daemon=True)
    t_flask = threading.Thread(target=flask_thread, daemon=True)

    # 3. Kích hoạt toàn bộ Modules
    t_sniff.start()
    t_pps.start()
    t_honey.start()
    t_flask.start()

    # 4. Ngủ vòng lặp để giữ cho bộ điều khiển Thread sống
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Hệ thống đã dừng lại bởi quản trị viên.")
