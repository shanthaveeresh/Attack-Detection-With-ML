import sys
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
from datetime import datetime
import pandas as pd
import os

# Danh sách ánh xạ cổng sang dịch vụ
port_to_service = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    443: 'HTTPS',
    110: 'POP3',
    143: 'IMAP',
    3306: 'MySQL',
    3389: 'RDP',  # Remote Desktop Protocol
    # Thêm dịch vụ khác nếu cần
}

# Biến lưu thông tin kết nối
connections = defaultdict(lambda: {
    'src_bytes': 0,
    'dst_bytes': 0,
    'packet_count': 0,
    'start_time': None,
    'protocol_type': None,
    'flags': set(),
    'syn_count': 0,
    'rej_count': 0
})
total_packets = 0

def get_protocol(packet):
    if packet.haslayer(TCP):
        return 'TCP'
    elif packet.haslayer(UDP):
        return 'UDP'
    else:
        return 'ICMP'

def get_flag(packet):
    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        return str(flags)  # Biến cờ TCP thành chuỗi
    return None

def get_service(packet):
    if packet.haslayer(TCP) or packet.haslayer(UDP):
        src_port = packet.sport
        dst_port = packet.dport
        
        # Kiểm tra cổng nguồn và cổng đích
        service = port_to_service.get(src_port) or port_to_service.get(dst_port)
        if service:
            return service
        else:
            return 'Unknown'  # Không tìm thấy dịch vụ
    return 'Unknown'

# Hàm xử lý gói tin
def packet_handler(packet):
    global total_packets  # Khai báo biến toàn cục
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = get_protocol(packet)
        flag = get_flag(packet)
        service = get_service(packet)
        size = len(packet)
        timestamp = datetime.now()

        # Xác định kết nối
        conn_key = (src_ip, dst_ip, protocol, service)
        conn = connections[conn_key]

        # Cập nhật thông tin kết nối
        conn['src_bytes'] += size if src_ip == conn_key[0] else 0
        conn['dst_bytes'] += size if dst_ip == conn_key[1] else 0
        conn['packet_count'] += 1
        if conn['start_time'] is None:
            conn['start_time'] = timestamp
        conn['protocol_type'] = protocol
        if flag:
            conn['flags'].add(flag)
        conn['service'] = service
        conn['duration'] = (timestamp - conn['start_time']).total_seconds()
        
        # Đếm gói SYN và REJ
        if 'S' in flag:  # SYN
            conn['syn_count'] += 1
        if 'R' in flag:  # REJ
            conn['rej_count'] += 1
        
        # Tăng tổng số gói
        total_packets += 1

# Hàm thu thập và lưu gói tin
def continuous_sniffing(interface, update_interval=15, csv_file="network_connections.csv"):
    global connections, total_packets

    print(f"Listening on interface: {interface}")

    # Kiểm tra nếu file CSV đã tồn tại
    file_exists = os.path.isfile(csv_file)

    while True:
        try:
            # Bắt gói tin
            print(f"Sniffing for {update_interval} seconds...")
            sniff(prn=packet_handler, iface=interface, filter="ip", timeout=update_interval)

            # Chuyển dữ liệu thành DataFrame
            data = []
            for conn_key, conn in connections.items():
                data.append({
                    'ip_source': conn_key[0],
                    'ip_destination': conn_key[1],
                    'duration': conn['duration'],
                    'protocol_type': conn['protocol_type'],
                    'src_bytes': conn['src_bytes'],
                    'dst_bytes': conn['dst_bytes'],
                    'packet_count': conn['packet_count'],
                })

            df = pd.DataFrame(data)

            syn_error_rate = (sum([conn['syn_count'] for conn in connections.values()]) / total_packets)  if total_packets > 0 else 0
            rej_error_rate = (sum([conn['rej_count'] for conn in connections.values()]) / total_packets)  if total_packets > 0 else 0

            # Thêm tỷ lệ lỗi vào DataFrame
            error_data = {
                'syn_error_rate': syn_error_rate,
                'rej_error_rate': rej_error_rate
            }

            error_df = pd.DataFrame([error_data])

            # Thêm tỷ lệ lỗi vào DataFrame data
            df = pd.concat([df, error_df], axis=1)
            
            # Ghi vào file CSV
            with open(csv_file, mode='a', newline='', encoding='utf-8') as f:
                df.to_csv(f, index=False, header=not file_exists)
            file_exists = True
            print(f"Appended data to {csv_file}")

            # Reset connections: Chỉ giữ kết nối đang hoạt động
            active_connections = defaultdict(lambda: {
                'src_bytes': 0,
                'dst_bytes': 0,
                'packet_count': 0,
                'start_time': None,
                'protocol_type': None,
                'flags': set(),
                'service': None,
                'syn_count': 0,
                'rej_count': 0
            })

            for conn_key, conn in connections.items():
                if conn['duration'] <= update_interval:
                    active_connections[conn_key] = conn

            connections = active_connections
            
        except Exception as e:
            print(f"Error: {e}")
            break

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python packet_capture.py <selected_interface>")
        sys.exit(1)

    # Lấy tên giao diện từ tham số dòng lệnh
    interface = " ".join(sys.argv[1:])
    print(f"Starting packet capture on interface: {interface}")

    try:
        # Bắt đầu thu thập gói tin
        continuous_sniffing(interface)
    except KeyboardInterrupt:
        print("\nStopping packet capture.")
        sys.exit(0)
