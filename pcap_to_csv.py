"""
使用方法：
    python pcap_to_csv.py capture.pcap
    python pcap_to_csv.py capture.pcap output.csv   自定义输出路径
"""

import sys
import csv
from collections import defaultdict

try:
    from scapy.all import rdpcap, IP, TCP, UDP
except ImportError:
    print("错误：请先安装 scapy：pip install scapy")
    sys.exit(1)

def pcap_to_csv(pcap_path, csv_path):
    print(f"正在读取：{pcap_path}")
    packets = rdpcap(pcap_path)
    print(f"共读取 {len(packets)} 个数据包，开始处理...")

    #按五元组聚合会话
    #key: (src_ip, dst_ip, protocol, src_port, dst_port)
    sessions = defaultdict(lambda: {
        "bytes": 0,
        "first_ts": float("inf"),
        "last_ts": 0.0
    })

    skipped = 0
    for pkt in packets:
        if not pkt.haslayer(IP):
            skipped += 1
            continue

        ip = pkt[IP]
        proto = ip.proto
        src_ip = ip.src
        dst_ip = ip.dst
        size = len(pkt)
        ts = float(pkt.time)

        src_port = ""
        dst_port = ""
        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

        key = (src_ip, dst_ip, proto, src_port, dst_port)
        s = sessions[key]
        s["bytes"] += size
        s["first_ts"] = min(s["first_ts"], ts)
        s["last_ts"] = max(s["last_ts"], ts)

    # 写入CSV
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Source", "Destination", "Protocol",
                         "SrcPort", "DstPort", "DataSize", "Duration"])
        for (src_ip, dst_ip, proto, src_port, dst_port), s in sessions.items():
            duration = round(s["last_ts"] - s["first_ts"], 6)
            writer.writerow([src_ip, dst_ip, proto,
                             src_port, dst_port, s["bytes"], duration])

    print(f"完成！共写入 {len(sessions)} 条会话记录")
    print(f"输出文件：{csv_path}")
    print(f"（跳过非IP包：{skipped} 个）")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法：python pcap_to_csv.py <input.pcap> [output.csv]")
        sys.exit(1)

    pcap_file = sys.argv[1]
    csv_file = sys.argv[2] if len(sys.argv) >= 3 else "network_data.csv"

    pcap_to_csv(pcap_file, csv_file)