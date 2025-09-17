import sys
import json
import socket
import time
import threading
from scapy.all import ARP, Ether, IP, sendp, sniff, get_if_hwaddr, srp, conf

# --- 通訊函式 ---
def log(level, message):
    """向前端發送日誌訊息"""
    print(json.dumps({"type": "log", "level": level, "message": message}), flush=True)

def event(event_type, data):
    """向前端發送事件"""
    print(json.dumps({"type": event_type, "data": data}), flush=True)

# --- 網路核心函式 ---
def get_mac_address(ip_address, interface):
    """根據 IP 位址獲取 MAC 位址"""
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=1, iface=interface, verbose=False)
        return ans[0][1].hwsrc if ans else None
    except Exception:
        return None

stop_event_flag = threading.Event()

def arp_spoof(gateway_ip, gateway_mac, target_macs, attacker_mac, interface):
    """持續進行 ARP 欺騙的背景執行緒"""
    while not stop_event_flag.is_set():
        try:
            for target_ip, target_mac in target_macs.items():
                # 欺騙目標電腦
                sendp(Ether(dst=target_mac)/ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwsrc=attacker_mac), iface=interface, verbose=False)
                # 欺騙閘道器
                sendp(Ether(dst=gateway_mac)/ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwsrc=target_mac), iface=interface, verbose=False)
            time.sleep(2)
        except Exception as e:
            log('error', f'Spoofing loop error: {e}')

def restore_arp(gateway_ip, gateway_mac, target_macs, interface):
    """恢復網路 ARP 表"""
    log('info', 'Restoring network for all targets...')
    for target_ip, target_mac in target_macs.items():
        sendp(Ether(dst=target_mac)/ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwsrc=gateway_mac), iface=interface, count=3, verbose=False)
        sendp(Ether(dst=gateway_mac)/ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwsrc=target_mac), iface=interface, count=3, verbose=False)
    log('info', 'Network restored.')

# --- 主程式邏輯 ---
def main():
    try:
        # 1. 從命令列讀取來自 Electron 的設定
        config = json.loads(sys.argv[1])
        target_ips = config.get("targets", [])
        whitelist_urls = config.get("whitelist", [])

        # 2. 自動偵測網路環境
        route = conf.route.route("0.0.0.0", verbose=False)
        INTERFACE, ATTACKER_IP, GATEWAY_IP = route[0], route[1], route[2]
        log('info', f"Network detected: IFACE={INTERFACE}, Gateway={GATEWAY_IP}")

        # 3. 建立 IP 白名單
        WHITELIST_IPS = {GATEWAY_IP, "8.8.8.8", "8.8.4.4"} # 自動加入閘道器和 DNS
        for url_str in whitelist_urls:
            try:
                hostname = url_str.split('//')[-1].split('/')[0].split(':')[0]
                ip = socket.gethostbyname(hostname)
                WHITELIST_IPS.add(ip)
                log('info', f"Whitelist: {hostname} -> {ip}")
            except Exception:
                log('warning', f"Cannot resolve URL: {url_str}")

        # 4. 獲取所有必要的 MAC 位址
        ATTACKER_MAC = get_if_hwaddr(INTERFACE)
        GATEWAY_MAC = get_mac_address(GATEWAY_IP, INTERFACE)
        
        target_macs = {}
        for ip in target_ips:
            mac = get_mac_address(ip, INTERFACE)
            if mac:
                target_macs[ip] = mac
                event('mac_found', {"ip": ip, "mac": mac})
            else:
                log('error', f"Failed to get MAC for target: {ip}")

        if not all([ATTACKER_MAC, GATEWAY_MAC]) or not target_macs:
            log('critical', "Missing essential MAC addresses. Exiting.")
            return

        # 5. 啟動 ARP 欺騙背景執行緒
        spoof_thread = threading.Thread(target=arp_spoof, args=(GATEWAY_IP, GATEWAY_MAC, target_macs, ATTACKER_MAC, INTERFACE))
        spoof_thread.start()
        log('info', 'ARP spoofing thread started.')

        # 6. 定義封包處理與過濾函式
        def packet_processor(packet):
            if IP in packet:
                src_ip, dst_ip = packet[IP].src, packet[IP].dst
                # 處理從學生電腦發出的封包
                if src_ip in target_macs and packet[Ether].src == target_macs[src_ip]:
                    status = "allowed" if dst_ip in WHITELIST_IPS else "blocked"
                    event('packet', {"status": status, "src": src_ip, "dst": dst_ip})
                    # 如果允許，手動轉發
                    if status == "allowed":
                        packet[Ether].dst = GATEWAY_MAC
                        sendp(packet, iface=INTERFACE, verbose=False)
                # 處理返回給學生電腦的封包
                elif dst_ip in target_macs and packet[Ether].src == GATEWAY_MAC:
                    packet[Ether].dst = target_macs[dst_ip]
                    sendp(packet, iface=INTERFACE, verbose=False)
        
        # 7. 開始嗅探、過濾並轉發封包
        sniff(prn=packet_processor, iface=INTERFACE, store=False, stop_filter=lambda p: stop_event_flag.is_set())
        
        # 8. 等待執行緒結束並恢復網路
        spoof_thread.join()
        restore_arp(GATEWAY_IP, GATEWAY_MAC, target_macs, INTERFACE)

    except Exception as e:
        log('critical', f'A critical error occurred in backend: {e}')
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        stop_event_flag.set()
