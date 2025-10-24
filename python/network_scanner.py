import json
import socket
import struct
import sys

from scapy.all import ARP, Ether, conf, srp  # type: ignore


def _to_ip(value: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", value))


def _mask_to_prefix(mask: int) -> int:
    # mask 以整數表示，需換算成 CIDR prefix 長度
    return bin(mask).count("1")


def _detect_network(interface: str, attacker_ip: str) -> str:
    for network, netmask, _gateway, iface, _addr, _metric in conf.route.routes:  # type: ignore[attr-defined]
        if iface == interface and netmask:
            try:
                network_ip = _to_ip(network)
                prefix = _mask_to_prefix(netmask)
                return f"{network_ip}/{prefix}"
            except OSError:
                continue

    # 若無法從路由表推得網段，退回用 /24 掃描
    base = attacker_ip.rsplit('.', 1)[0]
    return f"{base}.0/24"


def scan_network():
    route_info = conf.route  # type: ignore[attr-defined]

    if not route_info or not hasattr(route_info, 'route'):
        raise RuntimeError('無法取得路由資訊')

    interface, attacker_ip, _gateway_ip = route_info.route("0.0.0.0", verbose=False)

    if not interface or interface.startswith('lo'):
        raise RuntimeError(f'偵測到無效的網路介面: {interface!r}')

    network_cidr = _detect_network(interface, attacker_ip)

    answered, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network_cidr),
        timeout=2,
        iface=interface,
        inter=0.05,
        retry=1,
        verbose=False,
    )

    devices = []
    for _sent, received in answered:
        ip_addr = received.psrc
        mac_addr = received.hwsrc
        devices.append({"ip": ip_addr, "mac": mac_addr})

    devices.sort(key=lambda d: list(map(int, d["ip"].split('.'))))
    return {
        "success": True,
        "interface": interface,
        "network": network_cidr,
        "devices": devices,
    }


def main():
    try:
        result = scan_network()
    except Exception as exc:  # pylint: disable=broad-except
        print(json.dumps({"success": False, "error": str(exc)}), flush=True)
        sys.exit(1)

    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
