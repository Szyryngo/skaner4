from scapy.all import get_if_list, get_if_addr, get_if_hwaddr

def get_interfaces_pretty():
    """
    Zwraca listę krotek (nazwa_techniczna, opis_czytelny) dla wszystkich interfejsów.
    opis_czytelny: 'Ethernet (192.168.1.10, 00:11:22:33:44:55)'
    """
    result = []
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
        except Exception:
            ip = '-'
        try:
            mac = get_if_hwaddr(iface)
        except Exception:
            mac = '-'
        pretty = f"{iface} ({ip}, {mac})"
        result.append((iface, pretty))
    return result
