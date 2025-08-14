from scapy.all import get_if_list

def list_interfaces():
    """Zwraca listę dostępnych interfejsów sieciowych (nazwa scapy)."""
    return get_if_list()
