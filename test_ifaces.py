from modules.netif_pretty import get_interfaces_pretty
if __name__ == '__main__':
    interfaces = get_interfaces_pretty()
    print('Wynik get_interfaces_pretty():')
    for iface, pretty in interfaces:
        print(f'  {iface}  ->  {pretty}')
    print(f'Liczba interfejsów: {len(interfaces)}')
