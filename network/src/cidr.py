import ipaddress


def subnet_cidr(parent: str, new_bits: int, index: int) -> str:
    """
    Carves a subnet out of a parent IPv4 CIDR, like Terraform's cidrsubnet():
    subnet_cidr("10.0.0.0/16", 8, 2) == "10.0.2.0/24".
    """
    try:
        network = ipaddress.IPv4Network(parent)
    except ipaddress.AddressValueError as e:
        raise ValueError(f"invalid IPv4 address in {parent}") from e
    except ipaddress.NetmaskValueError as e:
        raise ValueError(f"invalid prefix length in {parent}") from e
    except ValueError as e:
        raise ValueError(f"{parent} has host bits set") from e

    new_prefix = network.prefixlen + new_bits
    if new_bits < 0 or new_prefix > 32:
        raise ValueError(f"cannot add {new_bits} bits to {parent}")
    if not 0 <= index < 2**new_bits:
        raise ValueError(f"index {index} doesn't fit in {new_bits} bits of {parent}")

    start = int(network.network_address) + index * 2 ** (32 - new_prefix)
    return str(ipaddress.IPv4Network((start, new_prefix)))
