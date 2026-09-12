import ipaddress

import pytest

from webguard.security.address_policy import PublicAddressPolicy
from webguard.security.errors import BlockedAddressError


@pytest.mark.security
@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "127.255.255.255",
        "::1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "fc00::1",
        "fd00::1",
        "169.254.1.1",
        "169.254.169.254",
        "fe80::1",
        "224.0.0.1",
        "ff02::1",
        "0.0.0.0",
        "::",
        "192.0.2.1",
        "198.51.100.2",
        "203.0.113.3",
        "2001:db8::1",
        "100.64.0.1",
        "240.0.0.1",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        "::ffff:192.168.1.1",
    ],
)
def test_blocks_non_public_addresses(address: str) -> None:
    with pytest.raises(BlockedAddressError):
        PublicAddressPolicy().validate(ipaddress.ip_address(address))


@pytest.mark.parametrize("address", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_accepts_unambiguous_public_addresses(address: str) -> None:
    PublicAddressPolicy().validate(ipaddress.ip_address(address))


@pytest.mark.security
def test_mixed_public_and_private_dns_answer_fails_closed() -> None:
    answers = (ipaddress.ip_address("8.8.8.8"), ipaddress.ip_address("10.0.0.1"))
    with pytest.raises(BlockedAddressError):
        PublicAddressPolicy().validate_all(answers)


def test_empty_address_set_fails_closed() -> None:
    with pytest.raises(BlockedAddressError):
        PublicAddressPolicy().validate_all(())
