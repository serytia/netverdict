"""La troncature de capture n'est PAS une anonymisation.

Le README, capture.ps1 et capture.sh affirmaient tous les trois « en-tetes seuls
donc aucun credential dans le bundle ». C'est faux, et c'etait une affirmation de
SECURITE dans un outil de securite : quelqu'un pouvait transmettre un bundle en
se croyant couvert.

La troncature coupe a N octets DEPUIS LE DEBUT DE LA TRAME. Un paquet plus court
que N passe donc en entier, payload compris — et les protocoles
d'authentification en clair sont precisement courts.

Ce test est le garde-fou de la formulation : si un jour la troncature devenait
reellement une garantie, il tomberait et il faudrait le reecrire sciemment.
"""

from __future__ import annotations

import dpkt
import pytest

# Les deux valeurs livrees : capture.sh utilise -s 96, capture.ps1 128 octets.
SNAPLENS = (96, 128)

# 14 (Ethernet) + 20 (IP) + 20 (TCP sans options) = 54 octets d'en-tetes.
TAILLE_ENTETES = 54


def _trame(payload: bytes) -> bytes:
    tcp = dpkt.tcp.TCP(sport=51001, dport=110, seq=1, ack=1, win=65535,
                       flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH)
    tcp.data = payload
    ip = dpkt.ip.IP(src=bytes([10, 0, 0, 42]), dst=bytes([10, 0, 0, 5]),
                    p=dpkt.ip.IP_PROTO_TCP)
    ip.data = tcp
    ip.len = 20 + len(bytes(tcp))
    return bytes(dpkt.ethernet.Ethernet(
        src=b"\x00" * 6, dst=b"\x11" * 6,
        type=dpkt.ethernet.ETH_TYPE_IP, data=ip))


def _payload_visible(trame: bytes, snaplen: int) -> bytes:
    """Ce qu'un lecteur du pcap retrouve apres troncature a `snaplen`."""
    return bytes(dpkt.ethernet.Ethernet(trame[:snaplen]).data.data.data)


# Secrets courts, tous rencontres en vrai sur des protocoles non chiffres.
SECRETS = [
    (b"PASS hunter2\r\n", "POP3 / FTP en clair"),
    (b"USER admin\r\nPASS Adm1n!2026\r\n", "login FTP complet"),
    (b'{"token":"eyJhbGciOiJIUzI1NiJ9.abc"}', "jeton dans un corps JSON"),
    (b"LOGIN user secret123\r\n", "IMAP LOGIN"),
]


@pytest.mark.parametrize("snaplen", SNAPLENS)
@pytest.mark.parametrize("payload,nom", SECRETS,
                         ids=[n.replace(" ", "-") for _, n in SECRETS])
def test_un_secret_court_traverse_la_troncature_intact(payload, nom, snaplen):
    trame = _trame(payload)
    assert len(trame) <= snaplen, (
        f"{nom} : la trame ({len(trame)} o) tient sous le snaplen, "
        f"c'est justement pour ca qu'elle n'est pas coupee")
    assert _payload_visible(trame, snaplen) == payload, (
        f"{nom} : ce payload doit ressortir INTACT du bundle — la formulation "
        f"« aucun payload donc aucun credential » serait un mensonge")


@pytest.mark.parametrize("snaplen", SNAPLENS)
def test_ce_que_la_troncature_elimine_vraiment(snaplen):
    """La borne honnete : elle coupe les GROS transferts. C'est son seul effet
    reel, et c'est ce que la documentation doit promettre — rien de plus."""
    payload = b"A" * 4000
    vu = _payload_visible(_trame(payload), snaplen)
    assert len(vu) == snaplen - TAILLE_ENTETES
    assert len(vu) < len(payload) / 10


def test_le_seuil_de_survie_est_bien_celui_annonce():
    """Frontiere exacte, pour que le tableau du README reste verifiable : un
    payload de (snaplen - 54) octets passe entier, un octet de plus est coupe."""
    for snaplen in SNAPLENS:
        limite = snaplen - TAILLE_ENTETES
        assert _payload_visible(_trame(b"x" * limite), snaplen) == b"x" * limite
        coupe = _payload_visible(_trame(b"x" * (limite + 1)), snaplen)
        assert len(coupe) == limite, "un octet au-dela, la coupe commence"


def test_un_en_tete_Authorization_partiel_reste_exploitable():
    """Meme tronque, ce qui sort est utilisable : 42 des 51 octets d'un en-tete
    Basic laissent le base64 quasi complet. « Partiellement expose » n'est pas
    « protege » — c'est la raison pour laquelle la doc ne promet plus rien."""
    payload = b"Authorization: Basic dXRpbGlzYXRldXI6czNjcmV0UGFzc3dk\r\n"
    vu = _payload_visible(_trame(payload), 96)
    assert vu != payload, "a 96 octets cet en-tete est bien coupe"
    assert vu.startswith(b"Authorization: Basic ")
    assert len(vu) >= len(payload) * 0.75, (
        "les trois quarts du secret sortent quand meme du bundle")
