"""Sysmon Event ID 3 (NetworkConnect) -> jointure process <-> flux, retroactive.

CE QUI EST VERIFIE ET CE QUI RESTE A VERIFIER
---------------------------------------------
Les NOMS DE CHAMPS ci-dessous ne sont pas devines : ils viennent du schema du
binaire livre avec Windows (`C:\\Windows\\System32\\sysmon.exe -s`,
schemaversion 4.91) — SourceIp, SourcePort, DestinationIp, DestinationPort,
ProcessId, Image, User, Protocol, Initiated.

La FORME du XML, elle, est celle des evenements Windows standards que
sources/evtx.py parse deja pour d'autres fournisseurs. Elle reste a confronter
a un vrai enregistrement Sysmon apres `sysmon -i` : c'est la seule inconnue
restante, et elle sera bruyante (0 evenement parse) et non silencieuse.

Le risque principal de cette fonctionnalite n'est PAS de rater une jointure :
c'est d'attribuer un flux au MAUVAIS process. La majorite des tests verrouille
donc des non-correspondances.
"""

from __future__ import annotations

import pytest

from netverdict.correlate import attribution_for, attributions
from netverdict.sources import evtx
from netverdict.timeline import SourceStats, Timeline

# Flux de reference (celui de la fixture syn_no_answer, verifie plus bas) :
#   client 10.99.0.1:46004  ->  serveur 10.99.0.2:8080
_EVENT_TPL = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="{provider}" Guid="{{5770385f-c22a-43e0-bf4c-06f5698ffbd9}}"/>
    <EventID>{eid}</EventID>
    <Level>4</Level>
    <TimeCreated SystemTime="{ts}"/>
    <Computer>POSTE-01</Computer>
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">{ts_human}</Data>
    <Data Name="ProcessGuid">{{01234567-89ab-cdef-0123-456789abcdef}}</Data>
    <Data Name="ProcessId">{pid}</Data>
    <Data Name="Image">{image}</Data>
    <Data Name="User">POSTE-01\\user01</Data>
    <Data Name="Protocol">{proto}</Data>
    <Data Name="Initiated">{initiated}</Data>
    <Data Name="SourceIsIpv6">false</Data>
    <Data Name="SourceIp">{sip}</Data>
    <Data Name="SourceHostname">poste-01</Data>
    <Data Name="SourcePort">{sport}</Data>
    <Data Name="SourcePortName">-</Data>
    <Data Name="DestinationIsIpv6">false</Data>
    <Data Name="DestinationIp">{dip}</Data>
    <Data Name="DestinationHostname">-</Data>
    <Data Name="DestinationPort">{dport}</Data>
    <Data Name="DestinationPortName">-</Data>
  </EventData>
</Event>"""


def _systemtime(epoch: float) -> str:
    """epoch -> TimeCreated/@SystemTime tel que Windows l'ecrit (UTC, 7
    chiffres de fraction). Les fixtures synthetiques sont datees a l'epoch 0,
    donc on DERIVE l'horodatage du flux au lieu de le coder en dur."""
    from datetime import datetime, timedelta, timezone
    dt = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=epoch)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond:06d}0Z"


def _xml(path, *, ts="1970-01-01T00:00:00.0000000Z", sip="10.99.0.1", sport=46004,
         dip="10.99.0.2", dport=8080, pid=4212, image="C:\\Windows\\curl.exe",
         proto="tcp", initiated="true", provider="Microsoft-Windows-Sysmon",
         eid="3"):
    path.write_text(_EVENT_TPL.format(
        provider=provider, eid=eid, ts=ts, ts_human=ts, pid=pid, image=image,
        proto=proto, initiated=initiated, sip=sip, sport=sport, dip=dip,
        dport=dport), encoding="utf-8")
    return path


def _tl(events):
    tl = Timeline()
    tl.add_source("sysmon", events, SourceStats())
    return tl


@pytest.fixture
def flux(analyze):
    return analyze("syn_no_answer")[1]


@pytest.fixture
def colle(flux):
    """Les valeurs d'un evenement Sysmon qui CORRESPOND au flux, derivees du
    flux lui-meme : coder les adresses en dur ferait divergier le test le jour
    ou les fixtures changent (ce qui vient d'arriver)."""
    s = flux.signals
    return {"sip": s.client, "sport": s.cport, "dip": s.server,
            "dport": s.sport, "ts": _systemtime(s.t_first)}


def _events(tmp_path, nom="sysmon.xml", **kw):
    """Parse un evenement synthetique et rend (events, stats)."""
    return evtx.parse(_xml(tmp_path / nom, **kw))


class TestParsing:
    def test_l_evenement_3_porte_la_connexion(self, tmp_path):
        evs, stats = _events(tmp_path)
        assert (stats.total_lines, stats.parsed, stats.unparsed) == (1, 1, 0)
        c = evs[0].connection
        assert c is not None
        assert (c.src_ip, c.src_port) == ("10.99.0.1", 46004)
        assert (c.dst_ip, c.dst_port) == ("10.99.0.2", 8080)
        assert (c.pid, c.protocol, c.initiated) == (4212, "tcp", True)
        assert c.process_label() == "curl.exe (pid 4212)"

    def test_reste_hors_des_changements_d_infra(self, tmp_path):
        """Une connexion est une OBSERVATION. Si elle comptait comme un
        changement, la section « suspects » serait noyee par chaque connexion
        de la machine — la fonctionnalite en detruirait une autre."""
        evs, _ = _events(tmp_path)
        assert evs[0].category == "info"
        assert _tl(evs).changes() == []

    def test_le_message_est_lisible_sans_lire_le_json(self, tmp_path):
        evs, _ = _events(tmp_path)
        m = evs[0].message
        assert "curl.exe (pid 4212)" in m
        assert "10.99.0.1:46004 -> 10.99.0.2:8080" in m

    def test_un_quadruplet_incomplet_ne_produit_pas_de_jointure(self, tmp_path):
        """Mieux vaut aucune jointure qu'une jointure sur un champ manquant :
        elle rattacherait le flux au mauvais process."""
        evs, _ = _events(tmp_path, dip="")
        assert evs[0].connection is None
        # L'evenement lui-meme survit (on ne perd pas la ligne de timeline).
        assert evs[0].ident == "3"

    def test_initiated_absent_reste_indetermine(self, tmp_path):
        evs, _ = _events(tmp_path, initiated="-")
        assert evs[0].connection.initiated is None

    def test_les_champs_de_connexion_sont_neutralises(self, tmp_path):
        """Un nom de process ou d'utilisateur est controlable par un attaquant
        et finit affiche dans un terminal : les sequences ANSI/CR qui
        reecriraient le rapport doivent etre neutralisees DANS le contrat,
        comme le sont deja message/host/ident."""
        from netverdict.timeline import ConnectionInfo
        c = ConnectionInfo(
            src_ip="10.0.0.1", src_port=1, dst_ip="10.0.0.2", dst_port=2,
            image="C:\\x\\evil\x1b[2K\rfake.exe", user="dom\x1b[31mADMIN",
        )
        for champ in (c.image, c.user):
            assert "\x1b" not in champ
            assert "\r" not in champ
        assert "\x1b" not in c.process_label()

    def test_un_autre_fournisseur_avec_l_id_3_n_est_pas_traite_en_sysmon(self, tmp_path):
        """La table est indexee (provider, id) : un EventID 3 d'un autre
        fournisseur ne doit pas etre lu comme une connexion Sysmon."""
        evs, _ = _events(tmp_path, provider="Microsoft-Windows-Autre")
        assert evs[0].connection is None


class TestJointure:
    def test_attribue_le_process_du_cote_client(self, flux, colle, tmp_path):
        evs, _ = _events(tmp_path, **colle)
        a = attribution_for(flux, _tl(evs))
        assert a is not None
        assert a.side == "client"
        assert "curl.exe" in a.describe()
        assert "cote client" in a.describe()

    def test_attribue_le_process_du_cote_serveur_quand_le_sens_est_inverse(
            self, flux, colle, tmp_path):
        """L'evenement peut venir de la machine SERVEUR : le quadruplet est
        alors inverse, et savoir de quel cote on est change tout."""
        inverse = dict(colle, sip=colle["dip"], sport=colle["dport"],
                       dip=colle["sip"], dport=colle["sport"])
        evs, _ = _events(tmp_path, **inverse, image="C:\\srv\\nginx.exe",
                         initiated="false")
        a = attribution_for(flux, _tl(evs))
        assert a is not None and a.side == "serveur"
        assert "nginx.exe" in a.describe()

    @pytest.mark.parametrize("champ,pourquoi", [
        ("sport", "port client different = autre flux"),
        ("dport", "port serveur different = autre service"),
        ("sip", "adresse client differente = autre machine"),
        ("dip", "adresse serveur differente"),
    ])
    def test_une_correspondance_partielle_ne_suffit_JAMAIS(self, flux, colle,
                                                           tmp_path, champ,
                                                           pourquoi):
        casse = dict(colle)
        casse[champ] = (colle[champ] + 1 if champ.endswith("port")
                        else "203.0.113.7")
        evs, _ = _events(tmp_path, **casse)
        assert attribution_for(flux, _tl(evs)) is None, pourquoi

    def test_un_flux_udp_est_ignore(self, flux, colle, tmp_path):
        evs, _ = _events(tmp_path, **colle, proto="udp")
        assert attribution_for(flux, _tl(evs)) is None

    def test_un_evenement_trop_eloigne_dans_le_temps_est_ecarte(self, flux, colle,
                                                                tmp_path):
        """Meme quadruplet, mais des heures plus tard : c'est une autre
        session, pas celle de la capture."""
        loin = dict(colle, ts=_systemtime(flux.signals.t_first + 4 * 3600))
        evs, _ = _events(tmp_path, **loin)
        assert attribution_for(flux, _tl(evs)) is None

    def test_port_reutilise_prend_le_plus_proche_et_le_signale(self, flux, colle,
                                                               tmp_path):
        """Sur une capture longue, un port client peut servir deux fois.
        On choisit, mais on le DIT — sinon l'admin croit a une certitude."""
        t = flux.signals.t_first
        proche, _ = _events(tmp_path, "a.xml", **dict(colle, ts=_systemtime(t)),
                            image="C:\\bon.exe", pid=1)
        lointain, _ = _events(tmp_path, "b.xml",
                              **dict(colle, ts=_systemtime(t + 25)),
                              image="C:\\autre.exe", pid=2)
        a = attribution_for(flux, _tl(proche + lointain))
        assert a is not None
        assert a.candidates == 2
        assert "bon.exe" in a.describe()
        assert "port reutilise" in a.describe()

    def test_la_jointure_vaut_aussi_pour_un_flux_sain(self, analyze, tmp_path):
        """Contrairement aux suspects : savoir quel process parle est utile
        meme sans panne."""
        _sig, sain = analyze("clean")
        s = sain.signals
        evs, _ = _events(tmp_path, sip=s.client, sport=s.cport,
                         dip=s.server, dport=s.sport,
                         ts=_systemtime(s.t_first))
        assert attribution_for(sain, _tl(evs)) is not None

    def test_table_indexee_par_position(self, flux, colle, analyze, tmp_path):
        _sig, sain = analyze("clean")
        evs, _ = _events(tmp_path, **colle)
        table = attributions([sain, flux], _tl(evs))
        assert set(table) == {1}

    def test_sans_timeline_aucune_attribution(self, flux):
        assert attributions([flux], None) == {}


class TestSortieJson:
    def test_le_json_dit_que_l_attribution_est_retroactive(self, flux, colle,
                                                           fixtures, tmp_path):
        import json

        from netverdict.pcap import read_capture
        from netverdict.report import to_json

        evs, _ = _events(tmp_path, **colle)
        cap = read_capture(fixtures["syn_no_answer"])
        data = json.loads(to_json(cap, [flux], None, _tl(evs)))
        pa = data["flows"][0]["process_attribution"]
        assert pa["retroactive"] is True
        assert pa["side"] == "client"
        assert pa["pid"] == 4212
        assert pa["initiated"] is True
