"""WFP (Windows Filtering Platform) Event ID 5156/5157 -> jointure
process <-> flux, retroactive (v1.3, troisieme source apres Sysmon/auditd).

POURQUOI CETTE SOURCE EXISTE
-----------------------------
Sysmon EID 3 fait deja cette jointure, mais exige d'INSTALLER un agent
(`sysmon -i`). WFP est l'audit NATIF de Windows -- zero installation,
active par `auditpol` ou GPO -- c'est le meme service sans rien deployer.

Contrairement a auditd (qui ne connait jamais le port source de connect()),
WFP donne les DEUX extremites, exactement comme Sysmon : la jointure via
correlate._side_of est donc EXACTE (ProcessAttribution.exact=True). C'est
l'avantage de cette source sur auditd, et le test d'integration plus bas le
PROUVE plutot que de l'affirmer.

Noms de champs EventData (verifies contre la doc Microsoft du provider
Microsoft-Windows-Security-Auditing, EID 5156/5157) : ProcessID (notez le
'ID' en majuscules, different du 'Id' de Sysmon), Application (chemin NT
\\device\\harddiskvolumeN\\...), Direction (%%14592=Inbound,
%%14593=Outbound), SourceAddress/SourcePort/DestAddress/DestPort,
Protocol (numerique : 6=TCP, 17=UDP).
"""

from __future__ import annotations

import pytest

from netverdict.correlate import attribution_for
from netverdict.sources import evtx
from netverdict.timeline import SourceStats, Timeline

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# Flux de reference (fixture syn_no_answer, meme convention que
# test_sysmon_join.py) : client 10.99.0.1:46004 -> serveur 10.99.0.2:8080.
_WFP_TPL = """<Event xmlns="{ns}">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{{54849625-5478-4994-a5ba-3e3b0328c30d}}"/>
    <EventID>{eid}</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="{ts}"/>
    <Computer>POSTE-LAB-01</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="SubjectUserName">{user}</Data>
    <Data Name="SubjectDomainName">POSTE-LAB-01</Data>
    <Data Name="SubjectLogonId">0x3e7</Data>
    <Data Name="Application">{application}</Data>
    <Data Name="Direction">{direction}</Data>
    <Data Name="SourceAddress">{sip}</Data>
    <Data Name="SourcePort">{sport}</Data>
    <Data Name="DestAddress">{dip}</Data>
    <Data Name="DestPort">{dport}</Data>
    <Data Name="Protocol">{proto}</Data>
    <Data Name="FilterRTID">123456</Data>
    <Data Name="LayerName">%%14611</Data>
    <Data Name="LayerRTID">48</Data>
    <Data Name="ProcessID">{pid}</Data>
  </EventData>
</Event>"""


def _systemtime(epoch: float) -> str:
    """epoch -> TimeCreated/@SystemTime tel que Windows l'ecrit (UTC, 7
    chiffres de fraction). Meme derivation que test_sysmon_join.py : les
    fixtures synthetiques sont a l'epoch 0, on derive plutot que coder en
    dur l'horodatage du flux."""
    from datetime import datetime, timedelta, timezone
    dt = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=epoch)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond:06d}0Z"


def _wfp_xml(path, *, ts="1970-01-01T00:00:00.0000000Z", eid="5156",
             sip="10.99.0.1", sport=46004, dip="10.99.0.2", dport=8080,
             pid=4212,
             application=r"\device\harddiskvolume4\windows\system32\curl.exe",
             proto="6", direction="%%14593",
             user="POSTE-LAB-01\\utilisateur"):
    path.write_text(_WFP_TPL.format(
        ns=_NS, eid=eid, ts=ts, sip=sip, sport=sport, dip=dip, dport=dport,
        pid=pid, application=application, proto=proto, direction=direction,
        user=user), encoding="utf-8")
    return path


def _events(tmp_path, nom="wfp.xml", **kw):
    """Parse un evenement WFP synthetique et rend (events, stats)."""
    return evtx.parse(_wfp_xml(tmp_path / nom, **kw))


def _tl(events):
    tl = Timeline()
    tl.add_source("wfp", events, SourceStats())
    return tl


@pytest.fixture
def flux(analyze):
    return analyze("syn_no_answer")[1]


@pytest.fixture
def colle(flux):
    """Les valeurs d'un evenement WFP qui CORRESPOND au flux, derivees du
    flux lui-meme (meme discipline que test_sysmon_join.py::colle) : coder
    les adresses en dur ferait divergier le test si les fixtures changent."""
    s = flux.signals
    return {"sip": s.client, "sport": s.cport, "dip": s.server,
            "dport": s.sport, "ts": _systemtime(s.t_first)}


class TestParsing:
    def test_5156_outbound_porte_la_connexion_complete(self, tmp_path):
        evs, stats = _events(tmp_path)
        assert (stats.total_lines, stats.parsed, stats.unparsed) == (1, 1, 0)
        c = evs[0].connection
        assert c is not None
        assert (c.src_ip, c.src_port) == ("10.99.0.1", 46004)
        assert (c.dst_ip, c.dst_port) == ("10.99.0.2", 8080)
        assert (c.pid, c.protocol, c.initiated) == (4212, "tcp", True)
        assert c.user == "POSTE-LAB-01\\utilisateur"
        assert evs[0].category == "info"
        assert evs[0].severity == 0

    def test_process_label_extrait_correctement_le_chemin_nt(self, tmp_path):
        """Le chemin NT (\\device\\harddiskvolumeN\\...) ne peut pas etre
        resolu vers une lettre de lecteur sans API Windows -- WFP le garde
        tel quel. process_label() ne prend que le dernier segment de
        chemin, quel que soit le separateur : le nom court reste correct
        malgre le prefixe \\device\\harddiskvolumeN."""
        evs, _ = _events(tmp_path)
        assert evs[0].connection.image == (
            r"\device\harddiskvolume4\windows\system32\curl.exe")
        assert evs[0].connection.process_label() == "curl.exe (pid 4212)"

    def test_reste_hors_des_changements_d_infra(self, tmp_path):
        """OBSERVATION, pas changement d'infra -- meme regle que Sysmon
        EID 3 (cf. TimelineEvent.connection dans timeline.py)."""
        evs, _ = _events(tmp_path)
        assert _tl(evs).changes() == []

    def test_5157_bloque_le_dit_dans_le_message_et_en_severite(self, tmp_path):
        evs, _ = _events(tmp_path, eid="5157")
        assert evs[0].severity == 1
        assert evs[0].category == "info"
        assert "BLOQ" in evs[0].message.upper()
        c = evs[0].connection
        assert c is not None and c.protocol == "tcp"

    def test_5156_permis_le_dit_aussi(self, tmp_path):
        evs, _ = _events(tmp_path, eid="5156")
        assert "PERMIS" in evs[0].message.upper()
        assert "BLOQ" not in evs[0].message.upper()

    def test_direction_outbound_donne_initiated_true(self, tmp_path):
        evs, _ = _events(tmp_path, direction="%%14593")
        assert evs[0].connection.initiated is True

    def test_direction_inbound_donne_initiated_false(self, tmp_path):
        evs, _ = _events(tmp_path, direction="%%14592")
        assert evs[0].connection.initiated is False

    def test_direction_absente_reste_indeterminee(self, tmp_path):
        evs, _ = _events(tmp_path, direction="")
        assert evs[0].connection.initiated is None

    def test_protocol_6_est_tcp(self, tmp_path):
        evs, _ = _events(tmp_path, proto="6")
        assert evs[0].connection.protocol == "tcp"

    def test_protocol_17_est_udp(self, tmp_path):
        evs, _ = _events(tmp_path, proto="17")
        assert evs[0].connection.protocol == "udp"

    def test_protocol_inconnu_ne_devient_ni_tcp_ni_udp(self, tmp_path):
        """1 = ICMP : forcer 'tcp' par defaut ferait matcher une jointure
        TCP qui ne le concerne pas. La valeur numerique brute reste
        distincte de 'tcp' comme de 'udp'."""
        evs, _ = _events(tmp_path, proto="1")
        c = evs[0].connection
        assert c.protocol not in ("tcp", "udp")
        assert c.protocol == "1"

    def test_un_quadruplet_incomplet_ne_produit_pas_de_jointure(self, tmp_path):
        evs, _ = _events(tmp_path, dip="")
        assert evs[0].connection is None
        assert evs[0].ident == "5156"

    def test_subject_user_name_absent_donne_chaine_vide(self, tmp_path):
        evs, _ = _events(tmp_path, user="")
        assert evs[0].connection.user == ""

    def test_un_autre_eventid_du_meme_provider_n_est_pas_traite_en_wfp(
            self, tmp_path):
        """Le canal Security porte aussi les logons (4624...) et bien
        d'autres choses sous LE MEME provider : seul l'EventID 5156/5157
        doit produire une connexion."""
        evs, _ = _events(tmp_path, eid="4624")
        assert evs[0].connection is None


class TestGardeFou:
    def test_security_sans_5156_5157_pose_une_note_actionnable(self, tmp_path):
        f = tmp_path / "security.xml"
        f.write_text(f"""
<Event xmlns='{_NS}'><System>
  <Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID>
  <Level>0</Level>
  <TimeCreated SystemTime='2026-07-26T10:00:00.0Z'/><Computer>h1</Computer>
</System><EventData/></Event>
""", encoding="utf-8")
        events, stats = evtx.parse(f)
        assert len(events) == 1
        assert "5156" in stats.note and "5157" in stats.note
        assert "auditpol" in stats.note
        assert "Filtering Platform Connection" in stats.note

    def test_5156_present_donne_une_note_vide(self, tmp_path):
        evs, stats = _events(tmp_path)
        assert stats.note == ""

    def test_5157_present_donne_aussi_une_note_vide(self, tmp_path):
        evs, stats = _events(tmp_path, eid="5157")
        assert stats.note == ""

    def test_fichier_security_sans_wfp_ne_declenche_pas_la_note_sysmon(
            self, tmp_path):
        """Reciprocite exigee : un fichier de securite Windows sans WFP ne
        doit jamais produire le conseil `sysmon -c` (mauvaise source)."""
        f = tmp_path / "security.xml"
        f.write_text(f"""
<Event xmlns='{_NS}'><System>
  <Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID>
  <Level>0</Level>
  <TimeCreated SystemTime='2026-07-26T10:00:00.0Z'/><Computer>h1</Computer>
</System><EventData/></Event>
""", encoding="utf-8")
        _events_, stats = evtx.parse(f)
        assert "sysmon -c" not in stats.note
        assert "NetworkConnect" not in stats.note

    def test_fichier_sysmon_sans_eid3_ne_declenche_pas_la_note_wfp(
            self, tmp_path):
        """Reciprocite exigee : un fichier Sysmon sans EID3 ne doit jamais
        produire le conseil `auditpol` (mauvaise source)."""
        f = tmp_path / "sysmon.xml"
        f.write_text(f"""
<Event xmlns='{_NS}'><System>
  <Provider Name='Microsoft-Windows-Sysmon'/><EventID>1</EventID>
  <Level>4</Level>
  <TimeCreated SystemTime='2026-07-26T10:00:00.0Z'/><Computer>h1</Computer>
</System><EventData/></Event>
""", encoding="utf-8")
        _events_, stats = evtx.parse(f)
        assert "auditpol" not in stats.note
        assert "5156" not in stats.note


class TestNonRegressionSysmon:
    _SYSMON_TPL = """<Event xmlns="{ns}">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon"/>
    <EventID>3</EventID>
    <Level>4</Level>
    <TimeCreated SystemTime="{ts}"/>
    <Computer>POSTE-LAB-01</Computer>
  </System>
  <EventData>
    <Data Name="UtcTime">{ts_human}</Data>
    <Data Name="ProcessId">4212</Data>
    <Data Name="Image">C:\\Windows\\curl.exe</Data>
    <Data Name="User">POSTE-LAB-01\\utilisateur</Data>
    <Data Name="Protocol">tcp</Data>
    <Data Name="Initiated">true</Data>
    <Data Name="SourceIp">10.99.0.1</Data>
    <Data Name="SourcePort">46004</Data>
    <Data Name="DestinationIp">10.99.0.2</Data>
    <Data Name="DestinationPort">8080</Data>
  </EventData>
</Event>"""

    def test_un_fichier_sysmon_eid3_marche_exactement_pareil(self, tmp_path):
        """L'ajout des entrees WFP a _EVENT_TABLE et de la branche WFP dans
        _parse_event_element ne doit rien changer au chemin Sysmon
        existant : meme table, cle (provider, EventID) differente."""
        ts = "2026-07-26T10:00:00.0000000Z"
        f = tmp_path / "sysmon.xml"
        f.write_text(self._SYSMON_TPL.format(ns=_NS, ts=ts, ts_human=ts),
                     encoding="utf-8")
        events, stats = evtx.parse(f)
        assert stats.note == ""
        c = events[0].connection
        assert c is not None
        assert (c.src_ip, c.src_port, c.dst_ip, c.dst_port) == (
            "10.99.0.1", 46004, "10.99.0.2", 8080)
        assert c.protocol == "tcp"
        assert events[0].category == "info"


class TestIntegrationCorrelate:
    def test_attribution_via_5156_est_exacte(self, flux, colle, tmp_path):
        """LE test qui prouve l'avantage de WFP sur auditd : les deux
        extremites sont connues, donc exact=True (contrairement a auditd,
        qui ne peut jamais depasser exact=False -- cf. correlate._side_of)."""
        evs, _ = _events(tmp_path, **colle)
        a = attribution_for(flux, _tl(evs))
        assert a is not None
        assert a.exact is True
        assert a.side == "client"
        assert a.connection.pid == 4212
        assert "curl.exe" in a.describe()
        assert "rapproche par la DESTINATION seule" not in a.describe()

    def test_attribution_via_5157_bloque_fonctionne_aussi(self, flux, colle,
                                                          tmp_path):
        """Une connexion BLOQUEE reste une jointure valide : c'est meme le
        cas le plus utile pour expliquer un SYN sans reponse."""
        evs, _ = _events(tmp_path, **colle, eid="5157")
        a = attribution_for(flux, _tl(evs))
        assert a is not None
        assert a.exact is True

    def test_protocol_udp_est_ignore_par_correlate(self, flux, colle,
                                                   tmp_path):
        evs, _ = _events(tmp_path, **colle, proto="17")
        assert evs[0].connection.protocol == "udp"
        assert attribution_for(flux, _tl(evs)) is None
