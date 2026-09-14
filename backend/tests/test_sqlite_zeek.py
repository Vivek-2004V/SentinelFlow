"""
Tests for SQLite Persistence and Zeek Multi-Log Ingest.
"""
from fastapi.testclient import TestClient

from app.db.database import db
from app.ingest.zeek import correlate_zeek_logs
from app.main import app
from app.schemas.alert import EvidenceItem, SeverityLevel, StandardAlert

client = TestClient(app)


def test_sqlite_alert_crud():
    db.clear_alerts()

    alert = StandardAlert(
        flow_id="F-10021",
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        threat_class="C2_BEACON",
        severity=SeverityLevel.HIGH,
        confidence=0.88,
        attack_chain=["C2_BEACON"],
        evidence=[
            EvidenceItem(feature="periodicity", value=0.94, reason="Regular communication interval")
        ],
        action="ALERT_ONLY",
    )

    db.save_alert(alert)

    # Retrieve by ID
    fetched = db.get_alert_by_id(alert.flow_id)
    assert fetched is not None
    assert fetched.src_ip == "192.168.1.100"
    assert fetched.threat_class == "C2_BEACON"
    assert fetched.confidence == 0.88
    assert fetched.action == "ALERT_ONLY"
    assert len(fetched.evidence) == 1
    assert fetched.evidence[0].feature == "periodicity"

    # Query list
    alerts = db.get_alerts(limit=10)
    assert len(alerts) == 1
    assert alerts[0].alert_id == alert.alert_id

    # Check stats
    stats = db.get_alert_stats()
    assert stats["total_alerts"] == 1
    assert stats["by_threat_type"]["C2_BEACON"] == 1


def test_zeek_multi_log_correlation():
    conn_log = """
#separator \x09
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\tresp_pkts
1670000000.00\tC_UID_12345\t192.168.1.55\t49152\t8.8.8.8\t53\tudp\tdns\t0.05\t80\t80\tSF\tT\tF\t0\tDd\t1\t1
1670000001.00\tC_UID_67890\t192.168.1.66\t51234\t198.51.100.99\t443\ttcp\tssl\t75.0\t45000000\t120000\tSF\tT\tF\t0\tShADadFf\t32000\t1500
"""
    dns_log = """
#separator \x09
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\trtt\tquery
1670000000.00\tC_UID_12345\t192.168.1.55\t49152\t8.8.8.8\t53\tudp\t1234\t0.02\txq99z88b14aa77llkk2200mm.biz
"""
    ssl_log = """
#separator \x09
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tcurve\tserver_name\tresumed\tlast_alert\tnext_protocol\testablished\tcert_chain_fuids\tclient_cert_chain_fuids\tsubject\tissuer\tclient_subject\tclient_issuer\tsni_matches_cert\tvalidation_status\tja3
1670000001.00\tC_UID_67890\t192.168.1.66\t51234\t198.51.100.99\t443\tTLSv12\t0x002f\t-\texfil-target.net\tF\t-\t-\tT\t-\t-\t-\t-\t-\t-\t-\t-\t771,4865-4866-4867,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0
"""

    flows = correlate_zeek_logs(conn_log, dns_log, ssl_log)
    assert len(flows) == 2

    # Flow 1 (DNS correlated by UID)
    assert flows[0].src_ip == "192.168.1.55"
    assert flows[0].dns_query == "xq99z88b14aa77llkk2200mm.biz"

    # Flow 2 (SSL correlated by UID)
    assert flows[1].src_ip == "192.168.1.66"
    assert flows[1].tls_sni == "exfil-target.net"
    assert flows[1].bytes_sent == 45000000


def test_zeek_bundle_api_endpoint():
    conn_log = "1670000000.00\tUID_DGA_01\t192.168.1.99\t40000\t8.8.8.8\t53\tudp\tdns\t0.02\t80\t80\tSF\tT\tF\t0\tDd\t1\t1"
    dns_log = "1670000000.00\tUID_DGA_01\t192.168.1.99\t40000\t8.8.8.8\t53\tudp\t123\t0.01\tzq8899aa11bb22cc33dd.biz"

    resp = client.post(
        "/api/v1/ingest/zeek/bundle",
        json={
            "conn_log": conn_log,
            "dns_log": dns_log,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["flows_processed"] == 1
    assert data["alerts_generated"] >= 1
    assert data["alerts"][0]["threat_class"] in ("DGA", "LIKELY_COMPROMISED_HOST")
    assert data["alerts"][0]["action"] == "ALERT_ONLY"
