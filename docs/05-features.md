# Feature Engineering Taxonomy & Categorization

SentinelFlow organizes network features into **7 domain-specific threat categories** rather than maintaining an unmanageable monolithic feature list. This modular structure aligns directly with adversary tactics (ATT&CK) and network behavior baselines.

---

## 🏛️ Feature Categories & Threats

### A. Basic Flow Features (Connection Identity)
Essential network conversation 5-tuple and basic volume markers:
- `timestamp`: UTC start time of connection
- `flow_id`: Unique flow tracking identifier
- `src_ip`: Initiator IPv4/IPv6 address
- `dst_ip`: Responder IPv4/IPv6 address
- `src_port`: Client source port
- `dst_port`: Target service port
- `protocol`: Transport protocol (`TCP`, `UDP`, `ICMP`)
- `duration`: Total connection lifespan in seconds
- `packets`: Total packet count exchanged
- `bytes`: Total byte volume transferred

### B. Traffic Statistics (Volumetric Anomalies & DDoS)
High-resolution transmission dynamics for detecting flood attacks:
- `pps`: Packets per second transmission velocity
- `bps`: Bytes per second bandwidth consumption
- `mean_packet_size`: Arithmetic mean of packet byte sizes
- `packet_size_std`: Standard deviation of packet byte lengths (low in flood attacks)
- `mean_iat`: Mean inter-arrival time between packets
- `iat_std`: Standard deviation of inter-arrival times

### C. DNS Features (DGA & Tunneling)
Lexical and statistical attributes of domain resolution telemetry:
- `dns_query_length`: Character length of query name ($> 50$ indicates tunneling)
- `dns_entropy`: Shannon entropy in bits/char ($> 3.8$ indicates algorithmic generation)
- `unique_subdomains`: Number of distinct subdomain labels requested
- `dns_query_rate`: Frequency of DNS lookups per host window
- `txt_record_ratio`: Proportion of TXT/NULL record requests (tunneling indicators)

### D. C2 Beacon Features (Heartbeat & Botnet Regularity)
Temporal autocorrelation metrics detecting automated malware callbacks:
- `periodicity_score`: Autocorrelation regularity score $[0.0, 1.0]$ ($> 0.85$ indicates beacon)
- `mean_iat`: Expected beacon interval
- `iat_std`: Jitter around interval
- `destination_repetition`: Frequency of recurring connections to identical destination
- `connection_frequency`: Callbacks per unit time

### E. Reconnaissance Features (Scanning & Probing)
Graph fan-out and host discovery activity:
- `unique_dst_ports`: Distinct ports targeted by single source (port scan)
- `unique_dst_hosts`: Distinct IP addresses contacted in temporal window (subnet sweep)
- `connection_attempts`: Total SYN / probe attempts
- `port_fanout`: Ratio of unique ports to total connections
- `host_fanout`: Ratio of unique hosts to total connections

### F. Data Exfiltration Features (Asymmetry & Transfer Skew)
Outbound volume deviations:
- `outbound_bytes`: Bytes transmitted from monitored host
- `inbound_bytes`: Bytes received by monitored host
- `outbound_inbound_ratio`: Asymmetry skew ($\frac{\text{outbound}}{\text{total}}$ or $\frac{\text{outbound}}{\text{inbound}}$)
- `long_flow_score`: Presence of sustained large outbound data streams
- `destination_count`: External endpoints receiving bulk transfers

### G. TLS / QUIC Features (Encrypted Telemetry Anomalies)
Transport layer handshake metadata extracted **WITHOUT decrypting payloads**:
- `tls_version`: Protocol negotiation version (TLS 1.2, TLS 1.3)
- `ja3`: MD5 client handshake fingerprint hash
- `ja4`: Extended TLS 1.3 fingerprint format
- `tls_packet_size_variance`: Handshake and encrypted record size variations
- `tls_iat`: Inter-arrival timing of encrypted records
- `tls_flow_duration`: Lifetime of the encrypted session

---

## 🔒 Hard Security Boundary

> [!IMPORTANT]
> **Payload Decryption is Strictly Forbidden (`payload_decryption: false`).**  
> SentinelFlow operates on passive observation of headers, handshake negotiation parameters (SNI, JA3/JA4, cipher list), and packet size/timing dynamics. No SSL private keys, MITM proxies, or certificate decryption capabilities exist in the codebase.
