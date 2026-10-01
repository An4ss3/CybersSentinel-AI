# Initial specification (cahier des charges)

`CyberSentinel_AI_Cahier_des_Charges.pdf` (and its plain-text export) is the
**initial project specification**, written in French in July 2026 at the start
of the internship. It is kept for traceability: it records what was planned,
not what was delivered.

The scope was deliberately narrowed during the project. Several components the
specification describes were **not implemented**, and the repository must not
be read as providing them:

| Planned in the specification | Status in this repository |
|---|---|
| Network intrusion detection on CICIDS2017 (brute force, DoS/DDoS) | **Implemented** — the core of the work |
| Reproducible PCAP → Zeek → events → windows → labels chain | **Implemented** |
| FastAPI scoring API, PostgreSQL alert store, Grafana dashboard | **Implemented** as a demonstration prototype |
| Elasticsearch / Kibana log storage | Containers declared in `docker-compose.yml`; **not integrated** in the code |
| Redis Streams message bus | Container declared; **not integrated** in the code |
| GenAI SOC assistant (LLM + RAG) | **Not implemented** |
| Threat-intelligence enrichment (MITRE ATT&CK, CVE/NVD) | **Not implemented** |
| Malware and insider-threat detection | **Not implemented** |
| Multi-source log ingestion (Filebeat, Winlogbeat, Wazuh) | **Not implemented** |

The reason for the narrowing is methodological: most of the effort went into
building an evaluation whose conclusions are defensible, rather than into
breadth. See the [project overview](../PROJECT_OVERVIEW.md).
