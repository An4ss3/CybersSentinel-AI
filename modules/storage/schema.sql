-- CyberSentinel AI — PostgreSQL schema (Couche 2 : alertes / métadonnées)
-- Reference: cahier des charges section 6.3 (scoring 0..100 -> 4 niveaux)
--            and section 6.5 (enrichissement threat intelligence).
-- Applied automatically by docker-compose on first Postgres init.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";  -- for gen_random_uuid()

-- ---------------------------------------------------------------------------
-- Enumerations
-- ---------------------------------------------------------------------------
DO $$ BEGIN
    CREATE TYPE criticality_level AS ENUM ('Low', 'Medium', 'High', 'Critical');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE attack_family AS ENUM (
        'brute_force', 'malware', 'ransomware', 'ddos', 'insider_threat', 'unknown'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE alert_status AS ENUM ('new', 'under_review', 'escalated', 'closed', 'archived');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ---------------------------------------------------------------------------
-- Monitored assets (used by the scoring factor "criticité de l'actif")
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS assets (
    id            SERIAL PRIMARY KEY,
    hostname      TEXT UNIQUE NOT NULL,
    ip_address    INET,
    asset_type    TEXT,                         -- e.g. server, workstation, firewall
    criticality   criticality_level NOT NULL DEFAULT 'Low',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Alerts (core table produced by the detection + scoring pipeline)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    detected_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    source_event_id    TEXT,                    -- link back to Elasticsearch log document
    attack_type        attack_family NOT NULL DEFAULT 'unknown',

    -- Scoring (section 6.3): composite score in [0, 100]
    ml_confidence      NUMERIC(5,4) CHECK (ml_confidence BETWEEN 0 AND 1),
    asset_criticality  criticality_level,
    cve_severity       NUMERIC(3,1) CHECK (cve_severity BETWEEN 0 AND 10), -- CVSS base score
    composite_score    NUMERIC(5,2) NOT NULL CHECK (composite_score BETWEEN 0 AND 100),
    level              criticality_level NOT NULL,

    -- Context
    src_ip             INET,
    dst_ip             INET,
    asset_id           INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    model_name         TEXT,                    -- e.g. xgboost_brute_force_v1
    status             alert_status NOT NULL DEFAULT 'new',

    -- XAI (section 6.4): top influential features / textual justification
    explanation        JSONB,

    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_alerts_detected_at ON alerts (detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_level        ON alerts (level);
CREATE INDEX IF NOT EXISTS idx_alerts_attack_type  ON alerts (attack_type);
CREATE INDEX IF NOT EXISTS idx_alerts_status       ON alerts (status);

-- ---------------------------------------------------------------------------
-- Threat intelligence enrichment (section 6.5): MITRE ATT&CK + CVE/NVD
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS threat_intel (
    id            SERIAL PRIMARY KEY,
    alert_id      UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    mitre_tactic     TEXT,
    mitre_technique  TEXT,                       -- e.g. T1110 (Brute Force)
    cve_id           TEXT,                       -- e.g. CVE-2023-1234
    cvss_score       NUMERIC(3,1),
    reference_url    TEXT,
    fetched_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_threat_intel_alert ON threat_intel (alert_id);

-- ---------------------------------------------------------------------------
-- GenAI assistant audit trail (section 9: traçabilité des actions IA)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS genai_audit (
    id            SERIAL PRIMARY KEY,
    alert_id      UUID REFERENCES alerts(id) ON DELETE SET NULL,
    user_role     TEXT,                          -- analyste / superviseur / admin (RBAC)
    prompt        TEXT,
    response      TEXT,
    sources       JSONB,                         -- RAG citations
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Helper: map a composite score to a criticality level (section 6.3 table)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION score_to_level(score NUMERIC)
RETURNS criticality_level AS $$
BEGIN
    IF score >= 80 THEN RETURN 'Critical';
    ELSIF score >= 60 THEN RETURN 'High';
    ELSIF score >= 35 THEN RETURN 'Medium';
    ELSE RETURN 'Low';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE;
