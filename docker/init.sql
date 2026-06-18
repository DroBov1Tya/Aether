-- ============================================================
-- Aether — PostgreSQL initialization
-- Tables: agents, tasks
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- -----------------------------------------------------------
-- agents — registered scanner agents
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS agents (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip            VARCHAR(45)  NOT NULL,
    name          VARCHAR(255),
    version       VARCHAR(20),
    registered_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    status        VARCHAR(20)  NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'inactive', 'banned')),
    max_concurrent_tasks INTEGER NOT NULL DEFAULT 10
);

CREATE INDEX idx_agents_ip        ON agents (ip);
CREATE INDEX idx_agents_status    ON agents (status);

-- -----------------------------------------------------------
-- tasks — scan tasks dispatched to agents
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS tasks (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id      UUID REFERENCES agents(id) ON DELETE SET NULL,
    target        VARCHAR(255) NOT NULL,
    status        VARCHAR(20)  NOT NULL DEFAULT 'PENDING'
                    CHECK (status IN ('PENDING', 'IN_PROGRESS', 'DONE', 'FAILED', 'CANCELLED')),
    priority      INTEGER      NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    assigned_at   TIMESTAMPTZ,
    completed_at  TIMESTAMPTZ
);

CREATE INDEX idx_tasks_status     ON tasks (status);
CREATE INDEX idx_tasks_agent_id   ON tasks (agent_id);
CREATE INDEX idx_tasks_created_at ON tasks (created_at);
