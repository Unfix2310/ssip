"""
Database: SQLite async setup for policy persistence.

Creates and manages the policies.db database with tables for:
  - policies:         compiled policies with IR and metadata
  - reviews:          human review decisions
  - policy_versions:  version history for rollback support
"""

from __future__ import annotations

import logging
import os
import aiosqlite

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "policies.db")

_CREATE_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    version TEXT NOT NULL DEFAULT '1.0.0',
    status TEXT NOT NULL DEFAULT 'draft',
    input_text TEXT NOT NULL,
    ir_json TEXT NOT NULL,
    compiled_policies TEXT NOT NULL DEFAULT '{}',
    primary_format TEXT NOT NULL DEFAULT 'cedar',
    confidence_score REAL DEFAULT 0.0,
    routing_decision TEXT DEFAULT 'auto_approve',
    routing_reason TEXT,
    effect TEXT NOT NULL DEFAULT 'permit',
    principal_raw TEXT,
    resource_raw TEXT,
    principal_canonical TEXT,
    resource_canonical TEXT,
    principal_tier TEXT,
    resource_tier TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id TEXT NOT NULL,
    reviewer TEXT,
    decision TEXT NOT NULL,
    correction TEXT,
    reason TEXT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (policy_id) REFERENCES policies(id)
);

CREATE TABLE IF NOT EXISTS policy_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id TEXT NOT NULL,
    version TEXT NOT NULL,
    ir_json TEXT NOT NULL,
    compiled_policies TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    rolled_back INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (policy_id) REFERENCES policies(id)
);

CREATE INDEX IF NOT EXISTS idx_policies_status ON policies(status);
CREATE INDEX IF NOT EXISTS idx_reviews_policy_id ON reviews(policy_id);
CREATE INDEX IF NOT EXISTS idx_versions_policy_id ON policy_versions(policy_id);

CREATE TABLE IF NOT EXISTS controls (
    id TEXT PRIMARY KEY,
    version TEXT NOT NULL DEFAULT '1.0.0',
    status TEXT NOT NULL DEFAULT 'draft',
    input_text TEXT NOT NULL,
    ir_json TEXT NOT NULL,
    compiled_yaml TEXT NOT NULL DEFAULT '',
    document_id TEXT,
    section TEXT,
    rule_type TEXT,
    effect TEXT NOT NULL DEFAULT 'required',
    confidence_score REAL DEFAULT 0.0,
    routing_decision TEXT DEFAULT 'auto_approve',
    routing_reason TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS benchmark_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_at TEXT NOT NULL DEFAULT (datetime('now')),
    total_rules INTEGER NOT NULL,
    successful INTEGER NOT NULL,
    failed INTEGER NOT NULL,
    results_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_controls_status ON controls(status);
CREATE INDEX IF NOT EXISTS idx_controls_document ON controls(document_id);
"""


async def init_db() -> None:
    """Initialize the database and create tables if they don't exist."""
    logger.info("[Database] Initializing database at %s", DB_PATH)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(_CREATE_TABLES_SQL)
        await db.commit()
    logger.info("[Database] Database initialized successfully.")


async def get_db() -> aiosqlite.Connection:
    """Get an async database connection."""
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    return db
