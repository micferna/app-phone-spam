import Database from 'better-sqlite3';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

const DB_PATH = process.env.DB_PATH || './data/spam.db';
mkdirSync(dirname(DB_PATH), { recursive: true });

export const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
  -- Métadonnées serveur (ex : hash SHA-256 de la clé admin — jamais la
  -- clé en clair).
  CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    api_key TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    number TEXT NOT NULL,
    category TEXT,
    comment TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (user_id, number)
  );

  -- Numéros importés depuis des sources publiques (préfixes ARCEP mis à part,
  -- qui sont gérés en dur car ce sont des plages, pas des numéros).
  CREATE TABLE IF NOT EXISTS imported_numbers (
    number TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    label TEXT,
    imported_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- Préfixes importés depuis des sources publiques (ex : plages M2M,
  -- listes communautaires GitHub type Begone). Un préfixe couvre toute
  -- une plage de numéros.
  CREATE TABLE IF NOT EXISTS imported_prefixes (
    prefix TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    label TEXT,
    imported_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_reports_number ON reports(number);
`);
