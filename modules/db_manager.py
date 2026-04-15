#!/usr/bin/env python3
import sqlite3
import json
from datetime import datetime

class DBManager:
    def __init__(self, db_path='data/hunt_results.db'):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # 建立数据关联（域名 → 子域名 → IP → 端口 → 漏洞）
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE,
                    ip TEXT,
                    ports TEXT,
                    fingerprints TEXT,
                    last_scan TIMESTAMP
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER,
                    type TEXT,
                    url TEXT,
                    parameter TEXT,
                    payload TEXT,
                    evidence TEXT,
                    risk_level TEXT,
                    verified BOOLEAN,
                    poc_curl TEXT,
                    reproduction_steps TEXT,
                    remediation TEXT,
                    timestamp TIMESTAMP,
                    FOREIGN KEY (target_id) REFERENCES targets (id)
                )
            ''')
            conn.commit()

    def add_target(self, domain, ip=None, ports=None, fingerprints=None):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO targets (domain, ip, ports, fingerprints, last_scan)
                VALUES (?, ?, ?, ?, ?)
            ''', (domain, ip, json.dumps(ports), json.dumps(fingerprints), datetime.now()))
            conn.commit()
            return cursor.lastrowid

    def add_vulnerability(self, target_id, vuln_data):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO vulnerabilities (
                    target_id, type, url, parameter, payload, evidence, 
                    risk_level, verified, poc_curl, reproduction_steps, 
                    remediation, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                target_id,
                vuln_data.get('type'),
                vuln_data.get('url'),
                vuln_data.get('parameter'),
                vuln_data.get('payload'),
                vuln_data.get('evidence'),
                vuln_data.get('risk_level'),
                vuln_data.get('verified'),
                vuln_data.get('poc_curl'),
                json.dumps(vuln_data.get('reproduction_steps')),
                vuln_data.get('remediation'),
                datetime.now()
            ))
            conn.commit()
