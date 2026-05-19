"""
Database Module
Autonomous Security Platform

- Stores scan results
- Stores vulnerability findings
- Provides query interface
"""

import sqlite3


class Database:

    def __init__(self, db_name="security_platform.db"):
        self.db_name = db_name
        self._create_tables()

    # ------------------------------------------
    # Create Tables
    # ------------------------------------------

    def _create_tables(self):

        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            date TEXT
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            type TEXT,
            url TEXT,
            parameter TEXT,
            severity TEXT
        )
        """)

        conn.commit()
        conn.close()

    # ------------------------------------------
    # Insert Scan
    # ------------------------------------------

    def insert_scan(self, target, date):

        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO scans (target, date) VALUES (?, ?)",
            (target, date)
        )

        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return scan_id

    # ------------------------------------------
    # Insert Finding
    # ------------------------------------------

    def insert_finding(self, scan_id, finding):

        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO findings (scan_id, type, url, parameter, severity)
        VALUES (?, ?, ?, ?, ?)
        """, (
            scan_id,
            finding.get("type"),
            finding.get("url"),
            finding.get("parameter", ""),
            finding.get("severity")
        ))

        conn.commit()
        conn.close()

    # ------------------------------------------
    # Get All Scans
    # ------------------------------------------

    def get_scans(self):

        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM scans ORDER BY id DESC")
        data = cursor.fetchall()

        conn.close()
        return data

    # ------------------------------------------
    # Get Findings By Scan
    # ------------------------------------------

    def get_findings(self, scan_id):

        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT type, url, parameter, severity FROM findings WHERE scan_id=?",
            (scan_id,)
        )

        data = cursor.fetchall()
        conn.close()

        return data
