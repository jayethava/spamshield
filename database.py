"""
SpamShield: SQLite Database Layer
=================================
Manages storage, retrieval, filtering, deletion, and analytics
aggregation for past message analysis history.
"""

import os
import sqlite3
import json
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'database.db')


def get_db_connection():
    """Returns a SQLite connection with Row factory enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes the database schema if not already present."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            subject TEXT,
            message TEXT NOT NULL,
            snippet TEXT NOT NULL,
            verdict TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            confidence REAL NOT NULL,
            category TEXT NOT NULL,
            flagged_words TEXT,
            links_count INTEGER DEFAULT 0,
            suspicious_links INTEGER DEFAULT 0
        );
    """)
    conn.commit()
    conn.close()


def insert_check(message: str, verdict: str, risk_score: int, confidence: float,
                 category: str, flagged_words: list = None, links_count: int = 0,
                 suspicious_links: int = 0, subject: str = "") -> int:
    """Inserts a new analyzed message record into the database."""
    init_db()
    # Create clean snippet
    snippet_source = f"[{subject}] {message}" if subject else message
    snippet = snippet_source.strip().replace('\n', ' ')
    if len(snippet) > 85:
        snippet = snippet[:82] + "..."

    flagged_words_json = json.dumps(flagged_words or [])

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO checks (
            timestamp, subject, message, snippet, verdict,
            risk_score, confidence, category, flagged_words,
            links_count, suspicious_links
        ) VALUES (
            datetime('now', 'localtime'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
    """, (
        subject.strip() if subject else "",
        message.strip(),
        snippet,
        verdict,
        risk_score,
        confidence,
        category,
        flagged_words_json,
        links_count,
        suspicious_links
    ))
    new_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return new_id


def get_history(search: str = "", verdict_filter: str = "", category_filter: str = "", limit: int = 150):
    """Retrieves checks history matching optional search keyword and filters."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM checks WHERE 1=1"
    params = []

    if search.strip():
        query += " AND (message LIKE ? OR subject LIKE ? OR snippet LIKE ?)"
        term = f"%{search.strip()}%"
        params.extend([term, term, term])

    if verdict_filter.strip() and verdict_filter.upper() != "ALL":
        query += " AND verdict = ?"
        params.append(verdict_filter.upper())

    if category_filter.strip() and category_filter.lower() != "all":
        query += " AND category = ?"
        params.append(category_filter)

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    result = []
    for r in rows:
        flagged = []
        try:
            flagged = json.loads(r['flagged_words']) if r['flagged_words'] else []
        except Exception:
            pass

        result.append({
            'id': r['id'],
            'timestamp': r['timestamp'],
            'subject': r['subject'] or '',
            'message': r['message'],
            'snippet': r['snippet'],
            'verdict': r['verdict'],
            'risk_score': r['risk_score'],
            'confidence': r['confidence'],
            'category': r['category'],
            'flagged_words': flagged,
            'links_count': r['links_count'],
            'suspicious_links': r['suspicious_links']
        })
    return result


def delete_check(check_id: int) -> bool:
    """Deletes a single history record by ID."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM checks WHERE id = ?", (check_id,))
    rows_affected = cursor.rowcount
    conn.commit()
    conn.close()
    return rows_affected > 0


def clear_history() -> int:
    """Deletes all records from the checks history."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM checks")
    rows_affected = cursor.rowcount
    conn.commit()
    conn.close()
    return rows_affected


def get_analytics_summary():
    """
    Computes aggregated statistical metrics for the Dashboard:
    - Counts by verdict (SAFE, SUSPICIOUS, SPAM)
    - Counts by scam category
    - Timeline breakdown (checks per day or date)
    - Average risk score
    """
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    # Total counts
    cursor.execute("SELECT COUNT(*), AVG(risk_score) FROM checks")
    total_row = cursor.fetchone()
    total_checks = total_row[0] or 0
    avg_risk = round(total_row[1] or 0.0, 1)

    # Verdict breakdown
    cursor.execute("SELECT verdict, COUNT(*) FROM checks GROUP BY verdict")
    verdict_rows = cursor.fetchall()
    verdict_counts = {'SAFE': 0, 'SUSPICIOUS': 0, 'SPAM': 0}
    for row in verdict_rows:
        if row[0] in verdict_counts:
            verdict_counts[row[0]] = row[1]

    # Category breakdown
    cursor.execute("SELECT category, COUNT(*) FROM checks GROUP BY category ORDER BY COUNT(*) DESC")
    category_rows = cursor.fetchall()
    category_counts = {row[0]: row[1] for row in category_rows}

    # Timeline breakdown (Last 7 days or unique dates)
    cursor.execute("""
        SELECT substr(timestamp, 1, 10) as check_date, COUNT(*)
        FROM checks
        GROUP BY check_date
        ORDER BY check_date ASC
        LIMIT 14
    """)
    timeline_rows = cursor.fetchall()
    timeline = [{'date': row[0], 'count': row[1]} for row in timeline_rows]

    conn.close()

    return {
        'total_checks': total_checks,
        'avg_risk': avg_risk,
        'verdict_counts': verdict_counts,
        'category_counts': category_counts,
        'timeline': timeline
    }


def get_all_rows_for_export():
    """Returns all rows formatted for CSV export."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, timestamp, subject, snippet, verdict,
               risk_score, confidence, category, links_count, suspicious_links
        FROM checks
        ORDER BY id DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return rows


# Ensure database is created on import
init_db()
