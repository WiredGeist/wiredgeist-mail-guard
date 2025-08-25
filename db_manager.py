# db_manager.py

import sqlite3
from datetime import datetime
import os
import re

DB_NAME = "threat_db.sqlite"
DB_DIR = os.path.dirname(__file__)  # Gets the directory of the current script
DB_PATH = os.path.join(DB_DIR, DB_NAME)

def get_db_connection():
    """Establishes a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row # Allows accessing columns by name
    return conn

def initialize_database():
    """
    Creates the database tables if they don't already exist.
    This is safe to run every time the app starts.
    """
    create_emails_table = """
    CREATE TABLE IF NOT EXISTS Emails (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        subject TEXT,
        sender TEXT
    );
    """
    
    create_indicators_table = """
    CREATE TABLE IF NOT EXISTS Indicators (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        indicator_type TEXT NOT NULL,  -- e.g., 'ip', 'domain', 'url', 'hash'
        indicator_value TEXT NOT NULL UNIQUE,
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """
    
    create_links_table = """
    CREATE TABLE IF NOT EXISTS EmailIndicatorLinks (
        email_id INTEGER,
        indicator_id INTEGER,
        PRIMARY KEY (email_id, indicator_id),
        FOREIGN KEY (email_id) REFERENCES Emails (id) ON DELETE CASCADE,
        FOREIGN KEY (indicator_id) REFERENCES Indicators (id) ON DELETE CASCADE
    );
    """
    
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(create_emails_table)
        cursor.execute(create_indicators_table)
        cursor.execute(create_links_table)
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database initialization error: {e}")
    finally:
        conn.close()

def log_indicator(cursor, indicator_type: str, indicator_value: str):
    """
    Logs a single indicator (IP, domain, URL) to the database.
    If the indicator already exists, it just returns its ID.
    If it's new, it creates it and returns the new ID.
    """
    if not indicator_value:
        return None
    
    # Check if indicator already exists
    cursor.execute("SELECT id FROM Indicators WHERE indicator_value = ?", (indicator_value,))
    data = cursor.fetchone()
    
    if data:
        return data['id'] # Return existing ID
    else:
        # Insert new indicator
        cursor.execute(
            "INSERT INTO Indicators (indicator_type, indicator_value, first_seen) VALUES (?, ?, ?)",
            (indicator_type, indicator_value, datetime.now())
        )
        return cursor.lastrowid # Return new ID

def log_investigation(sender: str, subject: str, investigation_data: dict):
    """
    Logs an entire investigation to the database, linking all indicators to a new email record.
    
    Args:
        sender: The email's 'From' field.
        subject: The email's 'Subject' field.
        investigation_data: The 'analysis_data_for_ai' dictionary.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        # --- Step 1: Create the Email record ---
        cursor.execute("INSERT INTO Emails (subject, sender) VALUES (?, ?)", (subject, sender))
        email_id = cursor.lastrowid
        
        # --- Step 2: Log all indicators and link them to the email ---
        
        # Log the sender's domain
        sender_domain = re.search(r'@([\w.-]+)', sender).group(1) if re.search(r'@([\w.-]+)', sender) else None
        if sender_domain:
            indicator_id = log_indicator(cursor, 'domain', sender_domain)
            cursor.execute("INSERT OR IGNORE INTO EmailIndicatorLinks (email_id, indicator_id) VALUES (?, ?)", (email_id, indicator_id))

        # Log the origin IP
        origin_ip = re.search(r'IP Address: (\b(?:\d{1,3}\.){3}\d{1,3}\b)', investigation_data.get('ip_origin_report', '')).group(1)
        if origin_ip:
            indicator_id = log_indicator(cursor, 'ip', origin_ip)
            cursor.execute("INSERT OR IGNORE INTO EmailIndicatorLinks (email_id, indicator_id) VALUES (?, ?)", (email_id, indicator_id))

        # Log all domains found in the reverse IP lookup
        reverse_ip_domains = re.findall(r'- ([\w.-]+\.[a-zA-Z]{2,})', investigation_data.get('reverse_ip_lookup', ''))
        for domain in reverse_ip_domains:
            indicator_id = log_indicator(cursor, 'domain', domain)
            cursor.execute("INSERT OR IGNORE INTO EmailIndicatorLinks (email_id, indicator_id) VALUES (?, ?)", (email_id, indicator_id))
            
        # Log all domains found in the domain report (SSL cert)
        ssl_domains = re.findall(r'- ([\w.-]+\.[a-zA-Z]{2,})', investigation_data.get('domain_report', ''))
        for domain in ssl_domains:
            indicator_id = log_indicator(cursor, 'domain', domain)
            cursor.execute("INSERT OR IGNORE INTO EmailIndicatorLinks (email_id, indicator_id) VALUES (?, ?)", (email_id, indicator_id))

        # Log all URLs from the link analysis
        urls = re.findall(r'https?://[^\s\n]+', investigation_data.get('embedded_link_analysis', ''))
        for url in urls:
            indicator_id = log_indicator(cursor, 'url', url)
            cursor.execute("INSERT OR IGNORE INTO EmailIndicatorLinks (email_id, indicator_id) VALUES (?, ?)", (email_id, indicator_id))
        
        # --- Step 3: Commit all changes ---
        conn.commit()
        print(f"Successfully logged investigation for Email ID {email_id} to database.")
        
    except sqlite3.Error as e:
        conn.rollback() # Roll back changes if anything failed
        print(f"Database logging error: {e}")
    finally:
        conn.close()

def check_indicator_history(indicators: list):
    """
    Checks a list of indicators against the database to see if they've been seen before.
    
    Args:
        indicators: A list of indicator strings to check (IPs, domains, URLs).
        
    Returns:
        A formatted string report of any historical sightings.
    """
    if not indicators:
        return "No indicators to check."
        
    conn = get_db_connection()
    report_lines = []
    try:
        cursor = conn.cursor()
        
        # Using a parameterized query to safely check all indicators at once
        placeholders = ','.join('?' for _ in indicators)
        query = f"""
            SELECT i.indicator_value, i.first_seen, COUNT(l.email_id) as email_count
            FROM Indicators i
            JOIN EmailIndicatorLinks l ON i.id = l.indicator_id
            WHERE i.indicator_value IN ({placeholders})
            GROUP BY i.indicator_value
            ORDER BY email_count DESC;
        """
        
        cursor.execute(query, indicators)
        results = cursor.fetchall()
        
        if not results:
            return "No historical context found for these indicators."
            
        report_lines.append("🔴 Historical Threat Intel Found:")
        for row in results:
            first_seen_date = datetime.strptime(row['first_seen'].split(" ")[0], '%Y-%m-%d').strftime('%Y-%m-%d')
            report_lines.append(
                f"- Indicator: {row['indicator_value']}\n"
                f"  (Seen in {row['email_count']} previous email(s), first seen on {first_seen_date})"
            )
            
        return "\n".join(report_lines)
        
    except sqlite3.Error as e:
        return f"Database history check error: {e}"
    finally:
        conn.close()

if __name__ == "__main__":
    # This part runs only if you execute `python db_manager.py` directly
    # It's a good way to test that the tables are created.
    print(f"Initializing database at: {DB_PATH}")
    initialize_database()
    print("Database initialized successfully.")
