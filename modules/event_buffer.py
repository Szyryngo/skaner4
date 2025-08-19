"""Event buffering module: persist captured events in SQLite queue."""
import sqlite3
import threading
import time
import pickle
import os

class EventBuffer:
    """Persistent FIFO buffer for Event objects using SQLite."""
    def __init__(self, db_path=None):
        if db_path is None:
            data_dir = os.path.join(os.getcwd(), 'data')
            os.makedirs(data_dir, exist_ok=True)
            db_path = os.path.join(data_dir, 'event_buffer.db')
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.lock = threading.Lock()
        self._init_table()

    def _init_table(self):
        with self.lock:
            c = self.conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS events (
                         id INTEGER PRIMARY KEY AUTOINCREMENT,
                         ts REAL,
                         event BLOB)''')
            self.conn.commit()

    def insert_event(self, event):
        """Insert an Event into buffer."""
        with self.lock:
            raw = pickle.dumps(event)
            ts = time.time()
            c = self.conn.cursor()
            c.execute('INSERT INTO events (ts, event) VALUES (?, ?)', (ts, raw))
            self.conn.commit()

    def get_event(self):
        """Retrieve and remove the oldest Event from buffer, or None if empty."""
        with self.lock:
            c = self.conn.cursor()
            c.execute('SELECT id, event FROM events ORDER BY id LIMIT 1')
            row = c.fetchone()
            if not row:
                return None
            eid, raw = row
            event = pickle.loads(raw)
            c.execute('DELETE FROM events WHERE id = ?', (eid,))
            self.conn.commit()
            return event
