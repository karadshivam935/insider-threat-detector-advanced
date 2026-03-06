import sqlite3
from contextlib import contextmanager
from typing import Iterator

@contextmanager
def connect(db_path: str) -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
