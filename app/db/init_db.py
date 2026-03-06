from app.db.db import connect
from app.db.schema import SCHEMA_SQL

def init_db(db_path: str) -> None:
    with connect(db_path) as conn:
        conn.executescript(SCHEMA_SQL)
