"""Isolated served browser fixture; never add synthetic tests to the analyst DB."""

import sqlite3
import uuid
from contextlib import closing

from ingestion import ROOT
from main import create_app
from storage import DATABASE_PATH

session_dir = ROOT / "evaluation" / "browser" / ("session-" + uuid.uuid4().hex)
session_dir.mkdir(parents=True)
database = session_dir / "soc.sqlite3"
with closing(sqlite3.connect(DATABASE_PATH)) as source, closing(sqlite3.connect(database)) as destination:
    source.backup(destination)
app = create_app(database_path=database, import_dir=session_dir / "imports")
