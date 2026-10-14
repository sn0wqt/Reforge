"""Unit tests for Reforge safe read-only SQLite schema and metadata scanner."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from reforge.core.scanners.sqlite_scanner import (
    SqliteScanner,
    build_readonly_uri,
    quote_identifier,
    safe_cell_value,
)


def create_test_db(db_path: Path) -> Path:
    """Create a sample test database with tables, views, triggers, and indexes."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA encoding = 'UTF-8'")
    conn.execute("""
        CREATE TABLE departments (
            dept_id INTEGER PRIMARY KEY,
            dept_name TEXT NOT NULL,
            budget REAL DEFAULT 0.0
        );
    """)
    conn.execute("""
        CREATE TABLE employees (
            emp_id INTEGER PRIMARY KEY AUTOINCREMENT,
            dept_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            salary REAL DEFAULT 50000.0,
            photo BLOB,
            FOREIGN KEY (dept_id) REFERENCES departments(dept_id)
                ON UPDATE CASCADE ON DELETE RESTRICT
        );
    """)
    conn.execute("CREATE INDEX idx_emp_name ON employees(name);")
    conn.execute("CREATE UNIQUE INDEX idx_emp_dept_name ON employees(dept_id, name);")
    conn.execute("""
        CREATE VIEW active_employees AS
        SELECT emp_id, name, dept_id, salary
        FROM employees
        WHERE salary > 0;
    """)
    conn.execute("""
        CREATE TRIGGER tr_audit_emp AFTER INSERT ON employees
        BEGIN
            SELECT 1;
        END;
    """)

    # Populate sample rows
    conn.execute("INSERT INTO departments VALUES (1, 'Engineering', 1000000.0);")
    conn.execute("INSERT INTO departments VALUES (2, 'Design', 500000.0);")
    for i in range(1, 26):
        conn.execute(
            "INSERT INTO employees (dept_id, name, salary, photo) VALUES (?, ?, ?, ?)",
            (1 if i % 2 == 0 else 2, f"Worker_{i:02d}", 60000.0 + (i * 1000), b"\xde\xad\xbe\xef"),
        )
    conn.commit()
    conn.close()
    return db_path


def test_is_sqlite_database_and_probe_bytes(tmp_path: Path) -> None:
    db_file = tmp_path / "valid.db"
    create_test_db(db_file)

    assert SqliteScanner.is_sqlite_database(db_file) is True
    assert SqliteScanner.probe_bytes(db_file.read_bytes()[:32]) is True

    non_db = tmp_path / "plain.txt"
    non_db.write_text("Hello, world!")
    assert SqliteScanner.is_sqlite_database(non_db) is False
    assert SqliteScanner.probe_bytes(b"Hello world") is False
    assert SqliteScanner.is_sqlite_database(tmp_path / "nonexistent.db") is False


def test_build_readonly_uri(tmp_path: Path) -> None:
    db_file = tmp_path / "read_only.db"
    create_test_db(db_file)

    uri_immutable = build_readonly_uri(db_file, immutable=True)
    assert "immutable=1" in uri_immutable
    assert "mode=ro" in uri_immutable
    assert uri_immutable.startswith("file:")

    uri_mutable = build_readonly_uri(db_file, immutable=False)
    assert "immutable=0" in uri_mutable
    assert "mode=ro" in uri_mutable

    # Connect and verify write protection
    conn = SqliteScanner.connect_readonly(uri_immutable)
    try:
        cur = conn.cursor()
        rows = cur.execute("SELECT count(*) FROM departments").fetchone()
        assert rows[0] == 2

        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            cur.execute("INSERT INTO departments VALUES (99, 'Hacked', 0.0)")
    finally:
        conn.close()


def test_quote_identifier() -> None:
    assert quote_identifier("users") == '"users"'
    assert quote_identifier('my "table"') == '"my ""table"""'
    assert quote_identifier("col.with.dots") == '"col.with.dots"'


def test_safe_cell_value_formatting() -> None:
    assert safe_cell_value(None) is None
    assert safe_cell_value(42) == 42
    assert safe_cell_value("text") == "text"
    assert safe_cell_value(b"\xca\xfe\xba\xbe") == "cafebabe"
    assert safe_cell_value(float("inf")) == "Infinity"
    assert safe_cell_value(float("-inf")) == "-Infinity"
    assert safe_cell_value(float("nan")) == "NaN"
    assert safe_cell_value(-0.0) == "-0.0"
    assert safe_cell_value(0.0) == 0.0


def test_inspect_tables_columns_and_types(tmp_path: Path) -> None:
    db_file = tmp_path / "schema.db"
    create_test_db(db_file)

    info = SqliteScanner.inspect_file(db_file, use_snapshot=False)
    assert info.engine_version != ""
    assert info.database_encoding in ("UTF-8", "UTF-16le", "UTF-16be")
    assert "departments" in info.table_names
    assert "employees" in info.table_names

    dept_table = info.get_table("departments")
    assert dept_table is not None
    assert dept_table.kind == "table"
    assert dept_table.primary_keys == ("dept_id",)

    cols = {c.name: c for c in dept_table.columns}
    assert "dept_id" in cols
    assert "dept_name" in cols
    assert "budget" in cols

    assert cols["dept_id"].primary_key_position == 1
    assert cols["dept_name"].not_null is True
    assert cols["budget"].default_sql == "0.0"


def test_primary_keys_composite_and_single(tmp_path: Path) -> None:
    db_file = tmp_path / "pk.db"
    conn = sqlite3.connect(db_file)
    conn.execute("""
        CREATE TABLE order_items (
            order_id INTEGER,
            item_id INTEGER,
            qty INTEGER NOT NULL,
            PRIMARY KEY (order_id, item_id)
        );
    """)
    conn.commit()
    conn.close()

    info = SqliteScanner.inspect_file(db_file, use_snapshot=False)
    table = info.get_table("order_items")
    assert table is not None
    assert table.primary_keys == ("order_id", "item_id")

    cols = {c.name: c for c in table.columns}
    assert cols["order_id"].primary_key_position == 1
    assert cols["item_id"].primary_key_position == 2
    assert cols["qty"].primary_key_position == 0


def test_foreign_keys(tmp_path: Path) -> None:
    db_file = tmp_path / "fk.db"
    create_test_db(db_file)

    info = SqliteScanner.inspect_file(db_file, use_snapshot=False)
    emp_table = info.get_table("employees")
    assert emp_table is not None
    assert len(emp_table.foreign_keys) == 1

    fk = emp_table.foreign_keys[0]
    assert fk.target_table == "departments"
    assert fk.from_column == "dept_id"
    assert fk.to_column == "dept_id"
    assert fk.on_update == "CASCADE"
    assert fk.on_delete == "RESTRICT"


def test_strict_and_without_rowid_tables(tmp_path: Path) -> None:
    db_file = tmp_path / "strict.db"
    conn = sqlite3.connect(db_file)
    conn.execute("""
        CREATE TABLE strict_kv (
            key TEXT PRIMARY KEY,
            val TEXT NOT NULL
        ) WITHOUT ROWID, STRICT;
    """)
    conn.commit()
    conn.close()

    info = SqliteScanner.inspect_file(db_file, use_snapshot=False)
    table = info.get_table("strict_kv")
    assert table is not None
    assert table.without_rowid is True
    assert table.strict is True
    assert table.primary_keys == ("key",)


def test_generated_columns(tmp_path: Path) -> None:
    db_file = tmp_path / "generated.db"
    conn = sqlite3.connect(db_file)
    conn.execute("""
        CREATE TABLE invoices (
            id INTEGER PRIMARY KEY,
            amount REAL,
            tax REAL GENERATED ALWAYS AS (amount * 0.1) STORED,
            total REAL GENERATED ALWAYS AS (amount + tax) VIRTUAL
        );
    """)
    conn.commit()
    conn.close()

    info = SqliteScanner.inspect_file(db_file, use_snapshot=False)
    table = info.get_table("invoices")
    assert table is not None

    cols = {c.name: c for c in table.columns}
    assert cols["id"].hidden == 0
    assert cols["amount"].hidden == 0
    # Generated columns have hidden in (2, 3)
    assert cols["tax"].hidden in (2, 3)
    assert cols["total"].hidden in (2, 3)


def test_indexes_unique_and_composite(tmp_path: Path) -> None:
    db_file = tmp_path / "indexes.db"
    create_test_db(db_file)

    info = SqliteScanner.inspect_file(db_file, use_snapshot=False)
    idx_map = {idx.name: idx for idx in info.indexes}

    assert "idx_emp_name" in idx_map
    assert idx_map["idx_emp_name"].table == "employees"
    assert idx_map["idx_emp_name"].unique is False
    assert idx_map["idx_emp_name"].columns == ("name",)

    assert "idx_emp_dept_name" in idx_map
    assert idx_map["idx_emp_dept_name"].table == "employees"
    assert idx_map["idx_emp_dept_name"].unique is True
    assert idx_map["idx_emp_dept_name"].columns == ("dept_id", "name")


def test_views_and_triggers(tmp_path: Path) -> None:
    db_file = tmp_path / "views_triggers.db"
    create_test_db(db_file)

    info = SqliteScanner.inspect_file(db_file, use_snapshot=False)
    assert "active_employees" in info.view_names
    view = next(v for v in info.views if v.name == "active_employees")
    assert "SELECT" in (view.sql or "")

    assert len(info.triggers) >= 1
    trigger = next(t for t in info.triggers if t.name == "tr_audit_emp")
    assert trigger.table == "employees"
    assert "AFTER INSERT" in (trigger.sql or "")


def test_case_insensitive_trigger_attribution(tmp_path: Path) -> None:
    db_file = tmp_path / "casing.db"
    conn = sqlite3.connect(db_file)
    conn.execute("CREATE TABLE Accounts (account_id INT PRIMARY KEY);")
    conn.execute("CREATE TRIGGER tr_accounts AFTER INSERT ON accounts BEGIN SELECT 1; END;")
    conn.commit()
    conn.close()

    info = SqliteScanner.inspect_file(db_file, use_snapshot=False)
    trigger = next(t for t in info.triggers if t.name == "tr_accounts")
    # Should resolve to canonical table name "Accounts"
    assert trigger.table == "Accounts"


def test_row_sampling_and_truncation(tmp_path: Path) -> None:
    db_file = tmp_path / "sampling.db"
    create_test_db(db_file)

    # 1. Truncated sample (limit 10 of 25 rows)
    info_trunc = SqliteScanner.inspect_file(
        db_file,
        use_snapshot=False,
        sample_table="employees",
        row_limit=10,
    )
    sample = info_trunc.sampled_rows
    assert sample is not None
    assert sample.table == "employees"
    assert sample.returned_rows == 10
    assert sample.truncated is True
    assert len(sample.rows) == 10
    assert sample.rows[0]["photo"] == "deadbeef"  # Blob formatted as hex string

    # 2. Complete sample (limit 50 of 25 rows)
    info_full = SqliteScanner.inspect_file(
        db_file,
        use_snapshot=False,
        sample_table="employees",
        row_limit=50,
    )
    sample_full = info_full.sampled_rows
    assert sample_full is not None
    assert sample_full.returned_rows == 25
    assert sample_full.truncated is False

    # 3. Specific column projection
    conn = SqliteScanner.connect_readonly(build_readonly_uri(db_file))
    try:
        col_sample = SqliteScanner.sample_table_rows(
            conn,
            "employees",
            limit=5,
            columns=["name", "salary"],
        )
        assert col_sample.columns == ("name", "salary")
        assert list(col_sample.rows[0].keys()) == ["name", "salary"]

        with pytest.raises(ValueError, match="does not exist"):
            SqliteScanner.sample_table_rows(conn, "employees", columns=["nonexistent_col"])
    finally:
        conn.close()


def test_wal_snapshot_and_checkpointing(tmp_path: Path) -> None:
    db_file = tmp_path / "wal_test.db"
    conn = sqlite3.connect(db_file)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("CREATE TABLE wal_records (id INT, note TEXT);")
    conn.execute("INSERT INTO wal_records VALUES (1, 'initial');")
    conn.commit()

    # Insert without checkpointing so WAL has pending frames
    conn.execute("INSERT INTO wal_records VALUES (2, 'in_wal');")
    conn.commit()

    wal_file = tmp_path / "wal_test.db-wal"
    assert wal_file.is_file()

    # Capture snapshot
    snap_dir = tmp_path / "snapshots"
    snap_result = SqliteScanner.capture_snapshot(db_file, snap_dir)
    assert snap_result.wal_artifact is not None
    assert snap_result.wal_artifact.size_bytes > 0
    assert snap_result.database_artifact.size_bytes > 0

    # Inspection via snapshot incorporates the WAL frames
    info = SqliteScanner.inspect_file(db_file, use_snapshot=True, sample_table="wal_records", row_limit=10)
    assert info.sampled_rows is not None
    assert info.sampled_rows.returned_rows == 2
    notes = [r["note"] for r in info.sampled_rows.rows]
    assert "initial" in notes
    assert "in_wal" in notes

    conn.close()


def test_journal_quiescence_verification(tmp_path: Path) -> None:
    db_file = tmp_path / "journal_test.db"
    create_test_db(db_file)
    journal_file = tmp_path / "journal_test.db-journal"

    # 1. Clean TRUNCATE journal (0 bytes)
    journal_file.write_bytes(b"")
    quiescent, reason = SqliteScanner.verify_journal_quiescence(journal_file)
    assert quiescent is True
    assert reason is None

    # 2. Clean PERSIST journal (28 zero bytes)
    journal_file.write_bytes(b"\x00" * 28)
    quiescent, reason = SqliteScanner.verify_journal_quiescence(journal_file)
    assert quiescent is True
    assert reason is None

    # 3. Active uncommitted journal (non-zero bytes)
    journal_file.write_bytes(b"\xd9\xd5\x05\xf9" + (b"\x01" * 24))
    quiescent, reason = SqliteScanner.verify_journal_quiescence(journal_file)
    assert quiescent is False
    assert "recovery" in (reason or "")

    # Snapshot must reject active journal
    with pytest.raises(ValueError, match="Rollback journal may require recovery"):
        SqliteScanner.capture_snapshot(db_file, tmp_path / "snap_fail")


def test_probe_file_and_get_table(tmp_path: Path) -> None:
    db_file = tmp_path / "probe.db"
    create_test_db(db_file)

    info = SqliteScanner.probe_file(db_file)
    assert info is not None
    assert any("engine: SQLite" in n for n in info.notes)
    assert any(n.startswith("tables:") for n in info.notes)
    assert "departments" in info.table_names
    assert "employees" in info.table_names

    # Case-insensitive table getter
    assert info.get_table("DEPARTMENTS") is not None
    assert info.get_table("departments") is not None
    assert info.get_table("nonexistent") is None

    # Probe on non-db
    fake_file = tmp_path / "fake.bin"
    fake_file.write_bytes(b"NOT A SQLITE DB")
    assert SqliteScanner.probe_file(fake_file) is None
