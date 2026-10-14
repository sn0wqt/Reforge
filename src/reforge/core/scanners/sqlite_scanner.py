"""Safe read-only SQLite schema, metadata, and snapshot scanner.

Ported from REA's robust SQLite inspection architecture. Uses Python's built-in
sqlite3 in read-only URI mode (`file:...immutable=1&mode=ro`) with defensive PRAGMAs,
quiescence checks for rollback journals and WAL files, atomic stability verification,
and deep schema discovery (tables, columns, primary keys, foreign keys, indexes,
views, triggers, STRICT/WITHOUT ROWID modes, and generated columns).
"""

from __future__ import annotations

import hashlib
import math
import sqlite3
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SQLITE_HEADER_MAGIC = b"SQLite format 3\x00"
SQLITE_JOURNAL_HEADER_SIZE = 28
DEFAULT_MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024  # 256 MiB budget
DEFAULT_ROW_SAMPLE_LIMIT = 20


def quote_identifier(name: str) -> str:
    """Safely quote a SQLite identifier with double quotes, escaping embedded quotes."""
    escaped = name.replace('"', '""')
    return f'"{escaped}"'


def build_readonly_uri(path: str | Path, immutable: bool = True) -> str:
    """Build a safe read-only file: URI for SQLite with mode=ro and immutable flag."""
    p = Path(path).resolve()
    base_uri = p.as_uri()
    imm_flag = "1" if immutable else "0"
    return f"{base_uri}?immutable={imm_flag}&mode=ro"


def safe_cell_value(val: Any) -> Any:
    """Convert a raw SQLite cell into a JSON-safe representation.

    Handles integers, floats (including -0.0, Infinity, NaN), text, blobs (as hex),
    and null values safely without arbitrary code execution.
    """
    if val is None:
        return None
    if isinstance(val, (int, str, bool)):
        return val
    if isinstance(val, float):
        if math.isinf(val):
            return "Infinity" if val > 0 else "-Infinity"
        if math.isnan(val):
            return "NaN"
        if val == 0.0 and math.copysign(1.0, val) < 0:
            return "-0.0"
        return val
    if isinstance(val, (bytes, bytearray, memoryview)):
        return bytes(val).hex()
    return str(val)


@dataclass(frozen=True)
class SqliteColumn:
    """Column definition extracted from PRAGMA table_xinfo."""

    cid: int
    name: str
    declared_type: str
    not_null: bool
    default_sql: str | None
    primary_key_position: int  # 0 if not PK, 1..N indicating PK column order
    hidden: int = 0  # 0=normal, 1=hidden, 2=virtual generated, 3=stored generated


@dataclass(frozen=True)
class SqliteForeignKey:
    """Foreign key relationship extracted from PRAGMA foreign_key_list."""

    id: int
    seq: int
    target_table: str
    from_column: str
    to_column: str | None
    on_update: str
    on_delete: str
    match: str = "NONE"


@dataclass(frozen=True)
class SqliteIndex:
    """Index metadata and indexed columns."""

    name: str
    table: str
    sql: str | None
    root_page: int
    unique: bool
    columns: tuple[str, ...] = ()


@dataclass(frozen=True)
class SqliteView:
    """View definition from sqlite_schema."""

    name: str
    sql: str | None


@dataclass(frozen=True)
class SqliteTrigger:
    """Trigger definition and associated table."""

    name: str
    table: str
    sql: str | None


@dataclass(frozen=True)
class SqliteTable:
    """Table definition including columns, constraints, and mode flags."""

    name: str
    sql: str | None
    root_page: int
    kind: str  # "table", "view", "virtual", "shadow", "unknown"
    without_rowid: bool = False
    strict: bool = False
    column_count: int | None = None
    columns: tuple[SqliteColumn, ...] = ()
    primary_keys: tuple[str, ...] = ()
    foreign_keys: tuple[SqliteForeignKey, ...] = ()


@dataclass(frozen=True)
class SqliteArtifactInfo:
    """File identity and hash evidence."""

    path: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True)
class SqliteSnapshotResult:
    """Result of capturing an isolated SQLite snapshot and WAL pair."""

    snapshot_path: str
    database_artifact: SqliteArtifactInfo
    wal_artifact: SqliteArtifactInfo | None
    journal_present: bool
    journal_active: bool


@dataclass(frozen=True)
class SqliteRowSample:
    """Bounded, safe sample of committed ordinary-table rows."""

    table: str
    columns: tuple[str, ...]
    rows: tuple[dict[str, Any], ...]
    row_limit: int
    returned_rows: int
    truncated: bool


@dataclass
class SqliteDatabaseInfo:
    """Comprehensive inspection report for an SQLite database."""

    database_path: str
    engine_version: str
    database_encoding: str
    artifact: SqliteArtifactInfo | None = None
    wal_artifact: SqliteArtifactInfo | None = None
    tables: tuple[SqliteTable, ...] = ()
    indexes: tuple[SqliteIndex, ...] = ()
    views: tuple[SqliteView, ...] = ()
    triggers: tuple[SqliteTrigger, ...] = ()
    limitations: tuple[str, ...] = ()
    sampled_rows: SqliteRowSample | None = None

    @property
    def notes(self) -> tuple[str, ...]:
        entries: list[str] = [
            f"engine: SQLite {self.engine_version}",
            f"encoding: {self.database_encoding}",
            f"tables: {len(self.tables)}",
            f"indexes: {len(self.indexes)}",
            f"views: {len(self.views)}",
            f"triggers: {len(self.triggers)}",
        ]
        if self.wal_artifact:
            entries.append(f"wal: present ({self.wal_artifact.size_bytes} bytes)")
        if self.limitations:
            entries.append(f"limitations: {len(self.limitations)} items noted")
        return tuple(entries)

    def get_table(self, name: str) -> SqliteTable | None:
        """Find a table by exact name, falling back to case-insensitive match."""
        for t in self.tables:
            if t.name == name:
                return t
        lower_name = name.lower()
        for t in self.tables:
            if t.name.lower() == lower_name:
                return t
        return None

    @property
    def table_names(self) -> tuple[str, ...]:
        return tuple(t.name for t in self.tables)

    @property
    def view_names(self) -> tuple[str, ...]:
        return tuple(v.name for v in self.views)


class SqliteScanner:
    """Zero-dependency, safe, read-only SQLite schema, metadata, and row extractor."""

    @classmethod
    def is_sqlite_database(cls, path: str | Path) -> bool:
        """Check if file starts with the 16-byte SQLite 3 magic header."""
        p = Path(path)
        if not p.is_file() or p.is_symlink():
            return False
        try:
            with p.open("rb") as f:
                header = f.read(16)
            return header == SQLITE_HEADER_MAGIC
        except OSError:
            return False

    @classmethod
    def probe_bytes(cls, data: bytes) -> bool:
        """Return True if raw data begins with SQLite 3 format header."""
        return data.startswith(SQLITE_HEADER_MAGIC)

    @classmethod
    def verify_journal_quiescence(cls, journal_path: str | Path) -> tuple[bool, str | None]:
        """Verify whether an existing rollback journal is quiescent (clean).

        In PERSIST mode, a committed transaction zeroes the entire 28-byte header.
        In TRUNCATE mode, the file is 0 bytes.
        If non-zero bytes are present in the header, rollback recovery is required.
        """
        p = Path(journal_path)
        if not p.exists():
            return True, None
        try:
            st = p.stat()
        except OSError as e:
            return False, f"Could not stat journal: {e}"
        if st.st_size == 0:
            return True, None
        if st.st_size < SQLITE_JOURNAL_HEADER_SIZE:
            return False, f"Incomplete journal header: {st.st_size} bytes"
        try:
            with p.open("rb") as f:
                header = f.read(SQLITE_JOURNAL_HEADER_SIZE)
            if len(header) == SQLITE_JOURNAL_HEADER_SIZE and all(b == 0 for b in header):
                return True, None
            return False, f"Active or uncommitted journal requires recovery: {p}"
        except OSError as e:
            return False, f"Failed to read journal: {e}"

    @classmethod
    def capture_snapshot(
        cls,
        source_path: str | Path,
        target_dir: str | Path,
        max_bytes: int = DEFAULT_MAX_SNAPSHOT_BYTES,
    ) -> SqliteSnapshotResult:
        """Safely snapshot a database and optional WAL into an isolated directory.

        Detects file changes during acquisition and verifies journal quiescence.
        """
        src = Path(source_path).resolve()
        if not src.is_file():
            raise FileNotFoundError(f"Selected SQLite database does not exist: {src}")
        if src.is_symlink():
            raise ValueError(f"Expected a regular file without a symlink: {src}")

        tgt_dir = Path(target_dir).resolve()
        tgt_dir.mkdir(parents=True, exist_ok=True)
        snapshot_path = tgt_dir / "database.snapshot"

        wal_path = src.with_name(src.name + "-wal")
        has_wal = wal_path.is_file() and not wal_path.is_symlink()

        journal_path = src.with_name(src.name + "-journal")
        has_journal = journal_path.exists()

        if has_journal:
            quiescent, reason = cls.verify_journal_quiescence(journal_path)
            if not quiescent:
                raise ValueError(f"Rollback journal may require recovery: {reason}")

        db_stat_before = src.stat()
        total_size = db_stat_before.st_size
        wal_stat_before = None
        if has_wal:
            wal_stat_before = wal_path.stat()
            total_size += wal_stat_before.st_size

        if total_size > max_bytes:
            raise ValueError(f"Selected SQLite database and WAL exceed combined {max_bytes}-byte budget: {src}")

        with src.open("rb") as f:
            db_bytes = f.read()
        db_sha256 = hashlib.sha256(db_bytes).hexdigest()
        with snapshot_path.open("wb") as f:
            f.write(db_bytes)

        wal_artifact = None
        if has_wal:
            with wal_path.open("rb") as f:
                wal_bytes = f.read()
            wal_sha256 = hashlib.sha256(wal_bytes).hexdigest()
            wal_snapshot_path = tgt_dir / "database.snapshot-wal"
            with wal_snapshot_path.open("wb") as f:
                f.write(wal_bytes)
            wal_artifact = SqliteArtifactInfo(
                path=str(wal_path),
                size_bytes=len(wal_bytes),
                sha256=wal_sha256,
            )

        # Integrity checks: ensure file did not mutate during read
        db_stat_after = src.stat()
        if db_stat_after.st_size != db_stat_before.st_size or db_stat_after.st_mtime_ns != db_stat_before.st_mtime_ns:
            raise OSError(f"SQLite database changed during acquisition: {src}")

        if has_wal and wal_stat_before is not None:
            wal_stat_after = wal_path.stat()
            if (
                wal_stat_after.st_size != wal_stat_before.st_size
                or wal_stat_after.st_mtime_ns != wal_stat_before.st_mtime_ns
            ):
                raise OSError(f"SQLite WAL changed during acquisition: {wal_path}")

        if has_journal:
            quiescent_after, reason_after = cls.verify_journal_quiescence(journal_path)
            if not quiescent_after:
                raise OSError(f"Rollback journal activated during acquisition: {reason_after}")

        db_artifact = SqliteArtifactInfo(
            path=str(src),
            size_bytes=len(db_bytes),
            sha256=db_sha256,
        )

        return SqliteSnapshotResult(
            snapshot_path=str(snapshot_path),
            database_artifact=db_artifact,
            wal_artifact=wal_artifact,
            journal_present=has_journal,
            journal_active=False,
        )

    @classmethod
    def connect_readonly(cls, uri: str) -> sqlite3.Connection:
        """Open a SQLite connection in read-only URI mode with hardened PRAGMAs."""
        conn = sqlite3.connect(uri, uri=True)
        try:
            conn.execute("PRAGMA trusted_schema = OFF;")
            conn.execute("PRAGMA query_only = ON;")
            conn.execute("PRAGMA mmap_size = 0;")
            conn.execute("PRAGMA cell_size_check = ON;")
        except sqlite3.OperationalError:
            pass
        return conn

    @classmethod
    def inspect_connection(
        cls,
        conn: sqlite3.Connection,
        database_path: str = "",
        artifact: SqliteArtifactInfo | None = None,
        wal_artifact: SqliteArtifactInfo | None = None,
    ) -> SqliteDatabaseInfo:
        """Extract full schema and metadata from an active read-only connection."""
        limitations: list[str] = []

        cur = conn.cursor()
        engine_version: str = cur.execute("SELECT sqlite_version()").fetchone()[0]

        enc_row = cur.execute("PRAGMA encoding").fetchone()
        database_encoding: str = enc_row[0] if enc_row else "UTF-8"

        # 1. Table inventory via PRAGMA main.table_list
        table_list_map: dict[str, tuple[str, str, str, int, int, int]] = {}
        try:
            for row in cur.execute("PRAGMA main.table_list"):
                # schema, name, type, ncol, wr, strict
                schema, name, tbl_type, ncol, wr, strict = (
                    row[0],
                    row[1],
                    row[2],
                    row[3],
                    row[4],
                    row[5],
                )
                if schema == "main":
                    table_list_map[name] = (schema, name, tbl_type, ncol, wr, strict)
        except sqlite3.OperationalError:
            pass

        # Identify unresolved virtual tables (ncol == 0)
        unresolved_virtual = [
            (name, f"{name.lower()}_")
            for name, (_, _, tbl_type, ncol, _, _) in table_list_map.items()
            if tbl_type == "virtual" and ncol == 0
        ]

        # 2. Query sqlite_schema (or sqlite_master fallback)
        schema_table = "sqlite_schema"
        try:
            cur.execute("SELECT 1 FROM main.sqlite_schema LIMIT 1")
        except sqlite3.OperationalError:
            schema_table = "sqlite_master"

        schema_items = cur.execute(f"SELECT type, name, tbl_name, rootpage, sql FROM main.{schema_table}").fetchall()

        # Build name case-folding lookup for table references (e.g., triggers)
        canonical_tables = {item[1].lower(): item[1] for item in schema_items if item[0] == "table"}

        tables: list[SqliteTable] = []
        indexes: list[SqliteIndex] = []
        views: list[SqliteView] = []
        triggers: list[SqliteTrigger] = []

        for item_type, name, tbl_name, rootpage, sql in schema_items:
            if item_type == "table":
                listed = table_list_map.get(name)
                tbl_type = listed[2] if listed else "table"
                without_rowid = bool(listed[4]) if listed else False
                strict = bool(listed[5]) if listed else False
                column_count = (
                    None if (listed and listed[2] == "virtual" and listed[3] == 0) else (listed[3] if listed else None)
                )

                # Shadow table detection
                is_shadow = False
                lower_name = name.lower()
                for parent_name, prefix in unresolved_virtual:
                    if lower_name.startswith(prefix):
                        is_shadow = True
                        limitations.append(
                            f"SQLite could not resolve virtual table {parent_name}. "
                            f"Table {name} may be its shadow table; row inspection is unavailable."
                        )
                        break

                kind = "unknown" if is_shadow else tbl_type

                columns: list[SqliteColumn] = []
                primary_keys: list[str] = []
                foreign_keys: list[SqliteForeignKey] = []

                if kind not in ("unknown", "virtual") or (listed and listed[3] > 0):
                    quoted = quote_identifier(name)

                    # Extract columns via table_xinfo
                    try:
                        xinfo_rows = cur.execute(f"PRAGMA main.table_xinfo({quoted})").fetchall()
                        for c_row in xinfo_rows:
                            columns.append(
                                SqliteColumn(
                                    cid=c_row[0],
                                    name=c_row[1],
                                    declared_type=c_row[2],
                                    not_null=bool(c_row[3]),
                                    default_sql=c_row[4],
                                    primary_key_position=c_row[5],
                                    hidden=c_row[6] if len(c_row) > 6 else 0,
                                )
                            )
                    except sqlite3.OperationalError:
                        try:
                            info_rows = cur.execute(f"PRAGMA main.table_info({quoted})").fetchall()
                            for c_row in info_rows:
                                columns.append(
                                    SqliteColumn(
                                        cid=c_row[0],
                                        name=c_row[1],
                                        declared_type=c_row[2],
                                        not_null=bool(c_row[3]),
                                        default_sql=c_row[4],
                                        primary_key_position=c_row[5],
                                        hidden=0,
                                    )
                                )
                        except sqlite3.OperationalError:
                            pass

                    # Primary key sequence
                    pk_ordered = sorted(
                        [c for c in columns if c.primary_key_position > 0],
                        key=lambda c: c.primary_key_position,
                    )
                    primary_keys = [c.name for c in pk_ordered]

                    # Foreign keys
                    try:
                        fk_rows = cur.execute(f"PRAGMA main.foreign_key_list({quoted})").fetchall()
                        for fk in fk_rows:
                            foreign_keys.append(
                                SqliteForeignKey(
                                    id=fk[0],
                                    seq=fk[1],
                                    target_table=fk[2],
                                    from_column=fk[3],
                                    to_column=fk[4],
                                    on_update=fk[5],
                                    on_delete=fk[6],
                                    match=fk[7] if len(fk) > 7 else "NONE",
                                )
                            )
                    except sqlite3.OperationalError:
                        pass

                tables.append(
                    SqliteTable(
                        name=name,
                        sql=sql,
                        root_page=rootpage or 0,
                        kind=kind,
                        without_rowid=without_rowid,
                        strict=strict,
                        column_count=column_count,
                        columns=tuple(columns),
                        primary_keys=tuple(primary_keys),
                        foreign_keys=tuple(foreign_keys),
                    )
                )

            elif item_type == "index":
                idx_quoted = quote_identifier(name)
                idx_cols: list[str] = []
                try:
                    for i_row in cur.execute(f"PRAGMA main.index_info({idx_quoted})"):
                        if i_row[2]:
                            idx_cols.append(i_row[2])
                except sqlite3.OperationalError:
                    pass

                # Check unique status
                unique = False
                try:
                    tbl_quoted = quote_identifier(tbl_name)
                    for l_row in cur.execute(f"PRAGMA main.index_list({tbl_quoted})"):
                        if l_row[1] == name:
                            unique = bool(l_row[2])
                            break
                except sqlite3.OperationalError:
                    pass

                indexes.append(
                    SqliteIndex(
                        name=name,
                        table=tbl_name,
                        sql=sql,
                        root_page=rootpage or 0,
                        unique=unique,
                        columns=tuple(idx_cols),
                    )
                )

            elif item_type == "view":
                views.append(SqliteView(name=name, sql=sql))

            elif item_type == "trigger":
                # Case-fold table target if matched
                target_table = canonical_tables.get(tbl_name.lower(), tbl_name)
                triggers.append(SqliteTrigger(name=name, table=target_table, sql=sql))

        return SqliteDatabaseInfo(
            database_path=database_path,
            engine_version=engine_version,
            database_encoding=database_encoding,
            artifact=artifact,
            wal_artifact=wal_artifact,
            tables=tuple(tables),
            indexes=tuple(indexes),
            views=tuple(views),
            triggers=tuple(triggers),
            limitations=tuple(limitations),
        )

    @classmethod
    def sample_table_rows(
        cls,
        conn: sqlite3.Connection,
        table_name: str,
        limit: int = DEFAULT_ROW_SAMPLE_LIMIT,
        columns: Sequence[str] | None = None,
    ) -> SqliteRowSample:
        """Sample committed rows from an ordinary table without triggering view/trigger side effects."""
        quoted_table = quote_identifier(table_name)
        cur = conn.cursor()

        # Discover columns and hidden status
        cols_meta: list[tuple[str, int]] = []
        try:
            for c_row in cur.execute(f"PRAGMA main.table_xinfo({quoted_table})"):
                cols_meta.append((c_row[1], c_row[6] if len(c_row) > 6 else 0))
        except sqlite3.OperationalError:
            for c_row in cur.execute(f"PRAGMA main.table_info({quoted_table})"):
                cols_meta.append((c_row[1], 0))

        if not cols_meta:
            raise ValueError(f"Table '{table_name}' does not exist or has no columns")

        visible_cols = [c[0] for c in cols_meta if c[1] != 1]
        target_cols = list(columns) if columns is not None else visible_cols

        all_names = {c[0] for c in cols_meta}
        for c in target_cols:
            if c not in all_names:
                raise ValueError(f"Selected column '{c}' does not exist in table '{table_name}'")

        if not target_cols:
            return SqliteRowSample(
                table=table_name,
                columns=(),
                rows=(),
                row_limit=limit,
                returned_rows=0,
                truncated=False,
            )

        col_clause = ", ".join(quote_identifier(c) for c in target_cols)
        query = f"SELECT {col_clause} FROM main.{quoted_table} NOT INDEXED LIMIT ?"

        cur.execute(query, (limit,))
        raw_rows = cur.fetchall()

        formatted_rows: list[dict[str, Any]] = []
        for raw in raw_rows:
            formatted_rows.append(
                {col_name: safe_cell_value(val) for col_name, val in zip(target_cols, raw, strict=False)}
            )

        trunc_cur = conn.cursor()
        trunc_cur.execute(f"SELECT 1 FROM main.{quoted_table} NOT INDEXED LIMIT 1 OFFSET ?", (limit,))
        truncated = trunc_cur.fetchone() is not None

        return SqliteRowSample(
            table=table_name,
            columns=tuple(target_cols),
            rows=tuple(formatted_rows),
            row_limit=limit,
            returned_rows=len(formatted_rows),
            truncated=truncated,
        )

    @classmethod
    def inspect_file(
        cls,
        path: str | Path,
        use_snapshot: bool = True,
        target_snapshot_dir: str | Path | None = None,
        sample_table: str | None = None,
        row_limit: int = DEFAULT_ROW_SAMPLE_LIMIT,
    ) -> SqliteDatabaseInfo:
        """Inspect an SQLite database safely.

        If use_snapshot=True, snapshots database and WAL into an isolated directory
        first, incorporating uncheckpointed committed WAL transactions cleanly without
        touching the source file. If use_snapshot=False, inspects in-place with
        immutable=1&mode=ro (zero locks, zero disk writes).
        """
        src = Path(path).resolve()
        if not src.is_file():
            raise FileNotFoundError(f"Database file not found: {src}")

        if use_snapshot:
            if target_snapshot_dir is not None:
                snap = cls.capture_snapshot(src, target_snapshot_dir)
                uri = build_readonly_uri(snap.snapshot_path, immutable=False)
                conn = cls.connect_readonly(uri)
                try:
                    info = cls.inspect_connection(
                        conn,
                        database_path=str(src),
                        artifact=snap.database_artifact,
                        wal_artifact=snap.wal_artifact,
                    )
                    if sample_table:
                        info.sampled_rows = cls.sample_table_rows(conn, sample_table, limit=row_limit)
                    return info
                finally:
                    conn.close()
            else:
                with tempfile.TemporaryDirectory(prefix="reforge-sqlite-") as tmpdir:
                    snap = cls.capture_snapshot(src, tmpdir)
                    uri = build_readonly_uri(snap.snapshot_path, immutable=False)
                    conn = cls.connect_readonly(uri)
                    try:
                        info = cls.inspect_connection(
                            conn,
                            database_path=str(src),
                            artifact=snap.database_artifact,
                            wal_artifact=snap.wal_artifact,
                        )
                        if sample_table:
                            info.sampled_rows = cls.sample_table_rows(conn, sample_table, limit=row_limit)
                        return info
                    finally:
                        conn.close()
        else:
            uri = build_readonly_uri(src, immutable=True)
            with src.open("rb") as f:
                src_bytes = f.read()
            db_artifact = SqliteArtifactInfo(
                path=str(src),
                size_bytes=len(src_bytes),
                sha256=hashlib.sha256(src_bytes).hexdigest(),
            )
            wal_path = src.with_name(src.name + "-wal")
            wal_artifact = None
            if wal_path.is_file() and not wal_path.is_symlink():
                with wal_path.open("rb") as f:
                    wal_bytes = f.read()
                wal_artifact = SqliteArtifactInfo(
                    path=str(wal_path),
                    size_bytes=len(wal_bytes),
                    sha256=hashlib.sha256(wal_bytes).hexdigest(),
                )
            conn = cls.connect_readonly(uri)
            try:
                info = cls.inspect_connection(
                    conn,
                    database_path=str(src),
                    artifact=db_artifact,
                    wal_artifact=wal_artifact,
                )
                if sample_table:
                    info.sampled_rows = cls.sample_table_rows(conn, sample_table, limit=row_limit)
                return info
            finally:
                conn.close()

    @classmethod
    def probe_file(cls, path: str | Path) -> SqliteDatabaseInfo | None:
        """Probe if file is SQLite; if so return schema inspection, else None."""
        if not cls.is_sqlite_database(path):
            return None
        try:
            return cls.inspect_file(path, use_snapshot=False)
        except Exception:
            return None
