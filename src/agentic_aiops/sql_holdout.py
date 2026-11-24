"""Synthetic/disposable SQLite holdout evaluation; never a production SQL executor."""
from __future__ import annotations

import math
import re
import sqlite3
from typing import Any

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
_CASE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}\Z")
_TYPES = {"INTEGER", "REAL", "TEXT"}
_FUNCTIONS = {"count", "sum", "avg", "min", "max", "lower", "upper", "length", "abs", "round", "coalesce"}
_MAX_ROWS = 256


def _ident(value: Any) -> str:
    if type(value) is not str or not _IDENT.fullmatch(value):
        raise ValueError("invalid SQL identifier")
    return value


def _value(value: Any) -> bool:
    return (value is None or type(value) is int and abs(value) <= 2**53
            or type(value) is float and math.isfinite(value)
            or type(value) is str and len(value) <= 1024 and "\x00" not in value)


def _rows(value: Any, width: int, limit: int) -> list[list]:
    if (type(value) is not list or len(value) > limit
            or any(type(row) is not list or len(row) != width
                   or any(not _value(cell) for cell in row) for row in value)):
        raise ValueError("invalid bounded SQL rows")
    return value


def _fixture(value: Any):
    if (type(value) is not dict or set(value) != {
        "schema_version", "case_id", "tables", "expected_rows"} or
            value["schema_version"] != "sre.sql.holdout-case/v1"):
        raise ValueError("invalid SQL holdout fixture")
    case_id = value["case_id"]
    if type(case_id) is not str or not _CASE_ID.fullmatch(case_id):
        raise ValueError("invalid case_id")
    tables = value["tables"]
    if type(tables) is not list or not 1 <= len(tables) <= 4:
        raise ValueError("invalid table count")
    allowed = {}
    for table in tables:
        if type(table) is not dict or set(table) != {"name", "columns", "rows"}:
            raise ValueError("invalid table fixture")
        name = _ident(table["name"])
        if name.casefold() in allowed or name.casefold().startswith("sqlite_"):
            raise ValueError("duplicate or reserved table")
        columns = table["columns"]
        if type(columns) is not list or not 1 <= len(columns) <= 12:
            raise ValueError("invalid columns")
        names = set()
        for column in columns:
            if (type(column) is not dict or set(column) != {"name", "type"}
                    or type(column["type"]) is not str or column["type"] not in _TYPES):
                raise ValueError("invalid column specification")
            col_name = _ident(column["name"])
            if col_name.casefold() in names:
                raise ValueError("duplicate column")
            names.add(col_name.casefold())
        _rows(table["rows"], len(columns), 128)
        allowed[name.casefold()] = names
    expected = value["expected_rows"]
    if (type(expected) is not list or len(expected) > _MAX_ROWS
            or any(type(row) is not list or not 1 <= len(row) <= 12
                   or any(not _value(cell) for cell in row) for row in expected)):
        raise ValueError("invalid expected SQL results")
    if expected and len({len(row) for row in expected}) != 1:
        raise ValueError("inconsistent expected row widths")
    return case_id, tables, allowed, expected


def _same_rows(left, right):
    return (len(left) == len(right) and all(
        len(a) == len(b) and all(type(x) is type(y) and x == y for x, y in zip(a, b))
        for a, b in zip(left, right)))


def evaluate_sql_case(fixture: Any, candidate: Any) -> dict[str, Any]:
    """Use a fresh in-memory DB with a fail-closed SELECT/READ authorizer.

    Client-supplied fixture and expected result remain untrusted until an
    independent data-owner pins and approves their bytes. This evaluator
    never authenticates model identity or grants execution/routing authority.
    """
    case_id, tables, allowed, expected = _fixture(fixture)
    if type(candidate) is not str or not 0 < len(candidate) <= 4096 or "\x00" in candidate:
        raise ValueError("invalid candidate query")
    report = {
        "schema_version": "sre.sql.evaluation/v1", "case_id": case_id,
        "execution_status": "REJECTED", "exact_result_match": False,
        "admission": "HOLD", "data_issuer_authenticated": False,
        "model_attribution_verified": False, "routing_authorized": False,
        "production_eligible": False,
    }
    query = candidate.strip()
    if not re.match(r"(?:SELECT|WITH)\b", query, flags=re.IGNORECASE):
        return report
    conn = sqlite3.connect(":memory:")
    try:
        for table in tables:
            name = table["name"]
            coldefs = ",".join('"' + col["name"] + '" ' + col["type"]
                               for col in table["columns"])
            conn.execute('CREATE TABLE "' + name + '" (' + coldefs + ')')
            if table["rows"]:
                params = ",".join("?" for _ in table["columns"])
                conn.executemany('INSERT INTO "' + name + '" VALUES (' + params + ')', table["rows"])
        conn.execute("PRAGMA query_only=ON")
        if not hasattr(conn, "setlimit"):
            return report
        # Bound intermediate SQLite strings/blobs and encoded rows, not only
        # final Python result cells. The opcode budget alone cannot do this.
        conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 64 * 1024)
        conn.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 4096)
        conn.setlimit(sqlite3.SQLITE_LIMIT_EXPR_DEPTH, 64)
        conn.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, 12)
        def authorizer(action, arg1, arg2, _db_name, _source):
            if action == sqlite3.SQLITE_SELECT:
                return sqlite3.SQLITE_OK
            if action == sqlite3.SQLITE_READ and isinstance(arg1, str):
                if arg1.casefold() in allowed and (not arg2 or arg2.casefold() in allowed[arg1.casefold()]):
                    return sqlite3.SQLITE_OK
            if action == sqlite3.SQLITE_FUNCTION and isinstance(arg2, str) and arg2.casefold() in _FUNCTIONS:
                return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY
        conn.set_authorizer(authorizer)
        budget = [0]
        def progress():
            budget[0] += 1
            return 1 if budget[0] > 5000 else 0
        conn.set_progress_handler(progress, 100)
        try:
            cursor = conn.execute(query)
            if cursor.description is None or not 1 <= len(cursor.description) <= 12:
                return report
            rows = cursor.fetchmany(_MAX_ROWS + 1)
            if len(rows) > _MAX_ROWS or any(not _value(cell) for row in rows for cell in row):
                return report
            report["execution_status"] = "COMPLETED"
            report["exact_result_match"] = _same_rows(rows, expected)
            return report
        except (sqlite3.Error, OverflowError, ValueError):
            return report
    finally:
        conn.close()
