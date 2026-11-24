"""Synthetic/disposable SQLite holdout evaluation; never a production SQL executor."""
from __future__ import annotations

import json
import math
import re
import sqlite3
from typing import Any

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
_CASE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}\Z")
_TYPES = {"INTEGER", "REAL", "TEXT"}
_FUNCTIONS = {"count", "sum", "avg", "min", "max", "lower", "upper", "length", "abs", "round", "coalesce"}
_MAX_ROWS = 256
_MAX_RESULT_BYTES = 1024 * 1024
_SURROGATE = re.compile(r"[\ud800-\udfff]")


def _ident(value: Any) -> str:
    if type(value) is not str or not _IDENT.fullmatch(value):
        raise ValueError("invalid SQL identifier")
    return value


def _value(value: Any) -> bool:
    return (value is None or type(value) is int and abs(value) <= 2**53
            or type(value) is float and math.isfinite(value)
            or type(value) is str and len(value) <= 1024 and "\x00" not in value
            and _SURROGATE.search(value) is None)


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
        rows = _rows(table["rows"], len(columns), 128)
        # Do not let SQLite affinity silently rewrite the pinned fixture.
        cell_types = {"INTEGER": int, "REAL": float, "TEXT": str}
        for row in rows:
            for cell, column in zip(row, columns):
                if cell is not None and type(cell) is not cell_types[column["type"]]:
                    raise ValueError("invalid fixture cell type")
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


def _sql_tokens(query: str):
    """Tokenize enough SQL syntax to identify CTE declarations safely.

    String literals and comments are opaque tokens, so a word such as WITH
    inside data cannot be mistaken for a nested CTE declaration.
    """
    tokens = []
    index = 0
    while index < len(query):
        char = query[index]
        if char.isspace():
            index += 1
            continue
        if query.startswith("--", index):
            end = query.find("\n", index + 2)
            index = len(query) if end < 0 else end + 1
            continue
        if query.startswith("/*", index):
            end = query.find("*/", index + 2)
            if end < 0:
                raise ValueError("unterminated SQL comment")
            index = end + 2
            continue
        if char in ("'", '"', chr(96)):
            quote = char
            index += 1
            value = []
            while index < len(query):
                if query[index] == quote:
                    if index + 1 < len(query) and query[index + 1] == quote:
                        value.append(quote)
                        index += 2
                        continue
                    index += 1
                    break
                value.append(query[index])
                index += 1
            else:
                raise ValueError("unterminated SQL quote")
            tokens.append(("quoted", "".join(value)))
            continue
        if char == "[":
            index += 1
            value = []
            while index < len(query):
                if query[index] == "]":
                    if index + 1 < len(query) and query[index + 1] == "]":
                        value.append("]")
                        index += 2
                        continue
                    index += 1
                    break
                value.append(query[index])
                index += 1
            else:
                raise ValueError("unterminated SQL identifier")
            tokens.append(("quoted", "".join(value)))
            continue
        if char.isascii() and (char.isalpha() or char == "_"):
            end = index + 1
            while (end < len(query) and query[end].isascii()
                   and (query[end].isalnum() or query[end] in "_$")):
                end += 1
            tokens.append(("word", query[index:end]))
            index = end
            continue
        if char in "(),":
            tokens.append(("punct", char))
        else:
            tokens.append(("other", char))
        index += 1
    return tokens


def _skip_sql_parentheses(tokens, index):
    if index >= len(tokens) or tokens[index] != ("punct", "("):
        raise ValueError("expected SQL parenthesis")
    depth = 0
    while index < len(tokens):
        if tokens[index] == ("punct", "("):
            depth += 1
        elif tokens[index] == ("punct", ")"):
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    raise ValueError("unbalanced SQL parentheses")


def _is_sql_word(tokens, index, word):
    return (index < len(tokens) and tokens[index][0] == "word"
            and tokens[index][1].upper() == word)


def _cte_names(query):
    """Return every CTE name, including nested WITH clauses.

    SQLite's authorizer emits SQLITE_READ for a CTE that shadows a real table,
    so the callback alone cannot prove that the fixture table was read.
    """
    tokens = _sql_tokens(query)
    names = set()
    for start, token in enumerate(tokens):
        if token[0] != "word" or token[1].upper() != "WITH":
            continue
        index = start + 1
        if _is_sql_word(tokens, index, "RECURSIVE"):
            index += 1
        while True:
            if index >= len(tokens) or tokens[index][0] not in ("word", "quoted"):
                raise ValueError("invalid SQL CTE name")
            names.add(tokens[index][1].casefold())
            index += 1
            if index < len(tokens) and tokens[index] == ("punct", "("):
                index = _skip_sql_parentheses(tokens, index)
            if not _is_sql_word(tokens, index, "AS"):
                raise ValueError("invalid SQL CTE declaration")
            index += 1
            if (_is_sql_word(tokens, index, "NOT")
                    and _is_sql_word(tokens, index + 1, "MATERIALIZED")):
                index += 2
            elif _is_sql_word(tokens, index, "MATERIALIZED"):
                index += 1
            index = _skip_sql_parentheses(tokens, index)
            if index < len(tokens) and tokens[index] == ("punct", ","):
                index += 1
                continue
            break
    return names


def evaluate_sql_case(fixture: Any, candidate: Any) -> dict[str, Any]:
    """Use a fresh in-memory DB with a fail-closed SELECT/READ authorizer.

    Client-supplied fixture and expected result remain untrusted until an
    independent data-owner pins and approves their bytes. This evaluator
    never authenticates model identity or grants execution/routing authority.
    """
    case_id, tables, allowed, expected = _fixture(fixture)
    if (type(candidate) is not str or not 0 < len(candidate) <= 4096
            or "\x00" in candidate or _SURROGATE.search(candidate) is not None):
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
    try:
        # A CTE can shadow an allowed fixture table and fool SQLite's
        # SQLITE_READ authorizer callback into reporting a false dependency.
        if _cte_names(query).intersection(allowed):
            return report
    except ValueError:
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
        read_dependencies = [0]
        def authorizer(action, arg1, arg2, _db_name, _source):
            if action == sqlite3.SQLITE_SELECT:
                return sqlite3.SQLITE_OK
            if action == sqlite3.SQLITE_READ and isinstance(arg1, str):
                if arg1.casefold() in allowed and (not arg2 or arg2.casefold() in allowed[arg1.casefold()]):
                    read_dependencies[0] += 1
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
            # A literal-only SELECT can coincidentally equal the private Oracle.
            # Require an allowed table READ dependency before scoring results.
            # This is syntactic dependency, not proof of semantic causal use.
            if not read_dependencies[0]:
                return report
            # Fetch one row at a time and cap the serialized result payload.
            # fetchmany(257) can materialize ~192 MiB (256 * 12 * 64 KiB)
            # before the per-cell checks reject oversized values.
            rows = []
            result_bytes = 0
            while len(rows) <= _MAX_ROWS:
                row = cursor.fetchone()
                if row is None:
                    break
                if any(not _value(cell) for cell in row):
                    return report
                try:
                    row_bytes = len(json.dumps(
                        row, ensure_ascii=False, separators=(",", ":"),
                    ).encode("utf-8")) + 1
                except (TypeError, UnicodeError):
                    return report
                if result_bytes + row_bytes > _MAX_RESULT_BYTES:
                    return report
                result_bytes += row_bytes
                rows.append(row)
            if len(rows) > _MAX_ROWS:
                return report
            report["execution_status"] = "COMPLETED"
            report["exact_result_match"] = _same_rows(rows, expected)
            return report
        except (sqlite3.Error, OverflowError, ValueError):
            return report
    finally:
        conn.close()
