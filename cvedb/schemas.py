"""Feed-scoped SQLite persistence for CVE records."""

from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from sqlite3 import Connection, ProgrammingError
from typing import TYPE_CHECKING, cast

from cvss import CVSS2, CVSS3, CVSSError

from cvedb.cpe import CPE, Testable
from cvedb.cve import CVE, Configurations, Description, Reference
from cvedb.feed import Data
from cvedb.dates import utc_datetime
from cvedb.search import (
    AbstractDateQuery,
    AndQuery,
    DescriptionQuery,
    AfterModifiedDateQuery,
    AfterPublishedDateQuery,
    BeforeModifiedDateQuery,
    BeforePublishedDateQuery,
    CompoundQuery,
    CPEQuery,
    EnvironmentQuery,
    OrQuery,
    SearchQuery,
    Sort,
    TermQuery,
    text_contains,
)
from cvedb.sql import And, Or, Select, SimpleQuery, TRUE

if TYPE_CHECKING:
    from cvedb.db import CVEdbData

CPE_COLUMNS = {
    "part": "part",
    "vendor": "vendor",
    "product": "product",
    "version": "version",
    "update": "update_str",
    "edition": "edition",
    "lang": "language",
    "sw_edition": "sw_edition",
    "target_sw": "target_sw",
    "target_hw": "target_hw",
    "other": "other",
}
_CPE_FIELDS = ", ".join(CPE_COLUMNS.values())
_CPE_VALUES = ", ".join("?" for _ in CPE_COLUMNS)
_CPE_LOOKUP = " AND ".join(f"{column} = ?" for column in CPE_COLUMNS.values())
_CHILD_FOREIGN_KEY = "FOREIGN KEY(cve, feed) REFERENCES cves(id, feed) ON DELETE CASCADE"
_TABLES = (
    "CREATE TABLE feeds(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, "
    "last_modified REAL, last_checked REAL)",
    "CREATE TABLE cves(id TEXT NOT NULL, feed INTEGER NOT NULL REFERENCES feeds(id), "
    "published REAL NOT NULL, last_modified REAL NOT NULL, impact_vector TEXT, "
    "base_score REAL, severity INTEGER NOT NULL, configurations TEXT NOT NULL, assigner TEXT, "
    "PRIMARY KEY(id, feed))",
    "CREATE TABLE descriptions(cve TEXT NOT NULL, feed INTEGER NOT NULL, "
    "position INTEGER NOT NULL, "
    "lang TEXT NOT NULL, description TEXT NOT NULL, PRIMARY KEY(cve, feed, position), "
    f"{_CHILD_FOREIGN_KEY})",
    "CREATE TABLE refs(cve TEXT NOT NULL, feed INTEGER NOT NULL, position INTEGER NOT NULL, "
    f"name TEXT, url TEXT, PRIMARY KEY(cve, feed, position), {_CHILD_FOREIGN_KEY})",
    "CREATE TABLE cpes(id INTEGER PRIMARY KEY, "
    + ", ".join(f"{column} TEXT NOT NULL" for column in CPE_COLUMNS.values())
    + f", UNIQUE({_CPE_FIELDS}))",
    "CREATE TABLE configurations(cpe INTEGER NOT NULL REFERENCES cpes(id), "
    f"cve TEXT NOT NULL, feed INTEGER NOT NULL, PRIMARY KEY(cve, feed, cpe), {_CHILD_FOREIGN_KEY})",
    "CREATE INDEX configurations_cpe ON configurations(cpe)",
)
CVERow = tuple[str, int, float, float, str | None, float | None, int, str, str | None]
_SORT_COLUMNS = {
    Sort.CVE_ID: "c.id",
    Sort.DESCRIPTION: (
        "COALESCE((SELECT description FROM descriptions "
        "WHERE cve=c.id AND feed=c.feed AND lang='en' ORDER BY position LIMIT 1), "
        "(SELECT description FROM descriptions WHERE cve=c.id AND feed=c.feed "
        "ORDER BY position LIMIT 1), '')"
    ),
    Sort.PUBLISHED_DATE: "c.published",
    Sort.LAST_MODIFIED_DATE: "c.last_modified",
    Sort.IMPACT: "c.base_score",
    Sort.SEVERITY: "c.severity",
}
_DATE_COLUMNS: dict[type[SearchQuery], tuple[str, str]] = {
    BeforePublishedDateQuery: ("c.published", "<="),
    BeforeModifiedDateQuery: ("c.last_modified", "<="),
    AfterPublishedDateQuery: ("c.published", ">="),
    AfterModifiedDateQuery: ("c.last_modified", ">="),
}


def _timestamp(value: datetime) -> float:
    return utc_datetime(value).timestamp()


def _sql_contains(value: str | None, query: str, case_sensitive: int) -> int:
    return int(text_contains(value, query, bool(case_sensitive)))


class UnsupportedQueryError(ValueError):
    """A query cannot be safely narrowed using the supported SQL predicates."""


def _enable_foreign_keys(connection: Connection) -> None:
    connection.execute("PRAGMA foreign_keys = ON")
    if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
        raise ValueError(
            "CVEdb requires foreign-key enforcement; finish the current transaction before "
            "opening or creating the database"
        )


def _impact(vector: str | None, cve_id: str) -> CVSS2 | CVSS3 | None:
    if vector is None:
        return None
    try:
        return CVSS3(vector)
    except CVSSError:
        try:
            return CVSS2(vector)
        except CVSSError as error:
            raise ValueError(
                f"Invalid stored CVSS vector for {cve_id}: {vector!r}; reimport this record"
            ) from error


class Schema:
    """The supported feed-aware database format.

    Version 2 replaces older formats whose child metadata cannot be assigned to
    feeds reliably. Older files are preserved and must be rebuilt separately.
    """

    version = 2

    def __init__(self, connection: Connection) -> None:
        self.connection = connection
        functions = connection.execute("PRAGMA function_list")
        try:
            signatures = functions.fetchall()
            columns = [column[0] for column in functions.description or ()]
        finally:
            functions.close()
        self._sql_search_available = bool(signatures)
        if not self._sql_search_available:
            return
        name, arity = columns.index("name"), columns.index("narg")
        if not any(row[name] == "cvedb_contains" and row[arity] == 3 for row in signatures):
            connection.create_function("cvedb_contains", 3, _sql_contains, deterministic=True)

    def path(self) -> str:
        """Return the connection's main database filename."""
        for _, name, filename in self.connection.execute("PRAGMA database_list"):
            if name == "main":
                return str(filename)
        raise ValueError("The SQLite connection has no main database")

    @staticmethod
    def latest() -> type["Schema"]:
        """Return the sole supported schema implementation."""
        return Schema

    @staticmethod
    def open(connection: Connection) -> "Schema":
        """Open the current schema or initialize a blank database.

        Raises:
            ValueError: An existing format requires a separate rebuild, is newer
                than supported, or cannot enforce foreign keys.
        """
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        tables = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        if not tables and version == 0:
            return Schema.create(connection)
        if version > Schema.version:
            raise ValueError(f"Database schema {version} is newer than supported version 2")
        if version != Schema.version:
            raise ValueError(
                f"Database schema {version} requires rebuilding at a separate database path. "
                "Keep the original file, create a new database, and reimport custom feeds; "
                "older records contain ambiguous or missing metadata"
            )
        _enable_foreign_keys(connection)
        return Schema(connection)

    @classmethod
    def create(cls, connection: Connection) -> "Schema":
        """Create schema version 2 without replacing any existing tables."""
        _enable_foreign_keys(connection)
        connection.execute("SAVEPOINT cvedb_schema")
        try:
            for statement in _TABLES:
                connection.execute(statement)
            connection.execute("PRAGMA user_version = 2")
        except BaseException:
            connection.execute("ROLLBACK TO cvedb_schema")
            connection.execute("RELEASE cvedb_schema")
            raise
        connection.execute("RELEASE cvedb_schema")
        return cls(connection)

    def feed_id(self, name: str) -> int:
        """Return the requested feed's identity regardless of previous inserts."""
        row = self.connection.execute("SELECT id FROM feeds WHERE name = ?", (name,)).fetchone()
        if row is not None:
            return int(row[0])
        self.connection.execute("INSERT OR IGNORE INTO feeds(name) VALUES (?)", (name,))
        row = self.connection.execute("SELECT id FROM feeds WHERE name = ?", (name,)).fetchone()
        if row is None:
            raise ValueError(f"Cannot resolve feed {name!r} after insertion")
        return int(row[0])

    def add(self, cve: CVE, source_feed: int) -> None:
        """Replace a feed's CVE and children atomically without committing the owner.

        The caller commits or rolls back the surrounding feed update. A failed
        child insertion restores the previous complete record even if the caller
        catches that error and continues its transaction.
        """
        if not self.connection.in_transaction:
            self.connection.execute("BEGIN")
        self.connection.execute("SAVEPOINT cvedb_record")
        try:
            self._replace_record(cve, source_feed)
        except BaseException:
            self.connection.execute("ROLLBACK TO cvedb_record")
            self.connection.execute("RELEASE cvedb_record")
            raise
        self.connection.execute("RELEASE cvedb_record")

    def _replace_record(self, cve: CVE, feed: int) -> None:
        key = (cve.cve_id, feed)
        removed = self.connection.execute(
            "SELECT cpe FROM configurations WHERE cve=? AND feed=?", key
        ).fetchall()
        self.connection.execute("DELETE FROM cves WHERE id=? AND feed=?", key)
        vector = None if cve.impact is None else cve.impact.vector
        score = (
            None
            if cve.impact is None or cve.impact.base_score is None
            else float(cve.impact.base_score)
        )
        self.connection.execute(
            "INSERT INTO cves VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                *key,
                _timestamp(cve.published_date),
                _timestamp(cve.last_modified_date),
                vector,
                score,
                int(cve.severity),
                cve.configurations.dumps(),
                cve.assigner,
            ),
        )
        self._add_children(cve, feed)
        for (cpe_id,) in removed:
            self.connection.execute(
                "DELETE FROM cpes WHERE id=? AND NOT EXISTS "
                "(SELECT 1 FROM configurations WHERE cpe=cpes.id)",
                (cpe_id,),
            )

    def _add_children(self, cve: CVE, feed: int) -> None:
        self.connection.executemany(
            "INSERT INTO descriptions VALUES (?, ?, ?, ?, ?)",
            (
                (cve.cve_id, feed, i, value.lang, value.value)
                for i, value in enumerate(cve.descriptions)
            ),
        )
        self.connection.executemany(
            "INSERT INTO refs VALUES (?, ?, ?, ?, ?)",
            (
                (cve.cve_id, feed, i, value.name, value.url)
                for i, value in enumerate(cve.references)
            ),
        )
        for criterion in cve.configurations.candidate_criteria():
            for cpe in criterion.vulnerable_cpes():
                cpe_id = self._cpe_id(cpe)
                self.connection.execute(
                    "INSERT OR IGNORE INTO configurations VALUES (?, ?, ?)",
                    (cpe_id, cve.cve_id, feed),
                )

    def _cpe_id(self, cpe: CPE) -> int:
        values = tuple(str(getattr(cpe, field)) for field in CPE_COLUMNS)
        self.connection.execute(
            f"INSERT OR IGNORE INTO cpes({_CPE_FIELDS}) VALUES ({_CPE_VALUES})", values
        )
        row = self.connection.execute(f"SELECT id FROM cpes WHERE {_CPE_LOOKUP}", values).fetchone()
        if row is None:
            raise ValueError(f"Cannot resolve indexed CPE after insertion: {cpe}")
        return int(row[0])

    def cve_iter(self, rows: Iterable[tuple[object, ...]]) -> Iterator[CVE]:
        """Hydrate feed-scoped records with their ordered metadata."""
        for row in rows:
            yield self._cve(cast(CVERow, row))

    def _cve(self, row: CVERow) -> CVE:
        cve_id, feed, published, modified, vector, _, _, serialized, assigner = row
        descriptions = self.connection.execute(
            "SELECT lang, description FROM descriptions WHERE cve=? AND feed=? ORDER BY position",
            (cve_id, feed),
        )
        references = self.connection.execute(
            "SELECT url, name FROM refs WHERE cve=? AND feed=? ORDER BY position", (cve_id, feed)
        )
        try:
            configurations = Testable.loads(serialized)
        except (ValueError, TypeError, KeyError, IndexError) as error:
            raise ValueError(
                f"Invalid stored configurations for {cve_id}; reimport this record"
            ) from error
        if not isinstance(configurations, Configurations):
            raise ValueError(f"Invalid stored configurations for {cve_id}; reimport this record")
        return CVE(
            cve_id=cve_id,
            published_date=datetime.fromtimestamp(published, timezone.utc),
            last_modified_date=datetime.fromtimestamp(modified, timezone.utc),
            impact=_impact(vector, cve_id),
            descriptions=tuple(Description(*d) for d in descriptions),
            references=tuple(Reference(*r) for r in references),
            assigner=assigner,
            configurations=configurations,
        )

    @classmethod
    def to_query(cls, query: SearchQuery) -> Select | None:
        """Prepare a conservative SQL predicate for supported queries."""
        if type(query) in (CPEQuery, EnvironmentQuery):
            return Select("", "", where=TRUE)
        if type(query) in (TermQuery, DescriptionQuery):
            return cls._text_query(cast(TermQuery, query))
        if isinstance(query, AbstractDateQuery) and type(query) in _DATE_COLUMNS:
            column, operator = _DATE_COLUMNS[type(query)]
            return Select(
                "", "", where=SimpleQuery(f"{column} {operator} ?"), params=[_timestamp(query.date)]
            )
        if type(query) in (AndQuery, OrQuery):
            return cls._compound_query(cast(CompoundQuery, query))
        return None

    @staticmethod
    def _text_query(query: TermQuery) -> Select:
        description = (
            "EXISTS (SELECT 1 FROM descriptions d WHERE d.cve=c.id AND d.feed=c.feed "
            "AND cvedb_contains(d.description, ?, ?))"
        )
        predicates = [description]
        if type(query) is TermQuery:
            predicates.extend(
                [
                    "cvedb_contains(c.id, ?, ?)",
                    "cvedb_contains(c.assigner, ?, ?)",
                    "EXISTS (SELECT 1 FROM refs r WHERE r.cve=c.id AND r.feed=c.feed "
                    "AND (cvedb_contains(r.name, ?, ?) OR cvedb_contains(r.url, ?, ?)))",
                ]
            )
        count = 1 if type(query) is DescriptionQuery else 5
        params: list[int | float | str | None] = [query.query, int(query.case_sensitive)] * count
        return Select("", "", where=SimpleQuery("(" + " OR ".join(predicates) + ")"), params=params)

    @classmethod
    def _compound_query(cls, query: CompoundQuery) -> Select | None:
        children = []
        params = []
        for child in query.sub_queries:
            converted = cls.to_query(child)
            if converted is None:
                return None
            children.append(converted.where if converted.where is not None else TRUE)
            params.extend(converted.params)
        combine = Or if isinstance(query, OrQuery) else And
        return Select("", "", where=combine(*children), params=params)

    def finalize_query(self, select: Select) -> None:
        """Select main records without introducing duplicate child rows."""
        select.columns = "c.*"
        select.from_tables = "cves c"

    def search(
        self,
        *queries: str | SearchQuery,
        db_data: "CVEdbData",
        sort: Iterable[Sort] = (Sort.CVE_ID,),
        ascending: bool = True,
    ) -> Iterator[CVE]:
        """Prepare SQL eagerly and return a lazy iterator of fully matched records.

        SQLite builds without function introspection use the in-memory query
        path without registering a function that cannot be inspected safely.

        Raises:
            UnsupportedQueryError: The query or SQLite build needs in-memory evaluation.
        """
        if not self._sql_search_available:
            raise UnsupportedQueryError(
                "This SQLite build lacks function introspection; evaluate the query in memory"
            )
        query = Data.make_query(*queries)
        select = self.to_query(query)
        if select is None:
            raise UnsupportedQueryError(f"Unsupported SQL query: {type(query).__name__}")
        feed_ids = [feed.feed_id for feed in db_data.feeds]
        feeds = SimpleQuery(f"c.feed IN ({', '.join('?' for _ in feed_ids)})")
        select.where = feeds if select.where is None else And(select.where, feeds)
        select.params.extend(feed_ids)
        direction = "ASC" if ascending else "DESC"
        sorts = tuple(sort)
        columns = [_SORT_COLUMNS[value] for value in sorts]
        if sorts and Sort.CVE_ID not in sorts:
            columns.append("c.id")
        select.order_by = ", ".join(f"{column} {direction}" for column in columns) or None
        self.finalize_query(select)
        return self._search_results(query, select)

    def _search_results(self, query: SearchQuery, select: Select) -> Iterator[CVE]:
        rows = self.connection.execute(select.to_sql(), select.params)
        try:
            for cve in self.cve_iter(rows):
                if query.matches(cve):
                    yield cve
        finally:
            try:
                rows.close()
            except ProgrammingError:
                try:
                    _ = self.connection.in_transaction
                except ProgrammingError:
                    pass  # A closed connection no longer permits explicit cursor cleanup.
                else:
                    raise
