"""Database-backed views, explicit refreshes, and owned SQLite contexts."""

from collections.abc import Generator, Iterable, Iterator
from contextlib import contextmanager
from datetime import datetime, UTC
from pathlib import Path
from sqlite3 import connect, Connection, ProgrammingError
import sys
from time import time
from types import TracebackType

from tqdm import tqdm

from cvedb.cve import CVE
from cvedb.dates import utc_datetime
from cvedb.feed import Data, DataSource, Feed, FEEDS, MAX_DATA_AGE_SECONDS
from cvedb.schemas import Schema, UnsupportedQueryError
from cvedb.search import SearchQuery, Sort

DEFAULT_DB_PATH = Path.home() / ".config" / "cvedb" / "cvedb.sqlite"
UPDATE_INTERVAL_SECONDS: int = MAX_DATA_AGE_SECONDS


@contextmanager
def _savepoint(connection: Connection, name: str) -> Generator[None, None, None]:
    connection.execute(f"SAVEPOINT {name}")
    try:
        yield
        connection.execute(f"RELEASE {name}")
    except BaseException:
        if connection.in_transaction:
            connection.execute(f"ROLLBACK TO {name}")
            connection.execute(f"RELEASE {name}")
        raise


class CVEdbDataSource(Data):
    """A non-owning view of persisted records that never initializes or updates feeds.

    The timestamp describes persisted data when the view is created; it is None
    when no source timestamp is known. Use this view while its connection is open.
    """

    def __init__(self, source: "DbBackedFeed | CVEdb") -> None:
        super().__init__(source.last_modified())
        self._source = source
        self.connection = source.connection
        self.schema = source.schema
        self.feeds = source.feeds if isinstance(source, CVEdb) else [source]

    def __iter__(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
        self,
    ) -> Iterator[CVE]:
        if not self.feeds:
            return
        placeholders = ", ".join("?" for _ in self.feeds)
        rows = self.connection.execute(
            f"SELECT * FROM cves WHERE feed IN ({placeholders})",
            tuple(feed.feed_id for feed in self.feeds),
        )
        try:
            yield from self.schema.cve_iter(rows)
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

    def __len__(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
        self,
    ) -> int:
        if not self.feeds:
            return 0
        placeholders = ", ".join("?" for _ in self.feeds)
        row = self.connection.execute(
            f"SELECT COUNT(*) FROM cves WHERE feed IN ({placeholders})",
            tuple(feed.feed_id for feed in self.feeds),
        ).fetchone()
        return int(row[0])


class DbBackedFeed(Feed):
    register = False

    def __init__(
        self, connection: Connection, parent: Feed, *, schema: Schema | None = None
    ) -> None:
        super().__init__(parent.name)
        self.parent = parent
        self.connection = connection
        self.schema = Schema.open(connection) if schema is None else schema
        self.feed_id = self.schema.feed_id(parent.name)
        self._initial_loaded = False

    def last_modified(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
        self,
    ) -> datetime | None:
        return self._date("last_modified")

    def last_checked(self) -> datetime | None:
        """Return the last successful explicit upstream check, or None."""
        return self._date("last_checked")

    def _date(self, column: str) -> datetime | None:
        row = self.connection.execute(
            f"SELECT {column} FROM feeds WHERE id = ?", (self.feed_id,)
        ).fetchone()
        return None if row is None or row[0] is None else datetime.fromtimestamp(row[0], UTC)

    def is_out_of_date(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
        self,
    ) -> bool:
        """Read whether another upstream check is due without changing metadata."""
        checked = self.last_checked()
        return checked is None or time() - checked.timestamp() >= UPDATE_INTERVAL_SECONDS

    def _load_initial(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
        self,
    ) -> CVEdbDataSource:
        if not self._initial_loaded:
            has_records = self.connection.execute(
                "SELECT 1 FROM cves WHERE feed=? LIMIT 1", (self.feed_id,)
            ).fetchone()
            known = self.last_modified() is not None or self.last_checked() is not None
            if not known and has_records is None:
                source = self.parent._load_initial()
                if source is not None:
                    self._persist(source)
            self._initial_loaded = True
        return CVEdbDataSource(self)

    def _persist(self, source: DataSource) -> None:
        modified = source.last_modified_date
        with _savepoint(self.connection, "cvedb_feed_records"):
            with tqdm(
                desc=self.name, unit=" CVEs", leave=False, disable=not sys.stderr.isatty()
            ) as t:
                for cve in source:
                    if modified is None:
                        raise ValueError(
                            f"Cannot initialize feed {self.name!r}: records need a timestamp"
                        )
                    self.schema.add(cve, self.feed_id)
                    t.update(1)
            if modified is not None:
                self.connection.execute(
                    "UPDATE feeds SET last_modified=? WHERE id=?",
                    (utc_datetime(modified).timestamp(), self.feed_id),
                )

    def _mark_checked(self, checked_at: float) -> None:
        self.connection.execute(
            "UPDATE feeds SET last_checked=? WHERE id=?", (checked_at, self.feed_id)
        )

    def reload(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
        self, existing_data: Data | None = None, force: bool = False
    ) -> CVEdbDataSource:
        """Refresh upstream data when due, or unconditionally when force is True.

        Persisted records are the authoritative existing-data view. A genuinely
        new source is ingested even if its timestamp is unchanged. Returning the
        existing-data object explicitly confirms an unchanged upstream response.

        Raises:
            TypeError: The upstream feed does not return a data source.
            ValueError: A new upstream source has no last-modified timestamp.
        """
        if not force and not self.is_out_of_date():
            return CVEdbDataSource(self)
        existing_data = None if self.last_modified() is None else CVEdbDataSource(self)
        source = self.parent.reload(existing_data)
        if not isinstance(source, DataSource):
            raise TypeError(f"Cannot reload feed {self.name!r}: upstream must return a DataSource")
        unchanged = existing_data is not None and source is existing_data
        if not unchanged and source.last_modified_date is None:
            raise ValueError(
                f"Cannot reload feed {self.name!r}: the upstream source has no last-modified "
                "timestamp; provide a timestamp before retrying"
            )
        with _savepoint(self.connection, "cvedb_feed_update"):
            if not unchanged:
                self._persist(source)
            self._mark_checked(time())
        return CVEdbDataSource(self)

    def data(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
        self, force_reload: bool = False
    ) -> "CVEdbData":
        """Return a lazy persisted view; force_reload explicitly refreshes upstream."""
        if force_reload:
            self.reload(force=True)
        return CVEdbData(self)


class CVEdbContext:
    """Own one connection and transaction across nested entries.

    Any nested exception makes the whole outer transaction rollback-only, even
    if the caller catches that exception before the outer context exits.
    """

    def __init__(self, db_path: str | Path, parents: Iterable[Feed] | None = None) -> None:
        self.db_path = Path(db_path)
        self.parents = None if parents is None else tuple(parents)
        self._connection: Connection | None = None
        self._db: CVEdb | None = None
        self._entries = 0
        self._rollback_only = False

    def __enter__(self) -> "CVEdb":
        if self._db is not None:
            self._entries += 1
            return self._db
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        connection = connect(str(self.db_path))
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("BEGIN")
            database = CVEdb(connection, self.parents)
        except BaseException:
            try:
                connection.close()
            finally:
                self._reset()
            raise
        self._connection = connection
        self._db = database
        self._entries = 1
        return database

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        connection = self._connection
        if connection is None or self._entries == 0:
            raise RuntimeError("Cannot exit a CVEdb context that has not been entered")
        self._rollback_only = self._rollback_only or exc_type is not None
        self._entries -= 1
        if self._entries:
            return
        try:
            if self._rollback_only:
                connection.rollback()
            else:
                try:
                    connection.commit()
                except BaseException:
                    connection.rollback()
                    raise
        finally:
            try:
                connection.close()
            finally:
                self._reset()

    def _reset(self) -> None:
        self._connection = None
        self._db = None
        self._entries = 0
        self._rollback_only = False


class CVEdbData(CVEdbDataSource):
    """A persisted view that initializes local data lazily and uses SQL searches."""

    def _ensure_initial(self) -> None:
        self.last_modified_date = self._source._load_initial().last_modified_date

    def __iter__(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
        self,
    ) -> Iterator[CVE]:
        self._ensure_initial()
        return super().__iter__()

    def __len__(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
        self,
    ) -> int:
        self._ensure_initial()
        return super().__len__()

    def search(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
        self,
        *queries: str | SearchQuery,
        sort: Iterable[Sort] = (Sort.CVE_ID,),
        ascending: bool = True,
    ) -> Iterator[CVE]:
        """Prepare SQL eagerly, retaining lazy results and custom-query fallback."""
        self._ensure_initial()
        if not self.feeds:
            return iter(())
        sorts = tuple(sort)
        try:
            return self.schema.search(*queries, sort=sorts, ascending=ascending, db_data=self)
        except UnsupportedQueryError:
            return super().search(*queries, sort=sorts, ascending=ascending)

    def reload(self, force: bool = False) -> CVEdbDataSource:
        """Explicitly check upstream feeds and refresh this view's timestamp."""
        source = self._source.reload(force=force)
        self.last_modified_date = source.last_modified_date
        return source


class CVEdb(Feed):
    register = False

    def __init__(self, connection: Connection, parents: Iterable[Feed] | None = None) -> None:
        super().__init__("cves")
        self.connection = connection
        self.schema = Schema.open(connection)
        parents = FEEDS.values() if parents is None else parents
        self.feeds = [DbBackedFeed(connection, parent, schema=self.schema) for parent in parents]

    def last_modified(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
        self,
    ) -> datetime | None:
        """Return the newest known persisted feed timestamp, or None."""
        dates = [feed.last_modified() for feed in self.feeds]
        return max((value for value in dates if value is not None), default=None)

    def _load_initial(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
        self,
    ) -> CVEdbDataSource:
        for feed in self.feeds:
            feed._load_initial()
        return CVEdbDataSource(self)

    def data(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
        self, force_reload: bool = False
    ) -> CVEdbData:
        """Return a lazy local view; force_reload explicitly checks every upstream feed."""
        if force_reload:
            self.reload(force=True)
        return CVEdbData(self)

    def reload(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
        self, existing_data: Data | None = None, force: bool = False
    ) -> CVEdbDataSource:
        """Atomically refresh due feeds, bypassing throttling when force is True.

        This explicit update may use the network. Ordinary data views initialize
        installed data without checking built-in NVD feeds upstream. The return
        value is a non-owning persisted view, valid while this connection is open.
        A surrounding transaction retains ownership of commit or rollback.
        """
        feeds = [feed for feed in self.feeds if force or feed.is_out_of_date()]
        if feeds:
            with _savepoint(self.connection, "cvedb_database_update"):
                with tqdm(
                    total=len(feeds),
                    desc="updating",
                    unit=" feeds",
                    leave=False,
                    disable=not sys.stderr.isatty(),
                ) as progress:
                    for feed in feeds:
                        feed.reload(force=force)
                        progress.update(1)
        return CVEdbDataSource(self)

    @staticmethod
    def open(
        db_path: str | Path = DEFAULT_DB_PATH, parents: Iterable[Feed] | None = None
    ) -> CVEdbContext:
        """Open an owned connection whose outermost context commits or rolls back and closes."""
        return CVEdbContext(db_path, parents)
