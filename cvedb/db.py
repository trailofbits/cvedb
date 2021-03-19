from datetime import datetime, timezone
import itertools
from pathlib import Path
from sqlite3 import connect, Connection
from time import time
from typing import Iterable, Iterator, List, Optional, Sized, Union

from tqdm import tqdm

from .cve import CVE
from .feed import Data, DataSource, Feed, FEEDS, MAX_DATA_AGE_SECONDS
from .schemas import Schema
from .search import SearchQuery, Sort

DEFAULT_DB_PATH = Path.home() / ".config" / "cvedb" / "cvedb.sqlite"

UPDATE_INTERVAL_SECONDS: int = MAX_DATA_AGE_SECONDS


class CVEdbDataSource(DataSource):
    def __init__(self, source: Union["DbBackedFeed", "CVEdb"]):
        super().__init__(source.last_modified())
        self.connection: Connection = source.connection
        if isinstance(source, CVEdb):
            self.feeds: Iterable[DbBackedFeed] = source.feeds
        else:
            self.feeds = [source]

    def __iter__(self) -> Iterator[CVE]:
        c = self.connection.cursor()
        where_clause = " OR ".join(["feed = ?"] * len(self.feeds))
        params = tuple(feed.feed_id for feed in self.feeds)
        c.execute(f"SELECT * FROM cves WHERE {where_clause}", params)
        # The following assumes that all feeds have the same schema, which should always be true
        yield from self.feeds[0].schema.cve_iter(c.fetchall())


class DbBackedFeed(Feed):
    register = False

    def __init__(self, connection: Connection, parent: Feed):
        super().__init__(parent.name)
        self.parent: Feed = parent
        self.connection: Connection = connection
        with self.connection:
            self.schema: Schema = Schema.open(self.connection)
            self.feed_id: int = self.schema.feed_id(self.parent.name)

    def last_modified(self) -> Optional[datetime]:
        c = self.connection.cursor()
        c.execute("SELECT last_modified FROM feeds WHERE rowid = ?", (self.feed_id,))
        row = c.fetchone()
        if row is None or row[0] is None:
            return None
        return datetime.fromtimestamp(row[0], timezone.utc)

    def last_checked(self) -> Optional[datetime]:
        c = self.connection.cursor()
        c.execute("SELECT last_checked FROM feeds WHERE rowid = ?", (self.feed_id,))
        row = c.fetchone()
        if row is None or row[0] is None:
            return None
        return datetime.fromtimestamp(row[0], timezone.utc)

    def is_out_of_date(self) -> bool:
        last_checked = self.last_checked()
        if last_checked is not None and time() - last_checked.timestamp() < UPDATE_INTERVAL_SECONDS:
            # the data in the DB is new enough:
            return False
        else:
            out_of_date = super().is_out_of_date()
            with self.connection as c:
                c.execute(
                    "UPDATE feeds SET last_checked = ? WHERE rowid = ?",
                    (datetime.fromtimestamp(time()).astimezone().timestamp(), self.feed_id)
                )
            return out_of_date

    def reload(self, existing_data: Optional[Data] = None, force: bool = False) -> DataSource:
        if not force and existing_data is not None and not self.is_out_of_date():
            return existing_data
        with tqdm(desc=self.name, unit=" CVEs", leave=False) as t:
            if existing_data is not None:
                existing_modified_time = existing_data.last_modified_date
            else:
                existing_modified_time = None
            new_data = self.parent.reload(existing_data)
            if new_data is existing_data:
                return new_data
            if isinstance(new_data, Sized):
                t.total = len(new_data)
            with self.connection as c:
                c.execute(
                    "UPDATE feeds SET last_checked = ? WHERE rowid = ?",
                    (datetime.fromtimestamp(time()).astimezone().timestamp(), self.feed_id)
                )
                if existing_modified_time is None or new_data.last_modified_date != existing_modified_time:
                    c.execute(
                        "UPDATE feeds SET last_modified = ? WHERE rowid = ?",
                        (new_data.last_modified_date.astimezone().timestamp(), self.feed_id)
                    )
                    for cve in new_data:
                        self.schema.add(cve, self.feed_id)
                        t.update(1)
                c.commit()
        return CVEdbDataSource(self)

    def data(self, force_reload: bool = False) -> "CVEdbData":
        if force_reload:
            self.reload()
        return CVEdbData(self)


class CVEdbContext:
    def __init__(self, db_path: Union[str, Path], parents: Optional[Iterable[Feed]] = None):
        if not isinstance(db_path, Path):
            db_path = Path(str(db_path))
        self.db_path: Path = db_path
        self.parents: Optional[Iterable[Feed]] = parents
        self._connection: Optional[Connection] = None
        self._db: Optional[CVEdb] = None
        self._entries: int = 0

    def __enter__(self) -> "CVEdb":
        self._entries += 1
        if self._db is not None:
            assert self._connection is not None
            assert self._entries > 1
            return self._db
        db_dir = self.db_path.parent
        if not db_dir.exists():
            db_dir.mkdir(parents=True, exist_ok=True)
        self._connection = connect(str(self.db_path))
        self._connection.__enter__()
        return CVEdb(self._connection, self.parents)

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._entries -= 1
        if self._entries == 0:
            self._connection.__exit__(exc_type, exc_val, exc_tb)
            self._connection = None
            self._db = None


class CVEdbData(Data):
    def __init__(self, source: Union["CVEdb", DbBackedFeed]):
        super().__init__(source.last_modified())
        self.connection: Connection = source.connection
        if isinstance(source, CVEdb):
            self.feeds: Iterable[DbBackedFeed] = source.feeds
        else:
            self.feeds = [source]

    @property
    def schema(self) -> Schema:
        # The following assumes that all feeds have the same schema, which should always be true
        return self.feeds[0].schema

    def __iter__(self) -> Iterator[CVE]:
        self.reload()
        return itertools.chain(*(iter(CVEdbDataSource(feed)) for feed in self.feeds))

    def __len__(self):
        self.reload()
        c = self.connection.cursor()
        c.execute("SELECT COUNT(*) FROM cves")
        return c.fetchone()[0]

    def search(
            self,
            *queries: Union[str, SearchQuery],
            sort: Iterable[Sort] = (Sort.CVE_ID,),
            ascending: bool = True
    ) -> Iterator[CVE]:
        self.reload()
        try:
            return self.schema.search(*queries, sort=sort, ascending=ascending, db_data=self)
        except ValueError:
            pass
        return super().search(*queries, sort=sort, ascending=ascending)

    def reload(self):
        out_of_date_feeds = [feed for feed in self.feeds if feed.is_out_of_date()]
        for feed in tqdm(out_of_date_feeds, desc="updating", unit=" feeds", leave=False):
            feed.reload(feed.data(), force=True)


class CVEdb(Feed):
    register = False

    def __init__(self, connection: Connection, parents: Optional[Iterable[Feed]] = None):
        super().__init__("cves")
        if parents is None:
            parents = FEEDS.values()
        self.feeds: List[DbBackedFeed] = [DbBackedFeed(connection, parent) for parent in parents]
        self.connection: Connection = connection

    def last_modified(self) -> Optional[datetime]:
        newest = None
        for parent in self.feeds:
            parent_modified = parent.last_modified()
            if parent_modified is not None and (newest is None or parent_modified > newest):
                newest = parent_modified
        return newest

    def data(self, force_reload: bool = False) -> CVEdbData:
        return CVEdbData(self)

    def reload(self, existing_data: Optional[Data] = None, force: bool = False) -> CVEdbDataSource:
        return CVEdbDataSource(self)

    @staticmethod
    def open(db_path: Union[str, Path] = DEFAULT_DB_PATH, parents: Optional[Iterable[Feed]] = None) -> CVEdbContext:
        return CVEdbContext(db_path, parents)
