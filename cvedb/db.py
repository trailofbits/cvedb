from datetime import datetime, timezone
import itertools
from pathlib import Path
from sqlite3 import connect, Connection
from time import time
from typing import Iterable, Iterator, List, Optional, Tuple, Union

from tqdm import tqdm

from .cve import CVE
from .feed import Data, DataSource, Feed, FEEDS, MAX_DATA_AGE_SECONDS
from .schemas import Schema
from .search import (
    AfterModifiedDateQuery, AfterPublishedDateQuery, BeforeModifiedDateQuery, BeforePublishedDateQuery, CompoundQuery,
    OrQuery, SearchQuery, Sort, TermQuery
)

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
            return super().is_out_of_date()

    def reload(self, existing_data: Optional[Data] = None) -> DataSource:
        if existing_data is not None and not self.is_out_of_date():
            return existing_data
        with tqdm(desc=self.name, unit=" CVEs", leave=False) as t:
            new_data = self.parent.reload(existing_data)
            with self.connection as c:
                c.execute(
                    "UPDATE feeds SET last_checked = ? WHERE rowid = ?",
                    (datetime.fromtimestamp(time()).astimezone().timestamp(), self.feed_id)
                )
                if new_data is not existing_data:
                    c.execute(
                        "UPDATE feeds SET last_modified = ? WHERE rowid = ?",
                        (new_data.last_modified_date.astimezone().timestamp(), self.feed_id)
                    )
                    for cve in new_data:
                        self.schema.add(cve)
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

    def __iter__(self) -> Iterator[CVE]:
        self.reload()
        return itertools.chain(*(iter(CVEdbDataSource(feed)) for feed in self.feeds))

    def __len__(self):
        self.reload()
        c = self.connection.cursor()
        c.execute("SELECT COUNT(*) FROM cves")
        return c.fetchone()[0]

    @staticmethod
    def _to_sql_clause(query: SearchQuery) -> Tuple[Optional[str], Optional[Tuple[Union[str, int], ...]]]:
        if isinstance(query, TermQuery):
            query_text = query.query
            description_query = "d.description"
            id_query = "c.id"
            if not query.case_sensitive:
                query_text = query_text.upper()
                description_query = f"UPPER({description_query})"
                id_query = f"UPPER({id_query})"
            return f"({description_query} LIKE ? OR {id_query} LIKE ?)", (f"%{query_text}%", f"%{query_text}%")
        elif isinstance(query, BeforePublishedDateQuery):
            return f"c.published <= ?", (int(query.date.astimezone().timestamp()),)
        elif isinstance(query, BeforeModifiedDateQuery):
            return f"c.last_modified <= ?", (int(query.date.astimezone().timestamp()),)
        elif isinstance(query, AfterPublishedDateQuery):
            return f"c.published >= ?", (int(query.date.astimezone().timestamp()),)
        elif isinstance(query, AfterModifiedDateQuery):
            return f"c.last_modified >= ?", (int(query.date.astimezone().timestamp()),)
        elif isinstance(query, CompoundQuery):
            if len(query.sub_queries) == 0:
                return ["true", "false"][isinstance(query, OrQuery)], ()
            elif len(query.sub_queries) == 1:
                return CVEdbData._to_sql_clause(query.sub_queries[0])
            components = []
            params = []
            for sub_query in query.sub_queries:
                c, p = CVEdbData._to_sql_clause(sub_query)
                if c is None or p is None:
                    return None, None
                components.append(c)
                params.extend(p)
            compound_query = [" AND ", " OR "][isinstance(query, OrQuery)].join(components)
            return f"({compound_query})", tuple(params)
        else:
            return None, None

    def search(
            self,
            *queries: Union[str, SearchQuery],
            sort: Iterable[Sort] = (Sort.CVE_ID,),
            ascending: bool = True
    ) -> Iterator[CVE]:
        self.reload()
        query = Data.make_query(*queries)
        query_string, query_params = CVEdbData._to_sql_clause(query)
        if query_string is None or query_params is None:
            # the query could not be converted to a SQL query
            yield from super().search(query, sort=sort, ascending=ascending)
        feeds_where_clause = f"c.feed IN ({', '.join('?' * len(self.feeds)) })"
        params = [feed.feed_id for feed in self.feeds]
        c = self.connection.cursor()
        params.extend(query_params)
        order_by = ""
        if sort:
            components = []
            asc = ["DESC", "ASC"][ascending]
            for s in sort:
                if s == Sort.CVE_ID:
                    components.append("c.id")
                elif s == Sort.DESCRIPTION:
                    components.append("d.description")
                elif s == Sort.LAST_MODIFIED_DATE:
                    components.append("c.last_modified")
                elif s == Sort.PUBLISHED_DATE:
                    components.append("c.published")
                elif s == Sort.IMPACT:
                    components.append("c.base_score")
                elif s == Sort.SEVERITY:
                    components.append("c.severity")
                else:
                    raise NotImplementedError(f"TODO: Add support for {s!r}")
                components[-1] = f"{components[-1]} {asc}"
            order_by = f"ORDER BY {', '.join(components)}"
        c.execute("SELECT DISTINCT c.* FROM descriptions d INNER JOIN cves c ON d.cve = c.id "
                  f"WHERE {feeds_where_clause} AND {query_string} {order_by}",
                  params)
        # The following assumes that all feeds have the same schema, which should always be true
        yield from self.feeds[0].schema.cve_iter(c.fetchall())

    def reload(self):
        out_of_date_feeds = [feed for feed in self.feeds if feed.is_out_of_date()]
        for feed in tqdm(out_of_date_feeds, desc="updating", unit=" feeds", leave=False):
            feed.reload(feed.data())


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

    def reload(self, existing_data: Optional[Data] = None) -> CVEdbDataSource:
        return CVEdbDataSource(self)

    @staticmethod
    def open(db_path: Union[str, Path] = DEFAULT_DB_PATH, parents: Optional[Iterable[Feed]] = None) -> CVEdbContext:
        return CVEdbContext(db_path, parents)
