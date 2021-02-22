from datetime import datetime
from pathlib import Path
from sqlite3 import connect, Connection
from typing import Iterable, Iterator, List, Optional, Tuple, Union

from cvss import CVSS2, CVSS3, CVSSError

from .cve import CVE
from .feed import Data, DataSource, Feed, FEEDS


FEED_TABLE_CREATE = (
    "CREATE TABLE IF NOT EXISTS feeds("
    "name VARCHAR UNIQUE NOT NULL, "
    "last_modified INTEGER NULL"
    ")"
)

CVE_TABLE_CREATE = (
    "CREATE TABLE IF NOT EXISTS cves("
    "id VARCHAR DESC NOT NULL, "
    "feed REFERENCES feeds (rowid) NOT NULL, "
    "published INTEGER NOT NULL, "
    "last_modified INTEGER NOT NULL, "
    "impact_vector VARCHAR NULL, "
    "description VARCHAR NULL, "
    "PRIMARY KEY (id, feed)"
    ")"
)


class DbBackedFeed(Feed):
    register = False

    def __init__(self, connection: Connection, parent: Feed):
        super().__init__(parent.name)
        self.parent: Feed = parent
        self.connection: Connection = connection
        with self.connection:
            self.connection.execute(FEED_TABLE_CREATE)
            self.connection.execute(CVE_TABLE_CREATE)
            c = self.connection.cursor()
            c.execute(f"INSERT OR IGNORE INTO feeds (name) VALUES (?)", (parent.name,))
            if c.lastrowid is not None:
                self.feed_id: int = c.lastrowid
            else:
                c.execute("SELECT * FROM feeds WHERE name = ?", self.parent.name)
                self.feed_id = c.fetchone().rowid

    def last_modified(self) -> Optional[datetime]:
        c = self.connection.cursor()
        c.execute("SELECT last_modified FROM feeds WHERE rowid = ?", self.feed_id)
        return datetime.fromtimestamp(c.fetchone()["last_modified"])

    def reload(self, existing_data: Optional[Data] = None) -> DataSource:
        return self.parent.reload(existing_data=existing_data)


class CVEdbContext:
    def __init__(self, db_path: Union[str, Path], parents: Optional[Iterable[Feed]] = None):
        if not isinstance(db_path, Path):
            db_path = Path(str(db_path))
        self.db_path: Path = db_path
        self.parents: Optional[Iterable[Feed]] = None
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
    def __init__(self, db: "CVEdb"):
        self.db: CVEdb = db

    def __iter__(self) -> Iterator[CVE]:
        c = self.db.connection.cursor()
        c.execute("SELECT * FROM cves")
        for cve in c.fetchall():
            if cve["impact_vector"] is None:
                impact = None
            else:
                try:
                    impact = CVSS3(cve["impact_vector"])
                except CVSSError:
                    try:
                        impact = CVSS2(cve["impact_vector"])
                    except CVSSError:
                        impact = None
            yield CVE(
                cve_id=cve["id"],
                published_date=datetime.fromtimestamp(cve["published"]),
                last_modified_date=datetime.fromtimestamp(cve["last_modified"]),
                impact=impact,
                descriptions=(),  # TODO: Implement descriptions
                references=(),  # TODO: Implement references
                assigner=None  # TODO: Implement assigner
            )

    def __len__(self):
        c = self.db.connection.cursor()
        c.execute("SELECT COUNT(*) FROM cves")
        return c.fetchone()[0]


class CVEdb(Feed):
    register = False

    def __init__(self, connection: Connection, parents: Optional[Iterable[Feed]] = None):
        super().__init__("cves")
        if parents is None:
            parents = FEEDS.values()
        self.parents: List[DbBackedFeed] = [DbBackedFeed(connection, parent) for parent in parents]
        self.connection: Connection = connection

    def last_modified(self) -> Optional[datetime]:
        newest = None
        for parent in self.parents:
            parent_modified = parent.last_modified()
            if parent_modified is not None and (newest is None or parent_modified > newest):
                newest = parent_modified
        return newest

    def data(self, force_reload: bool = False) -> CVEdbData:
        return CVEdbData(self)

    def reload(self, existing_data: Optional[Data] = None) -> DataSource:
        pass

    @staticmethod
    def open(db_path: Union[str, Path], parents: Optional[Iterable[Feed]] = None) -> CVEdbContext:
        return CVEdbContext(db_path, parents)
