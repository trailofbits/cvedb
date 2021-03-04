from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Iterable, Iterator, List, Optional, Union


class Query(ABC):
    parent: Optional["Query"] = None

    @abstractmethod
    def to_sql(self) -> str:
        raise NotImplementedError()

    def traverse(self) -> Iterator["Query"]:
        yield self

    def remove_from_parent(self):
        if self.parent is None:
            return
        elif hasattr(self.parent, "remove"):
            self.parent.remove(self)
        else:
            raise TypeError(f"Query {self} cannot be removed from {self.parent}")


class TrueQuery(Query):
    def to_sql(self) -> str:
        return "1"


TRUE: TrueQuery = TrueQuery()


class SimpleQuery(Query):
    def __init__(self, query: str):
        self.query: str = query

    def to_sql(self) -> str:
        return self.query

    def __repr__(self):
        return f"{self.__class__.__name__}(query={self.query!r})"


class CompoundQuery(Query):
    operand: str

    def __init__(self, *queries: Query):
        self.queries: List[Query] = []
        self.extend(queries)

    def __init_subclass__(cls, **kwargs):
        if not hasattr(cls, "operand") or cls.operand is None:
            raise TypeError(f"CompoundQuery {cls.__name__} must set an operand")

    @classmethod
    def create(cls, *queries: Query) -> Query:
        if len(queries) == 0:
            return TRUE
        elif len(queries) == 1:
            return queries[0]
        else:
            return cls(*queries)

    def traverse(self) -> Iterator[Query]:
        yield self
        for q in self.queries:
            yield from q.traverse()

    def add(self, query: Query):
        if isinstance(query, TrueQuery):
            # ignore true queries
            pass
        elif isinstance(query, CompoundQuery) and query.operand == self.operand:
            self.extend(query.queries)
        else:
            query.remove_from_parent()
            self.queries.append(query)
            query.parent = self

    def extend(self, queries: Iterable[Query]):
        for query in queries:
            self.add(query)

    def remove(self, query: Query):
        for i, q in enumerate(self.queries):
            if q == query:
                self.queries = self.queries[:i] + self.queries[i+1:]
                q.parent = None
                return
        raise ValueError(f"Query {query} is not a member of {self}")

    def to_sql(self) -> str:
        if len(self.queries) == 0:
            return TRUE.to_sql()
        elif len(self.queries) == 1:
            return next(iter(self.queries)).to_sql()
        return f" {self.operand} ".join(f"({query.to_sql()})" for query in self.queries)


class And(CompoundQuery):
    operand = "AND"


class Or(CompoundQuery):
    operand = "OR"


@dataclass(unsafe_hash=True, order=True)
class Select:
    columns: str
    from_tables: str
    where: Optional[Query] = None
    order_by: Optional[str] = None
    limit: Optional[int] = None
    params: List[Optional[Union[int, float, str]]] = field(default_factory=list)

    def __post_init__(self):
        if not isinstance(self.params, list):
            self.params = list(self.params)

    def to_sql(self) -> str:
        stmt = f"SELECT {self.columns} FROM {self.from_tables}"
        if self.where is not None:
            stmt = f"{stmt} WHERE {self.where.to_sql()}"
        if self.order_by is not None:
            stmt = f"{stmt} ORDER BY {self.order_by}"
        if self.limit is not None:
            stmt = f"{stmt} LIMIT {self.limit}"
        return stmt

    def __str__(self):
        return self.to_sql()
