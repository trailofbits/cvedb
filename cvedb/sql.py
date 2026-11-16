from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import ClassVar


class Query(ABC):
    parent: "CompoundQuery | None" = None

    @abstractmethod
    def to_sql(self) -> str:
        raise NotImplementedError

    def traverse(self) -> Iterator["Query"]:
        yield self

    def remove_from_parent(self) -> None:
        if self.parent is not None:
            self.parent.remove(self)


class TrueQuery(Query):
    def to_sql(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self,
    ) -> str:
        return "1"


TRUE = TrueQuery()


class SimpleQuery(Query):
    def __init__(self, query: str) -> None:
        self.query = query

    def to_sql(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self,
    ) -> str:
        return self.query

    def __repr__(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self,
    ) -> str:
        return f"{self.__class__.__name__}(query={self.query!r})"


class CompoundQuery(Query):
    operand: ClassVar[str]

    def __init__(self, *queries: Query) -> None:
        self.queries: list[Query] = []
        self.extend(queries)

    def __init_subclass__(cls) -> None:
        if not hasattr(cls, "operand"):
            raise TypeError(f"CompoundQuery {cls.__name__} must set an operand")

    @classmethod
    def create(cls, *queries: Query) -> Query:
        if len(queries) == 0:
            return TrueQuery()
        if len(queries) == 1:
            return queries[0]
        return cls(*queries)

    def traverse(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self,
    ) -> Iterator[Query]:
        yield self
        for query in self.queries:
            yield from query.traverse()

    def add(self, query: Query) -> None:
        if isinstance(query, TrueQuery):
            query = TrueQuery()
        if isinstance(query, CompoundQuery) and query.operand == self.operand:
            self.extend(query.queries)
        else:
            query.remove_from_parent()
            self.queries.append(query)
            query.parent = self

    def extend(self, queries: Iterable[Query]) -> None:
        for query in queries:
            self.add(query)

    def remove(self, query: Query) -> None:
        for index, value in enumerate(self.queries):
            if value == query:
                del self.queries[index]
                value.parent = None
                return
        raise ValueError(f"Query {query} is not a member of {self}")

    def to_sql(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self,
    ) -> str:
        if not self.queries:
            return "1"
        if len(self.queries) == 1:
            return self.queries[0].to_sql()
        return f" {self.operand} ".join(f"({query.to_sql()})" for query in self.queries)


class And(CompoundQuery):
    operand = "AND"


class Or(CompoundQuery):
    operand = "OR"


@dataclass(unsafe_hash=True, order=True)
class Select:
    columns: str
    from_tables: str
    where: Query | None = None
    order_by: str | None = None
    limit: int | None = None
    params: list[int | float | str | None] = field(default_factory=list)

    def to_sql(self) -> str:
        statement = f"SELECT {self.columns} FROM {self.from_tables}"
        if self.where is not None:
            statement = f"{statement} WHERE {self.where.to_sql()}"
        if self.order_by is not None:
            statement = f"{statement} ORDER BY {self.order_by}"
        if self.limit is not None:
            statement = f"{statement} LIMIT {self.limit}"
        return statement

    def __str__(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self,
    ) -> str:
        return self.to_sql()
