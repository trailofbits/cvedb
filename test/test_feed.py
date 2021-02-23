from datetime import datetime
from typing import Optional, Iterator
from unittest import TestCase

from cvedb.cve import CVE
from cvedb.feed import Feed, FEEDS, Data, DataSource


class TestFeed(TestCase):
    def test_custom_feed(self):
        class CustomDataSource(DataSource):
            def __iter__(self) -> Iterator[CVE]:
                yield CVE(
                    "FAKE_CVE",
                    datetime.now(),
                    datetime.now()
                )

        class CustomFeed(Feed):
            def __init__(self):
                super().__init__(name="custom")

            def reload(self, existing_data: Optional[Data] = None) -> DataSource:
                return CustomDataSource(datetime.now())

        feed = CustomFeed()

        self.assertIn("custom", FEEDS)
        self.assertIs(FEEDS["custom"], feed)

        data = feed.data()

        self.assertEqual(len(data), 1)
        self.assertEqual(next(iter(data)).cve_id, "FAKE_CVE")
