from unittest import TestCase

from cvedb.db import CVEdb
from cvedb.cpe import CPE, Logical, parse_formatted_string, Part
from cvedb.cve import Configurations


class TestCPE(TestCase):
    def test_parse(self):
        cpe = parse_formatted_string("cpe:2.3:a:kamadak-exif_project:kamadak-exif:0.5.2:*:*:*:*:rust:*:*")
        self.assertEqual(cpe.part, Part.APP)
        self.assertEqual(cpe.vendor, "kamadak-exif_project")
        self.assertEqual(cpe.product, "kamadak-exif")
        self.assertEqual(cpe.version, "0.5.2")
        self.assertEqual(cpe.update, Logical.ANY)
        self.assertEqual(cpe.edition, Logical.ANY)
        self.assertEqual(cpe.lang, Logical.ANY)
        self.assertEqual(cpe.sw_edition, Logical.ANY)
        self.assertEqual(cpe.target_sw, "rust")
        self.assertEqual(cpe.target_hw, Logical.ANY)
        self.assertEqual(cpe.other, Logical.ANY)

    def test_serialization(self):
        with CVEdb.open() as db:
            for i, cve in enumerate(db.data()):
                if i > 100:
                    break
                self.assertEqual(cve.configurations, Configurations.loads(cve.configurations.dumps()))

    def test_wildcards(self):
        self.assertTrue(CPE().is_complete_wildcard())
        self.assertFalse(CPE(vendor="foo").is_complete_wildcard())
