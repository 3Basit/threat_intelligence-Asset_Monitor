"""Tests for configuration module and basic project integrity."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest


class TestConfig(unittest.TestCase):

    def test_config_imports(self):
        import config
        self.assertTrue(hasattr(config, "DB_PATH"))
        self.assertTrue(hasattr(config, "NVD_API_KEY"))
        self.assertTrue(hasattr(config, "MODEL_DIR"))

    def test_db_path_default(self):
        import config
        self.assertTrue(config.DB_PATH.endswith("threat_intelligence.db"))

    def test_logger_imports(self):
        from logger import get_logger
        log = get_logger("test")
        self.assertIsNotNone(log)


class TestAllModulesImport(unittest.TestCase):
    """Verify all TI pipeline modules import without errors."""

    def test_import_database(self):
        import database
        self.assertTrue(hasattr(database, "init_db"))

    def test_import_matching(self):
        import matching
        self.assertTrue(hasattr(matching, "run_matching"))

    def test_import_threat_pressure(self):
        import threat_pressure
        self.assertTrue(hasattr(threat_pressure, "compute_tpf"))

    def test_import_cisa_kev(self):
        import cisa_kev
        self.assertTrue(hasattr(cisa_kev, "fetch_cisa_kev"))

    def test_import_nvd_fetch(self):
        import nvd_fetch
        self.assertTrue(hasattr(nvd_fetch, "enrich_cves"))

    def test_import_exploit_db(self):
        import exploit_db
        self.assertTrue(hasattr(exploit_db, "run_exploitdb"))


if __name__ == "__main__":
    unittest.main()
