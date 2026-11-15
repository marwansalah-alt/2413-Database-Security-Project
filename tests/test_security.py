import sqlite3
import tempfile
import unittest
from pathlib import Path
from security_demo import setup, authenticate, safe_lookup, unsafe_lookup, update_balance


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'test.db'
        setup(self.path)
        self.db = sqlite3.connect(self.path)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_injection_before_after(self):
        payload = "alice' OR '1'='1"
        self.assertEqual(len(unsafe_lookup(self.db, 'viewer', payload)), 3)
        self.assertEqual(len(safe_lookup(self.db, 'viewer', payload)), 0)

    def test_viewer_cannot_modify(self):
        with self.assertRaises(PermissionError):
            update_balance(self.db, 'viewer', 1, 999)
        self.assertEqual(safe_lookup(self.db, 'viewer', 'alice')[0][2], 100)

    def test_editor_can_modify(self):
        self.assertEqual(update_balance(self.db, 'editor', 1, 125), 1)
        self.assertEqual(safe_lookup(self.db, 'editor', 'alice')[0][2], 125)

    def test_authentication(self):
        self.assertEqual(authenticate(self.db, 'alice', 'alice-demo-password'), 'viewer')
        with self.assertRaises(PermissionError):
            authenticate(self.db, 'alice', 'wrong')

    def test_unknown_role_denied(self):
        with self.assertRaises(PermissionError):
            safe_lookup(self.db, 'unknown', 'alice')


if __name__ == '__main__':
    unittest.main()
