import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[2] / "results" / "verify_raw_v005.py"
spec = importlib.util.spec_from_file_location("raw_verifier", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="v005-sha-test-")
        self.root = Path(self.temp.name)
        self.file = self.root / "data.csv"
        self.file.write_bytes(b"synthetic\n")
        self.sha = hashlib.sha256(self.file.read_bytes()).hexdigest()
        self.manifest = self.root / "SHA256.txt"

    def tearDown(self):
        self.temp.cleanup()

    def check_lines(self, lines):
        self.manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return module.verify(self.root, self.manifest)

    def test_exact(self):
        result = self.check_lines([f"{self.sha}  ./data.csv"])
        self.assertTrue(result["verified"])
        self.assertEqual(result["unlisted_local_files"], [])

    def test_mismatch(self):
        self.assertFalse(self.check_lines([f"{'0' * 64}  data.csv"])["verified"])

    def test_missing(self):
        self.assertFalse(self.check_lines([f"{self.sha}  missing.csv"])["verified"])

    def test_duplicate(self):
        result = self.check_lines([f"{self.sha}  data.csv", f"{self.sha}  ./data.csv"])
        self.assertFalse(result["verified"])
        self.assertTrue(result["unsafe"])

    def test_unsafe_targets(self):
        for target in ["../elsewhere", "/absolute", "C:/outside", "a\\b"]:
            with self.subTest(target=target):
                self.assertFalse(self.check_lines([f"{self.sha}  {target}"])["verified"])

    def test_empty_manifest(self):
        self.assertFalse(self.check_lines([])["verified"])

    def test_extra_is_reported_not_destroyed(self):
        extra = self.root / "extra.txt"
        extra.write_bytes(b"keep")
        result = self.check_lines([f"{self.sha}  data.csv"])
        self.assertTrue(result["verified"])
        self.assertEqual(result["unlisted_local_files"], ["extra.txt"])
        self.assertTrue(extra.exists())


if __name__ == "__main__":
    unittest.main()
