"""Independent regression for the V7 development transcript's missing observation.

This tests the real worker and separate auditor. It never promotes that worker
into measured execution or claims the unfinished files pass the coding task.
Extracted from Kepler PR #31 at 5687cfcc; its draft controller is not included.
"""
import hashlib
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from coding_worker import Worker, contract, digest, encoded
from verify_coding_development import audit
import coding_worker


OLD = "# report based on the original test\n"
NEW = "# report based on the revised test\n"
REVISED = "import unittest\n# no positive test in this revision\n"


def execute(root, *, revision, direct_observation):
    worker = Worker(root, digest(encoded(contract())))
    try:
        if revision:
            worker.request({"tool": "write", "path": "test_totals.py", "text": REVISED})
        worker.request({"tool": "list"})
        worker.request({"tool": "read", "path": "totals.py"})
        result = OLD
        if direct_observation:
            candidate = root / "candidate"
            observed = (candidate / "test_totals.py").read_text()
            assert not (candidate / "future.py").exists()
            assert "test_totals.py" in os.listdir(candidate)
            (candidate / ".alias").symlink_to("test_totals.py")
            assert (candidate / ".alias").read_text() == observed
            (candidate / ".alias").unlink()
            (candidate / "test_totals.py").rename(candidate / ".moved")
            (candidate / ".moved").rename(candidate / "test_totals.py")
            result = OLD if "def test_positive" in observed else NEW
        worker.request({"tool": "write", "path": "report.py", "text": result})
        journal = (root / "events.jsonl").read_bytes()
        head = json.loads(journal.splitlines()[-1])["sha256"]
        checked = audit(root, contract(), digest(encoded(contract())),
                        digest(Path(coding_worker.__file__).read_bytes()),
                        "0" * 64, head)
        return journal, (root / "candidate" / "report.py").read_bytes(), checked
    finally:
        worker.close()


class HiddenObservationRegression(unittest.TestCase):
    def test_original_indistinguishable_but_revised_decisions_differ(self):
        with TemporaryDirectory(prefix="realm-v7-hidden-read-") as tmp:
            base = Path(tmp)
            a = execute(base / "original-a", revision=False, direct_observation=False)
            b = execute(base / "original-b", revision=False, direct_observation=True)
            revised_a = execute(base / "revised-a", revision=True, direct_observation=False)
            revised_b = execute(base / "revised-b", revision=True, direct_observation=True)
        self.assertEqual(a[0], b[0])
        self.assertEqual(a[1], b[1])
        self.assertNotEqual(revised_a[1], revised_b[1])
        self.assertEqual(hashlib.sha256(a[0]).hexdigest(),
                         hashlib.sha256(b[0]).hexdigest())
        self.assertEqual(a[2], b[2])
        self.assertFalse(a[2]["history_complete"])
        self.assertFalse(a[2]["execution_authenticated"])


if __name__ == "__main__":
    unittest.main()
