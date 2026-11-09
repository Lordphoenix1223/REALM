"""A regression for the development transcript's incomplete observation boundary.

This exercises the real V7 development worker and auditor. It makes no claim
about the measured Linux/KVM execution path or production recovery authority.
"""

import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts.v7 import coding_worker
from scripts.v7.coding_worker import Worker, contract, digest, encoded
from scripts.v7.verify_coding_development import audit


OLD_REPORT = "# report selected for positive tests\n"
NEW_REPORT = "# report selected after test revision\n"
REVISED_TEST = "import unittest\n# positive test removed by revision\n"


class CausalCaptureBoundaryTests(unittest.TestCase):
    def run_history(self, root: Path, *, revised: bool, hidden_observer: bool):
        worker = Worker(root, digest(encoded(contract())))
        try:
            if revised:
                worker.request({"tool": "write", "path": "test_totals.py", "text": REVISED_TEST})
            worker.request({"tool": "list"})
            worker.request({"tool": "read", "path": "totals.py"})

            if hidden_observer:
                candidate = root / "candidate"
                observed = (candidate / "test_totals.py").read_text()
                self.assertFalse((candidate / "future.py").exists())
                self.assertIn("test_totals.py", os.listdir(candidate))
                alias = candidate / ".alias"
                alias.symlink_to("test_totals.py")
                self.assertEqual(alias.read_text(), observed)
                alias.unlink()
                (candidate / "test_totals.py").rename(candidate / ".moved")
                (candidate / ".moved").rename(candidate / "test_totals.py")
                report = OLD_REPORT if "def test_positive" in observed else NEW_REPORT
            else:
                report = OLD_REPORT

            worker.request({"tool": "write", "path": "report.py", "text": report})
            journal = (root / "events.jsonl").read_bytes()
            head = json.loads(journal.splitlines()[-1])["sha256"]
            checked = audit(
                root,
                contract(),
                digest(encoded(contract())),
                digest(Path(coding_worker.__file__).read_bytes()),
                "0" * 64,  # No interpreter-backed check occurs in this history.
                head,
            )
            self.assertEqual(checked["status"], "DEVELOPMENT_TRANSCRIPT_CHECKED")
            self.assertEqual(checked["authority"], "NONE")
            self.assertFalse(checked["history_complete"])
            self.assertFalse(checked["execution_authenticated"])
            return journal, (root / "candidate" / "report.py").read_text(), checked
        finally:
            worker.close()

    def test_same_transcript_can_hide_a_revised_dependency(self):
        with TemporaryDirectory(prefix="realm-v7-hidden-observation-") as tmp:
            base = Path(tmp)
            original_plain = self.run_history(base / "original-plain", revised=False, hidden_observer=False)
            original_hidden = self.run_history(base / "original-hidden", revised=False, hidden_observer=True)
            revised_plain = self.run_history(base / "revised-plain", revised=True, hidden_observer=False)
            revised_hidden = self.run_history(base / "revised-hidden", revised=True, hidden_observer=True)

        self.assertEqual(original_plain, original_hidden)
        self.assertEqual(original_plain[1], OLD_REPORT)
        self.assertEqual(revised_plain[1], OLD_REPORT)
        self.assertEqual(revised_hidden[1], NEW_REPORT)
        self.assertNotEqual(revised_plain[1], revised_hidden[1])


if __name__ == "__main__":
    unittest.main()
