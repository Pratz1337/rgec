"""Real Docker contract checks on the same pinned ARVO image; no mocks."""

import json
import shlex
import subprocess
import unittest
import uuid
from pathlib import Path

from unauthorized_channels.build_broker import BuildBroker, _docker, prepare_build_image


class RealBuildBrokerContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        metadata = Path(
            "runs/rgec-broker-preparation-2026-10-02-v2/preparation.json"
        )
        preparation = json.loads(metadata.read_text()) if metadata.exists() else prepare_build_image()
        if _docker(["image", "inspect", preparation["prepared_image_id"]]).returncode:
            preparation = prepare_build_image()
        cls.root = Path("runs/rgec-broker-contract-2026-10-02-" + uuid.uuid4().hex[:8])
        cls.root.mkdir(exist_ok=False)
        store = cls.root / "host-store"
        store.mkdir()
        cls.broker = BuildBroker(
            preparation["prepared_image_id"], store,
        )
        cls.evidence = {"preparation": preparation}
        print("contract evidence:", cls.root, flush=True)

    @classmethod
    def tearDownClass(cls):
        (cls.root / "evidence.json").write_text(json.dumps(cls.evidence, indent=2))

    def test_native_compiler_failure_preserves_non_utf8_filename(self):
        session = self.broker.bind()
        try:
            # The input is this task's actual png.c. An invalid-UTF8 filename
            # exercises real native diagnostics without inventing a C workload.
            code = (
                "import os, subprocess, sys; "
                "name=b'/workspace/png_\\xff.c'; "
                "os.symlink(b'/src/graphicsmagick/coders/png.c', name); "
                "p=subprocess.Popen([b'clang', b'-x', b'c', b'-fsyntax-only', name], "
                "stdout=subprocess.PIPE, stderr=subprocess.PIPE); "
                "out,err=p.communicate(); os.write(1,out); os.write(2,err); "
                "sys.exit(p.returncode)"
            )
            result = session.exec("python3 -c " + shlex.quote(code))
            (self.root / "native-diagnostic.stdout").write_bytes(result.stdout)
            (self.root / "native-diagnostic.stderr").write_bytes(result.stderr)
            self.assertNotEqual(result.returncode, 0)
            self.assertIsInstance(result.stderr, bytes)
            self.assertIn(b"\xff", result.stderr)
            self.assertIn(b"error", result.stderr)
            self.evidence["native_diagnostic"] = {
                "returncode": result.returncode, "non_utf8_filename_preserved": True,
                "source": "/src/graphicsmagick/coders/png.c",
                "diagnostic": "native-diagnostic.stderr",
            }
        finally:
            session.close()

    def test_timeout_removes_real_build_and_descendants(self):
        session = self.broker.bind()
        try:
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                session.request({"action": "compile"}, timeout=1)
            timeout = caught.exception
            (self.root / "timeout.stdout").write_bytes(timeout.stdout or b"")
            (self.root / "timeout.stderr").write_bytes(timeout.stderr or b"")
            inspected = _docker(["inspect", session.name])
            self.assertNotEqual(inspected.returncode, 0)
            self.evidence["timeout"] = {
                "command": "cd /src/graphicsmagick && /bin/arvo compile",
                "deadline_seconds": 1, "container_removed": True,
                "outcome": "expected request invalidation, not a successful build",
            }
        finally:
            session.close()


if __name__ == "__main__":
    unittest.main()
