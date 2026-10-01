#!/usr/bin/env python3
"""Pruebas unitarias del watchdog SFTP (sin servidor real)."""

from __future__ import annotations

import os
import stat
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import paramiko

# Importar módulo bajo test
import sftp_watchdog as wd


class RemotePathMapperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        self.mapper = wd.RemotePathMapper(self.root, "/remote/base")

    def test_rel_inside_tree(self) -> None:
        f = self.root / "a" / "b.txt"
        f.parent.mkdir(parents=True)
        f.write_text("x")
        self.assertEqual(self.mapper.rel_from_local(f), "a/b.txt")
        self.assertEqual(self.mapper.remote_from_local(f), "/remote/base/a/b.txt")

    def test_rel_deleted_path_still_maps(self) -> None:
        gone = self.root / "gone.txt"
        self.assertEqual(self.mapper.rel_from_local(str(gone)), "gone.txt")

    def test_outside_tree_returns_none(self) -> None:
        other = Path(tempfile.gettempdir()) / "outside_watchdog_xyz"
        self.assertIsNone(self.mapper.rel_from_local(other))


class EnsureRemoteDirTests(unittest.TestCase):
    def test_creates_nested_dirs(self) -> None:
        created: list[str] = []
        stats: set[str] = set()

        class FakeSftp:
            def stat(self, path: str):
                if path not in stats:
                    raise OSError("missing")
                return mock.Mock()

            def mkdir(self, path: str) -> None:
                created.append(path)
                stats.add(path)

        stats.add("/")
        wd.ensure_remote_dir(FakeSftp(), "/remote/base/nested")  # type: ignore[arg-type]
        self.assertEqual(created, ["/remote", "/remote/base", "/remote/base/nested"])


class SftpSessionThreadSafetyTests(unittest.TestCase):
    def test_run_holds_lock_during_operation(self) -> None:
        creds = wd.SftpCredentials("h", 22, "u", "p", None, None)
        session = wd.SftpSession(creds)
        session._sftp = mock.Mock()
        lock_held = threading.Event()
        release = threading.Event()

        def slow_op(sftp):
            lock_held.set()
            release.wait(timeout=2)
            return "ok"

        t1 = threading.Thread(target=lambda: session.run(slow_op))
        t2 = threading.Thread(
            target=lambda: session.run(lambda s: "fast")
        )
        t1.start()
        self.assertTrue(lock_held.wait(timeout=2))
        t2.start()
        t2.join(timeout=0.2)
        self.assertTrue(
            t2.is_alive(),
            "La segunda operación debe esperar mientras la primera usa SFTP",
        )
        release.set()
        t1.join(timeout=2)
        t2.join(timeout=2)


class HandlerDeleteTests(unittest.TestCase):
    def test_delete_cancels_pending_upload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "pending.txt"
            mapper = wd.RemotePathMapper(root, "/r")
            session = mock.Mock()
            handler = wd.SftpMirrorHandler(session, mapper)
            timer = mock.Mock()
            handler._upload_timers[str(target)] = timer
            event = mock.Mock()
            event.is_directory = False
            event.src_path = str(target)
            session.run.return_value = None
            handler.on_deleted(event)
            timer.cancel.assert_called_once()


class HandlerMoveTests(unittest.TestCase):
    def test_file_move_rename_fallback_upload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "a.txt"
            dest = root / "b.txt"
            src.write_text("data")
            dest.write_text("data")

            mapper = wd.RemotePathMapper(root, "/r")
            session = mock.Mock()
            uploaded: list[tuple[Path, str]] = []

            def fake_run(fn, *args, **kwargs):
                sftp = mock.Mock()
                sftp.rename.side_effect = OSError("exists")

                def fake_stat(path: str):
                    attr = mock.Mock()
                    attr.st_mode = stat.S_IFDIR
                    return attr

                sftp.stat.side_effect = fake_stat

                def capture_put(local, remote):
                    uploaded.append((Path(local), remote))

                sftp.put = capture_put
                sftp.remove = mock.Mock()
                return fn(sftp, *args, **kwargs)

            session.run.side_effect = fake_run
            handler = wd.SftpMirrorHandler(session, mapper)
            event = wd.FileMovedEvent(src_path=str(src), dest_path=str(dest))
            handler.on_moved(event)
            self.assertEqual(len(uploaded), 1)
            self.assertEqual(uploaded[0][1], "/r/b.txt")


if __name__ == "__main__":
    unittest.main()
