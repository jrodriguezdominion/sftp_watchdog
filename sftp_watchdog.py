#!/usr/bin/env python3
"""Watchdog SFTP: copia inicial y espejo en tiempo real de un árbol local hacia SFTP."""

from __future__ import annotations

import errno
import fnmatch
import getpass
import logging
import os
import posixpath
import stat
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import paramiko
from paramiko import SFTPClient, SSHClient
from watchdog.events import (
    DirMovedEvent,
    FileMovedEvent,
    FileSystemEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

UPLOAD_DEBOUNCE_SEC = 0.4

IGNORE_PATTERNS = ("*~", "*.swp", "*.swx", ".#*")


def should_ignore(path: str) -> bool:
    name = os.path.basename(path)
    return any(fnmatch.fnmatch(name, pat) for pat in IGNORE_PATTERNS)


def prompt_local_path() -> Path:
    while True:
        raw = input("Ruta local absoluta: ").strip()
        p = Path(raw).expanduser().resolve()
        if not p.is_absolute():
            print("Debe ser una ruta absoluta.", file=sys.stderr)
            continue
        if not p.is_dir():
            print("No existe o no es un directorio.", file=sys.stderr)
            continue
        return p


def prompt_remote_path() -> str:
    while True:
        raw = input("Ruta remota absoluta: ").strip()
        if not raw.startswith("/"):
            print("La ruta remota debe empezar por '/'.", file=sys.stderr)
            continue
        return posixpath.normpath(raw)


@dataclass
class SftpCredentials:
    host: str
    port: int
    username: str
    password: str | None
    key_path: Path | None
    key_passphrase: str | None


def prompt_credentials() -> SftpCredentials:
    while True:
        host = input("Host remoto: ").strip()
        if host:
            break
        print("El host no puede estar vacío.", file=sys.stderr)
    port_raw = input("Puerto [22]: ").strip() or "22"
    try:
        port = int(port_raw)
    except ValueError:
        print("Puerto inválido.", file=sys.stderr)
        sys.exit(1)
    while True:
        username = input("Usuario: ").strip()
        if username:
            break
        print("El usuario no puede estar vacío.", file=sys.stderr)
    password = getpass.getpass("Contraseña (vacío para clave privada): ")
    key_path: Path | None = None
    key_passphrase: str | None = None
    if not password:
        key_raw = input("Ruta de clave privada: ").strip()
        key_path = Path(key_raw).expanduser().resolve()
        if not key_path.is_file():
            print("Clave privada no encontrada.", file=sys.stderr)
            sys.exit(1)
        key_passphrase = getpass.getpass("Passphrase de la clave (opcional): ") or None
    return SftpCredentials(
        host=host,
        port=port,
        username=username,
        password=password or None,
        key_path=key_path,
        key_passphrase=key_passphrase,
    )


class SftpSession:
    def __init__(self, creds: SftpCredentials) -> None:
        self.creds = creds
        self._client: SSHClient | None = None
        self._sftp: SFTPClient | None = None
        self._lock = threading.Lock()

    def connect(self) -> None:
        with self._lock:
            self._connect_unlocked()

    def _connect_unlocked(self) -> None:
        self._close_unlocked()
        client = SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(
            _ConfirmMissingHostKeyPolicy(self.creds.port)
        )
        kwargs: dict = {
            "hostname": self.creds.host,
            "port": self.creds.port,
            "username": self.creds.username,
            "allow_agent": True,
            "look_for_keys": False,
        }
        if self.creds.password:
            kwargs["password"] = self.creds.password
        elif self.creds.key_path:
            kwargs["key_filename"] = str(self.creds.key_path)
            if self.creds.key_passphrase:
                kwargs["passphrase"] = self.creds.key_passphrase
        else:
            raise paramiko.SSHException(
                "Indica contraseña o ruta de clave privada para autenticarse."
            )
        try:
            client.connect(**kwargs)
        except paramiko.AuthenticationException as e:
            raise paramiko.SSHException("Autenticación fallida.") from e
        self._client = client
        self._sftp = client.open_sftp()
        log.info("Conectado a %s:%s", self.creds.host, self.creds.port)

    def _close_unlocked(self) -> None:
        if self._sftp:
            try:
                self._sftp.close()
            except OSError:
                pass
            self._sftp = None
        if self._client:
            try:
                self._client.close()
            except OSError:
                pass
            self._client = None

    def close(self) -> None:
        with self._lock:
            self._close_unlocked()

    def run(self, fn, *args, **kwargs):
        """Ejecuta operación SFTP con reconexión ante fallo."""
        last_err: Exception | None = None
        for attempt in range(2):
            try:
                with self._lock:
                    if self._sftp is None:
                        self._connect_unlocked()
                    assert self._sftp is not None
                    return fn(self._sftp, *args, **kwargs)
            except (OSError, paramiko.SSHException) as e:
                if isinstance(e, OSError) and _is_permission_denied(e):
                    raise
                last_err = e
                log.warning("Error SFTP (intento %s): %s", attempt + 1, e)
                with self._lock:
                    self._close_unlocked()
        if last_err:
            raise last_err
        raise RuntimeError("run SFTP failed")


class _ConfirmMissingHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, port: int) -> None:
        self.port = port

    def missing_host_key(self, client, hostname, key):
        fingerprint = key.fingerprint
        label = f"[{hostname}]:{self.port}" if self.port != 22 else hostname
        print(f"\nHost desconocido: {label}")
        print(f"Huella: {fingerprint}")
        answer = input("¿Confiar y continuar? [s/N]: ").strip().lower()
        if answer not in ("s", "si", "sí", "y", "yes"):
            raise paramiko.SSHException("Host key rejected by user")
        client.get_host_keys().add(label, key.get_name(), key)
        filename = getattr(client, "_host_keys_filename", None)
        if filename:
            try:
                client.save_host_keys(filename)
            except OSError as exc:
                log.warning("No se pudo guardar %s: %s", filename, exc)


class RemotePathMapper:
    def __init__(self, local_root: Path, remote_root: str) -> None:
        self.local_root = local_root.resolve()
        self.remote_root = posixpath.normpath(remote_root)

    def rel_from_local(self, local_path: str | Path) -> str | None:
        root_abs = os.path.realpath(str(self.local_root))
        local_norm = os.path.normpath(str(local_path))
        try:
            local_abs = os.path.realpath(local_norm)
        except OSError:
            local_abs = os.path.abspath(local_norm)
        if local_abs != root_abs and not local_abs.startswith(root_abs + os.sep):
            return None
        rel = os.path.relpath(local_abs, root_abs)
        if rel == ".":
            return "."
        return rel.replace(os.sep, "/")

    def remote_from_local(self, local_path: str | Path) -> str | None:
        rel = self.rel_from_local(local_path)
        if rel is None:
            return None
        if rel == ".":
            return self.remote_root
        return posixpath.join(self.remote_root, rel)

    def is_under_local(self, path: str | Path) -> bool:
        return self.rel_from_local(path) is not None


def _sftp_errno(exc: OSError) -> int | None:
    err = getattr(exc, "errno", None)
    return err if isinstance(err, int) else None


def _is_not_found(exc: OSError) -> bool:
    if isinstance(exc, FileNotFoundError):
        return True
    return _sftp_errno(exc) == errno.ENOENT


def _is_permission_denied(exc: OSError) -> bool:
    if isinstance(exc, PermissionError):
        return True
    return _sftp_errno(exc) in (errno.EACCES, errno.EPERM)


def ensure_remote_dir(sftp: SFTPClient, remote_dir: str) -> None:
    remote_dir = posixpath.normpath(remote_dir)
    if remote_dir in ("", "/"):
        return
    parts = remote_dir.strip("/").split("/")
    current = ""
    for part in parts:
        current = f"/{part}" if not current else posixpath.join(current, part)
        try:
            st = sftp.stat(current)
        except OSError as exc:
            if not _is_not_found(exc):
                if _is_permission_denied(exc):
                    raise PermissionError(
                        exc.errno,
                        f"No hay permiso para acceder a la ruta remota '{current}'. "
                        "Verifica que la ruta exista y pertenezca a tu área SFTP.",
                    ) from exc
                raise
            try:
                sftp.mkdir(current)
            except OSError as mkdir_exc:
                if _is_permission_denied(mkdir_exc):
                    parent = posixpath.dirname(current) or "/"
                    raise PermissionError(
                        mkdir_exc.errno,
                        f"No se puede crear el directorio remoto '{current}' (permiso denegado). "
                        f"Tu usuario debe poder escribir en '{parent}'. "
                        "Usa una ruta bajo tu home o un directorio que ya exista y te pertenezca.",
                    ) from mkdir_exc
                raise
            continue
        if not stat.S_ISDIR(st.st_mode):
            raise OSError(f"La ruta remota existe y no es un directorio: {current}")


def upload_file(sftp: SFTPClient, local_file: Path, remote_file: str) -> None:
    parent = posixpath.dirname(remote_file)
    if parent and parent != "/":
        ensure_remote_dir(sftp, parent)
    sftp.put(str(local_file), remote_file)


def remove_remote_recursive(sftp: SFTPClient, remote_path: str) -> None:
    try:
        st = sftp.stat(remote_path)
    except OSError:
        return
    if not stat.S_ISDIR(st.st_mode):
        sftp.remove(remote_path)
        return
    for entry in sftp.listdir_attr(remote_path):
        child = posixpath.join(remote_path, entry.filename)
        if stat.S_ISDIR(entry.st_mode):
            remove_remote_recursive(sftp, child)
        else:
            sftp.remove(child)
    sftp.rmdir(remote_path)


def initial_sync(session: SftpSession, mapper: RemotePathMapper, local_root: Path) -> None:
    log.info("Copia inicial de %s -> %s", local_root, mapper.remote_root)

    def _sync(sftp: SFTPClient) -> None:
        ensure_remote_dir(sftp, mapper.remote_root)
        for dirpath, dirnames, filenames in os.walk(local_root):
            dirnames[:] = [d for d in dirnames if not should_ignore(os.path.join(dirpath, d))]
            local_dir = Path(dirpath)
            remote_dir = mapper.remote_from_local(local_dir)
            if remote_dir:
                ensure_remote_dir(sftp, remote_dir)
            for name in filenames:
                local_file = local_dir / name
                if should_ignore(str(local_file)):
                    continue
                remote_file = mapper.remote_from_local(local_file)
                if remote_file:
                    log.info("Subiendo %s", local_file)
                    upload_file(sftp, local_file, remote_file)

    session.run(_sync)
    log.info("Copia inicial completada.")


class SftpMirrorHandler(FileSystemEventHandler):
    def __init__(self, session: SftpSession, mapper: RemotePathMapper) -> None:
        super().__init__()
        self.session = session
        self.mapper = mapper
        self._upload_timers: dict[str, threading.Timer] = {}
        self._timer_lock = threading.Lock()

    def _cancel_upload_timer(self, path: str) -> None:
        with self._timer_lock:
            timer = self._upload_timers.pop(path, None)
            if timer:
                timer.cancel()

    def _schedule_upload(self, local_path: str) -> None:
        if should_ignore(local_path):
            return
        self._cancel_upload_timer(local_path)

        def do_upload() -> None:
            with self._timer_lock:
                self._upload_timers.pop(local_path, None)
            p = Path(local_path)
            if not p.is_file():
                return
            remote = self.mapper.remote_from_local(p)
            if not remote:
                return
            try:
                self.session.run(upload_file, p, remote)
                log.info("Subido %s", local_path)
            except OSError as e:
                log.error("No se pudo subir %s: %s", local_path, e)

        timer = threading.Timer(UPLOAD_DEBOUNCE_SEC, do_upload)
        with self._timer_lock:
            self._upload_timers[local_path] = timer
        timer.start()

    def on_created(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            remote = self.mapper.remote_from_local(event.src_path)
            if remote:

                def _mkdir(sftp: SFTPClient, r: str) -> None:
                    ensure_remote_dir(sftp, r)
                    log.info("Directorio remoto creado %s", r)

                try:
                    self.session.run(_mkdir, remote)
                except OSError as e:
                    log.error("No se pudo crear directorio %s: %s", remote, e)
        else:
            self._schedule_upload(event.src_path)

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._schedule_upload(event.src_path)

    def on_deleted(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._cancel_upload_timer(event.src_path)
        remote = self.mapper.remote_from_local(event.src_path)
        if not remote:
            return

        def _delete(sftp: SFTPClient, r: str, is_dir: bool) -> None:
            if is_dir:
                remove_remote_recursive(sftp, r)
            else:
                try:
                    sftp.remove(r)
                except OSError:
                    pass
            log.info("Eliminado remoto %s", r)

        try:
            self.session.run(_delete, remote, event.is_directory)
        except OSError as e:
            log.error("No se pudo eliminar %s: %s", remote, e)

    def on_moved(self, event: FileSystemEvent) -> None:
        if isinstance(event, (DirMovedEvent, FileMovedEvent)):
            if isinstance(event, FileMovedEvent):
                self._cancel_upload_timer(event.src_path)
            src_remote = self.mapper.remote_from_local(event.src_path)
            dest_under = self.mapper.is_under_local(event.dest_path)
            dest_remote = self.mapper.remote_from_local(event.dest_path)

            if dest_under and dest_remote and src_remote:
                def _rename(sftp: SFTPClient, a: str, b: str) -> None:
                    parent = posixpath.dirname(b)
                    if parent and parent != "/":
                        ensure_remote_dir(sftp, parent)
                    try:
                        sftp.rename(a, b)
                        log.info("Renombrado remoto %s -> %s", a, b)
                    except OSError:
                        if isinstance(event, FileMovedEvent) and Path(event.dest_path).is_file():
                            upload_file(sftp, Path(event.dest_path), b)
                            try:
                                sftp.remove(a)
                            except OSError:
                                pass
                        elif isinstance(event, DirMovedEvent) and Path(event.dest_path).is_dir():
                            ensure_remote_dir(sftp, b)
                            remove_remote_recursive(sftp, a)

                try:
                    self.session.run(_rename, src_remote, dest_remote)
                except OSError as e:
                    log.error("No se pudo renombrar %s: %s", src_remote, e)
            elif src_remote and not dest_under:

                def _delete_src(sftp: SFTPClient, r: str, is_dir: bool) -> None:
                    if is_dir:
                        remove_remote_recursive(sftp, r)
                    else:
                        sftp.remove(r)
                    log.info("Eliminado remoto (movido fuera) %s", r)

                try:
                    self.session.run(
                        _delete_src, src_remote, isinstance(event, DirMovedEvent)
                    )
                except OSError as e:
                    log.error("No se pudo eliminar origen %s: %s", src_remote, e)
            elif dest_under and dest_remote and not src_remote:
                if isinstance(event, FileMovedEvent):
                    self._schedule_upload(event.dest_path)
                else:

                    def _mkdir(sftp: SFTPClient, r: str) -> None:
                        ensure_remote_dir(sftp, r)

                    try:
                        self.session.run(_mkdir, dest_remote)
                    except OSError as e:
                        log.error("No se pudo crear %s: %s", dest_remote, e)

    def cancel_pending_uploads(self) -> None:
        with self._timer_lock:
            timers = list(self._upload_timers.values())
            self._upload_timers.clear()
        for timer in timers:
            timer.cancel()


def main() -> None:
    print("=== Watchdog SFTP ===\n")
    local_root = prompt_local_path()
    remote_root = prompt_remote_path()
    creds = prompt_credentials()
    mapper = RemotePathMapper(local_root, remote_root)
    session = SftpSession(creds)
    try:
        try:
            session.connect()
        except paramiko.SSHException as exc:
            log.error("%s", exc)
            sys.exit(1)
        initial_sync(session, mapper, local_root)
        handler = SftpMirrorHandler(session, mapper)
        observer = Observer()
        observer.schedule(handler, str(local_root), recursive=True)
        observer.start()
        log.info("Vigilando %s (Ctrl+C para salir)", local_root)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            log.info("Deteniendo...")
        finally:
            handler.cancel_pending_uploads()
            observer.stop()
            observer.join()
    finally:
        session.close()


if __name__ == "__main__":
    main()
