# SPDX-License-Identifier: LGPL-2.1-or-later
import contextlib
import dataclasses
import os
import shutil
import sys
import uuid
from collections.abc import Iterator, Sequence
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Optional, Protocol

# Import mkosi.cage so we can figure out its path which we need to be able to execute it.
import mkosi.cage
from mkosi.types import PathString
from mkosi.user import INVOKING_USER
from mkosi.util import flatten, one_zero


@dataclasses.dataclass(frozen=True)
class Mount:
    src: PathString
    dst: PathString
    ro: bool = False
    required: bool = True

    def __hash__(self) -> int:
        return hash((Path(self.src), Path(self.dst), self.ro, self.required))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Mount):
            return False

        return self.__hash__() == other.__hash__()

    def options(self) -> list[str]:
        if self.ro:
            opt = "--ro-bind" if self.required else "--ro-bind-try"
        else:
            opt = "--bind" if self.required else "--bind-try"

        return [opt, os.fspath(self.src), os.fspath(self.dst)]


class SandboxProtocol(Protocol):
    def __call__(
        self,
        *,
        binary: Optional[PathString],
        vartmp: bool = False,
        mounts: Sequence[Mount] = (),
    ) -> AbstractContextManager[list[PathString]]: ...


def nosandbox(
    *,
    binary: Optional[PathString],
    vartmp: bool = False,
    mounts: Sequence[Mount] = (),
) -> AbstractContextManager[list[PathString]]:
    return contextlib.nullcontext([])


def finalize_passwd_mounts(root: PathString) -> list[Mount]:
    """
    If passwd or a related file exists in the apivfs directory, bind mount it over the host files while we
    run the command, to make sure that the command we run uses user/group information from the apivfs
    directory instead of from the host.
    """
    return [
        Mount(Path(root) / "etc" / f, f"/etc/{f}", ro=True, required=False)
        for f in ("passwd", "group", "shadow", "gshadow")
    ]


def finalize_mounts(mounts: Sequence[Mount]) -> list[PathString]:
    mounts = list(set(mounts))

    mounts = [
        m for m in mounts
        if not any(
            m != n and
            m.ro == n.ro and
            m.required == n.required and
            Path(m.src).is_relative_to(n.src) and
            Path(m.dst).is_relative_to(n.dst) and
            Path(m.src).relative_to(n.src) == Path(m.dst).relative_to(n.dst)
            for n in mounts
        )
    ]

    return flatten(m.options() for m in mounts)


def network_options(*, network: bool) -> list[PathString]:
    return [
        "--setenv", "SYSTEMD_OFFLINE", one_zero(network),
        *(["--unshare-net"] if not network else []),
    ]


@contextlib.contextmanager
def sandbox_cmd(
    *,
    network: bool = False,
    devices: bool = False,
    vartmp: bool = False,
    scripts: Optional[Path] = None,
    tools: Path = Path("/"),
    relaxed: bool = False,
    mounts: Sequence[Mount] = (),
    usroverlaydirs: Sequence[PathString] = (),
    options: Sequence[PathString] = (),
    setup: Sequence[PathString] = (),
) -> Iterator[list[PathString]]:
    cmdline: list[PathString] = []
    mounts = list(mounts)

    if vartmp and not relaxed:
        # We want to use an empty subdirectory in the host's temporary directory as the sandbox's /var/tmp.
        vartmpdir = Path(os.getenv("TMPDIR", "/var/tmp")) / f"mkosi-var-tmp-{uuid.uuid4().hex[:16]}"
    else:
        vartmpdir = None

    cmdline += [
        *setup,
        sys.executable, "-SI", mkosi.cage.__file__,
        "--proc", "/proc",
        # We mounted a subdirectory of TMPDIR to /var/tmp so we unset TMPDIR so that /tmp or /var/tmp are used instead.
        "--unsetenv", "TMPDIR",
        *network_options(network=network),
    ]

    mounts += [
        # apivfs_cmd() and chroot_cmd() are executed from within the sandbox, but they still use cage.py, so we make
        # sure it is available inside the sandbox so it can be executed there as well.
        Mount(Path(mkosi.cage.__file__), "/cage.py", ro=True)
    ]

    if usroverlaydirs:
        cmdline += ["--overlay-src", tools / "usr"]

        for d in usroverlaydirs:
            cmdline += ["--overlay-src", d]

        cmdline += ["--overlay", "/usr"]
    else:
        mounts += Mount(tools / "usr", "/usr", ro=True),

    if relaxed:
        mounts += [Mount("/tmp", "/tmp")]
    else:
        cmdline += ["--dir", "/tmp", "--dir", "/var/tmp", "--unshare-ipc"]

    if (tools / "nix/store").exists():
        mounts += [Mount(tools / "nix/store", "/nix/store")]

    if devices or relaxed:
        mounts += [
            Mount("/sys", "/sys"),
            Mount("/run", "/run"),
            Mount("/dev", "/dev"),
        ]
    else:
        cmdline += ["--dev", "/dev"]

    if relaxed:
        dirs = ("/etc", "/opt", "/srv", "/media", "/mnt", "/var", os.fspath(INVOKING_USER.home()))

        for d in dirs:
            if Path(d).exists():
                mounts += [Mount(d, d)]

        if len(Path.cwd().parents) >= 2:
            # `Path.parents` only supports slices and negative indexing from Python 3.10 onwards.
            # TODO: Remove list() when we depend on Python 3.10 or newer.
            d = os.fspath(list(Path.cwd().parents)[-2])
        elif len(Path.cwd().parents) == 1:
            d = os.fspath(Path.cwd())
        else:
            d = ""

        if d and d not in (*dirs, "/home", "/usr", "/nix", "/tmp"):
            mounts += [Mount(d, d)]

    if vartmpdir:
        mounts += [Mount(vartmpdir, "/var/tmp")]

    for d in ("bin", "sbin", "lib", "lib32", "lib64"):
        if (p := tools / d).is_symlink():
            cmdline += ["--symlink", p.readlink(), Path('/') / p.relative_to(tools)]
        elif p.is_dir():
            mounts += [Mount(p, Path("/") / p.relative_to(tools), ro=True)]

    path = "/usr/bin:/usr/sbin" if tools != Path("/") else os.environ["PATH"]

    cmdline += ["--setenv", "PATH", f"/scripts:{path}", *options]

    # If we're using /usr from a tools tree, we have to use /etc/alternatives from the tools tree as well if it
    # exists since that points directly back to /usr. Apply this after the options so the caller can mount
    # something else to /etc without overriding this mount. In relaxed mode, we only do this if /etc/alternatives
    # already exists on the host as otherwise we'd modify the host's /etc by creating the mountpoint ourselves (or
    # fail when trying to create it).
    if (tools / "etc/alternatives").exists() and (not relaxed or Path("/etc/alternatives").exists()):
        mounts += [Mount(tools / "etc/alternatives", "/etc/alternatives", ro=True)]

    if scripts:
        mounts += [Mount(scripts, "/scripts", ro=True)]

    if network and not relaxed and Path("/etc/resolv.conf").exists():
        mounts += [Mount("/etc/resolv.conf", "/etc/resolv.conf")]

    cmdline += finalize_mounts(mounts)

    if not any(Path(m.dst) == Path("/etc") for m in mounts):
        cmdline += ["--symlink", "../proc/self/mounts", "/etc/mtab"]

    cmdline = [*cmdline, "--"]

    if vartmpdir:
        vartmpdir.mkdir(mode=0o1777)

    try:
        yield cmdline
    finally:
        if vartmpdir:
            shutil.rmtree(vartmpdir)


def apivfs_options(*, root: Path = Path("/buildroot")) -> list[PathString]:
    return [
        "--tmpfs", root / "run",
        "--tmpfs", root / "tmp",
        "--bind", "/var/tmp", root / "var/tmp",
        "--proc", root / "proc",
        "--dev", root / "dev",
        # Nudge gpg to create its sockets in /run by making sure /run/user/0 exists.
        "--dir", root / "run/user/0",
        # Make sure anything running in the root directory thinks it's in a container. $container can't always
        # be accessed so we write /run/host/container-manager as well which is always accessible.
        "--write", "mkosi", root / "run/host/container-manager",
    ]


def apivfs_script_cmd(*, tools: bool, options: Sequence[PathString] = ()) -> list[PathString]:
    return [
        "python3" if tools else sys.executable, "-SI", "/cage.py",
        "--bind", "/", "/",
        "--same-dir",
        *apivfs_options(),
        *options,
        "--",
    ]


def chroot_options(*, network: bool = False) -> list[PathString]:
    return [
        # Let's always run as (fake) root when we chroot inside the image as tools executed within the image could
        # have builtin assumptions about files being owned by root.
        "--become-root",
        # Unshare IPC namespace so any tests that exercise IPC related features don't fail with permission errors as
        # --become-root implies unsharing a user namespace which won't have access to the parent's IPC namespace
        # anymore.
        "--unshare-ipc",
        "--setenv", "container", "mkosi",
        "--setenv", "HOME", "/",
        "--setenv", "PATH", "/usr/bin:/usr/sbin",
        *(["--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf"] if network else []),
        "--setenv", "BUILDROOT", "/",
    ]


@contextlib.contextmanager
def chroot_cmd(
    *,
    root: Path,
    network: bool = False,
    mounts: Sequence[Mount] = (),
    options: Sequence[PathString] = (),
) -> Iterator[list[PathString]]:
    # We want to use an empty subdirectory in the host's temporary directory as the sandbox's /var/tmp.
    vartmpdir = Path(os.getenv("TMPDIR", "/var/tmp")) / f"mkosi-var-tmp-{uuid.uuid4().hex[:16]}"

    if vartmpdir:
        vartmpdir.mkdir(mode=0o1777)

    cmdline: list[PathString] = [
        sys.executable, "-SI", mkosi.cage.__file__,
        "--bind", root, "/",
        "--bind", vartmpdir, "/var/tmp",
        # We mounted a subdirectory of TMPDIR to /var/tmp so we unset TMPDIR so that /tmp or /var/tmp are used instead.
        "--unsetenv", "TMPDIR",
        *network_options(network=network),
        *apivfs_options(root=Path("/")),
        *chroot_options(network=network),
        *finalize_mounts(mounts),
        *options,
    ]

    if network and Path("/etc/resolv.conf").exists():
        cmdline += ["--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf"]

    try:
        yield cmdline + ["--"]
    finally:
        if vartmpdir:
            shutil.rmtree(vartmpdir)


def chroot_script_cmd(*, tools: bool, network: bool = False, work: bool = False) -> list[PathString]:
    return [
        "python3" if tools else sys.executable, "-SI", "/cage.py",
        "--bind", "/buildroot", "/",
        *apivfs_options(root=Path("/")),
        *chroot_options(network=network),
        *(["--bind", "/work", "/work", "--chdir", "/work/src"] if work else []),
        "--",
    ]
