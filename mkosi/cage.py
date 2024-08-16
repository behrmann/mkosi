# SPDX-License-Identifier: LGPL-2.1-or-later

"""
This is a standalone implementation of sandboxing which is used by mkosi. Note that this is invoked many times while
building the image and as a result, the performance of this script has a substantial impact on the performance of mkosi
itself. To keep the runtime of this script to a minimum, please don't import any extra modules if it can be avoided.
"""

import ctypes
import os
import sys
import warnings  # noqa: F401 (loaded lazily by os.execvp() which happens too late)

# The following constants are taken from the Linux kernel headers.
AT_EMPTY_PATH = 0x1000
AT_FDCWD = -100
AT_NO_AUTOMOUNT = 0x800
AT_RECURSIVE = 0x8000
AT_SYMLINK_NOFOLLOW = 0x100
BTRFS_SUPER_MAGIC = 0x9123683E
CAP_NET_ADMIN = 12
CAP_SYS_ADMIN = 21
CLONE_NEWIPC = 0x08000000
CLONE_NEWNET = 0x40000000
CLONE_NEWNS = 0x00020000
CLONE_NEWUSER = 0x10000000
ENOENT = 2
LINUX_CAPABILITY_U32S_3 = 2
LINUX_CAPABILITY_VERSION_3 = 0x20080522
MNT_DETACH = 2
MOUNT_ATTR_RDONLY = 0x00000001
MOUNT_ATTR_NOSUID = 0x00000002
MOUNT_ATTR_NODEV = 0x00000004
MOUNT_ATTR_NOEXEC = 0x00000008
MOUNT_ATTR_SIZE_VER0 = 32
MOVE_MOUNT_F_EMPTY_PATH = 0x00000004
MS_BIND = 4096
MS_MOVE = 8192
MS_REC = 16384
MS_SHARED = 1 << 20
MS_SLAVE = 1 << 19
NR_mount_setattr = 442
NR_move_mount = 429
NR_open_tree = 428
OPEN_TREE_CLOEXEC = os.O_CLOEXEC
OPEN_TREE_CLONE = 1
PR_CAP_AMBIENT = 47
PR_CAP_AMBIENT_RAISE = 2
# These definitions are taken from the libseccomp headers
SCMP_ACT_ALLOW = 0x7FFF0000
SCMP_ACT_ERRNO = 0x00050000

class mount_attr(ctypes.Structure):
    _fields_ = [
        ("attr_set", ctypes.c_uint64),
        ("attr_clr", ctypes.c_uint64),
        ("propagation", ctypes.c_uint64),
        ("userns_fd", ctypes.c_uint64),
    ]

class cap_user_header_t(ctypes.Structure):
    # __user_cap_header_struct
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("pid", ctypes.c_int),
    ]

class cap_user_data_t(ctypes.Structure):
    # __user_cap_data_struct
    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    ]

libc = ctypes.CDLL(None, use_errno=True)

libc.syscall.restype = ctypes.c_long
libc.unshare.argtypes = (ctypes.c_int,)
libc.statfs.argtypes = (ctypes.c_char_p, ctypes.c_void_p)
libc.eventfd.argtypes = (ctypes.c_int, ctypes.c_int)
libc.mount.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p)
libc.pivot_root.argtypes = (ctypes.c_char_p, ctypes.c_char_p)
libc.umount2.argtypes = (ctypes.c_char_p, ctypes.c_int)
libc.capget.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
libc.capset.argtypes = (ctypes.c_void_p, ctypes.c_void_p)


def oserror(filename: str = "") -> None:
    raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()), filename or None)


def unshare(flags: int) -> None:
    if libc.unshare(flags) < 0:
        oserror()


def statfs(path: str) -> int:
    # struct statfs is 120 bytes, which equals 15 longs. Since we only care about the first field and the first field
    # is of type long, we avoid declaring the full struct by just passing an array of 15 longs as the output argument.
    buffer = (ctypes.c_long * 15)()

    if libc.statfs(path.encode(), ctypes.byref(buffer)) < 0:
        oserror()

    return int(buffer[0])


def mount(src: str, dst: str, type: str, flags: int, options: str) -> None:
    srcb = src.encode() if src else None
    typeb = type.encode() if type else None
    optionsb = options.encode() if options else None
    if libc.mount(srcb, dst.encode(), typeb, flags, optionsb) < 0:
        oserror()


def umount2(path: str, flags: int = 0) -> None:
    if libc.umount2(path.encode(), flags) < 0:
        oserror()


def cap_permitted_to_ambient() -> None:
    """
    When unsharing a user namespace and mapping the current user to itself, the user has a full set of capabilities in
    the user namespace. This allows the user to do mounts after unsharing a mount namespace for example. However, these
    capabilities are lost again when the user executes a subprocess. As we also want subprocesses invoked by the user
    to be able to mount stuff, we make sure the capabilities are inherited by adding all the user's capabilities to the
    inherited and ambient capabilities set, which makes sure that they are passed down to subprocesses.
    """
    header = cap_user_header_t(LINUX_CAPABILITY_VERSION_3, 0)
    payload = (cap_user_data_t * LINUX_CAPABILITY_U32S_3)()

    if libc.capget(ctypes.addressof(header), ctypes.byref(payload)) < 0:
        oserror()

    payload[0].inheritable = payload[0].permitted
    payload[1].inheritable = payload[1].permitted

    if libc.capset(ctypes.addressof(header), ctypes.byref(payload)) < 0:
        oserror()

    effective = payload[1].effective << 32 | payload[0].effective

    with open("/proc/sys/kernel/cap_last_cap", "rb") as f:
        last_cap = int(f.read())

    libc.prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong)

    for cap in range(ctypes.sizeof(ctypes.c_uint64) * 8):
        if cap > last_cap:
            break

        if effective & (1 << cap) and libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0) < 0:
            oserror()


def have_effective_cap(capability: int) -> bool:
    with open("/proc/self/status", "rb") as f:
        for line in f.readlines():
            if line.startswith(b"CapEff:"):
                return (int(line[7:], 16) & (1 << capability)) != 0

    return False


def seccomp_suppress_chown() -> None:
    """
    There's still a few files and directories left in distributions in /usr and /etc that are not owned by root. This
    causes package managers to fail to install the corresponding packages when run from a single uid user namespace.
    Unfortunately, non-root users can only create files owned by their own uid. To still allow non-root users to build
    images, if requested we install a seccomp filter that makes calls to chown() and friends a noop.
    """
    libseccomp = ctypes.CDLL("libseccomp.so.2")
    if libseccomp is None:
        raise FileNotFoundError("libseccomp.so.2")

    libseccomp.seccomp_init.argtypes = (ctypes.c_uint32,)
    libseccomp.seccomp_init.restype = ctypes.c_void_p
    libseccomp.seccomp_release.argtypes = (ctypes.c_void_p,)
    libseccomp.seccomp_release.restype = None
    libseccomp.seccomp_syscall_resolve_name.argtypes = (ctypes.c_char_p,)
    libseccomp.seccomp_rule_add_exact.argtypes = (ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint)
    libseccomp.seccomp_load.argtypes = (ctypes.c_void_p,)

    seccomp = libseccomp.seccomp_init(SCMP_ACT_ALLOW)

    try:
        for syscall in (b"chown", b"chown32", b"fchown", b"fchown32", b"fchownat", b"lchown", b"lchown32"):
            id = libseccomp.seccomp_syscall_resolve_name(syscall)
            libseccomp.seccomp_rule_add_exact(seccomp, SCMP_ACT_ERRNO, id, 0)

            libseccomp.seccomp_load(seccomp)
    finally:
        libseccomp.seccomp_release(seccomp)


def mount_rbind(src: str, dst: str, attrs: int = 0) -> None:
    """
    When using the old mount syscall to do a recursive bind mount, mount options are not applied recursively. Because
    we want to do recursive read-only bind mounts in some cases, we use the new mount API for that which does allow
    recursively changing mount options when doing bind mounts.
    """

    flags = AT_NO_AUTOMOUNT|AT_RECURSIVE|AT_SYMLINK_NOFOLLOW|OPEN_TREE_CLONE

    try:
        libc.open_tree.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        fd = libc.open_tree(AT_FDCWD, src.encode(), flags)
    except AttributeError:
        libc.syscall.argtypes = (ctypes.c_long, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        fd = libc.syscall(NR_open_tree, AT_FDCWD, src.encode(), flags)

    if fd < 0:
        oserror(src)

    try:
        attr = mount_attr()
        attr.attr_set = attrs

        flags = AT_EMPTY_PATH|AT_RECURSIVE

        try:
            libc.mount_setattr.argtypes = (
                ctypes.c_int, ctypes.c_char_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_size_t,
            )
            r = libc.mount_setattr(fd, b"", flags, ctypes.addressof(attr), MOUNT_ATTR_SIZE_VER0)
        except AttributeError:
            libc.syscall.argtypes = (
                ctypes.c_long, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_size_t,
            )
            r = libc.syscall(NR_mount_setattr, fd, b"", flags, ctypes.addressof(attr), MOUNT_ATTR_SIZE_VER0)

        if r < 0:
            oserror(src)

        try:
            libc.move_mount.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
            r = libc.move_mount(fd, b"", AT_FDCWD, dst.encode(), MOVE_MOUNT_F_EMPTY_PATH)
        except AttributeError:
            libc.syscall.argtypes = (
                ctypes.c_long, ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint,
            )
            r = libc.syscall(NR_move_mount, fd, b"", AT_FDCWD, dst.encode(), MOVE_MOUNT_F_EMPTY_PATH)

        if r < 0:
            oserror(dst)
    finally:
        os.close(fd)


class umask:
    def __init__(self, mask: int):
        self.mask = mask

    def __enter__(self) -> None:
        self.mask = os.umask(self.mask)

    def __exit__(self, *args: object, **kwargs: object) -> None:
        os.umask(self.mask)


def become_user(uid: int, gid: int) -> None:
    """
    This function implements the required dance to unshare a user namespace and map the current user to itself or to
    root within it. The kernel only allows a process running outside of the unshared user namespace to write the
    necessary uid and gid mappings, so we fork off a child process, make it wait until the parent process has unshared
    a user namespace, and then writes the necessary uid and gid mappings.
    """
    ppid = os.getpid()

    event = libc.eventfd(0, 0)
    if event < 0:
        oserror()

    pid = os.fork()
    if pid == 0:
        try:
            os.read(event, ctypes.sizeof(ctypes.c_uint64))
            os.close(event)
            with open(f"/proc/{ppid}/setgroups", "wb") as f:
                f.write(b"deny\n")
            with open(f"/proc/{ppid}/gid_map", "wb") as f:
                f.write(f"{gid} {os.getgid()} 1\n".encode())
            with open(f"/proc/{ppid}/uid_map", "wb") as f:
                f.write(f"{uid} {os.getuid()} 1\n".encode())
        except OSError as e:
            os._exit(e.errno)
        except BaseException:
            os._exit(1)
        else:
            os._exit(0)

    try:
        unshare(CLONE_NEWUSER)
    finally:
        os.write(event, ctypes.c_uint64(1))
        os.close(event)
        _, status = os.waitpid(pid, 0)

    rc = os.waitstatus_to_exitcode(status)
    if rc != 0:
        raise OSError(rc, os.strerror(rc))


def acquire_privileges(*, become_root: bool = False) -> bool:
    if os.getuid() == 0 or (not become_root and have_effective_cap(CAP_SYS_ADMIN)):
        return False

    if become_root:
        become_user(0, 0)
    else:
        become_user(os.getuid(), os.getgid())
        cap_permitted_to_ambient()

    return True


def userns_has_single_user() -> bool:
    try:
        with open("/proc/self/uid_map", "rb") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return False

    return len(lines) == 1 and int(lines[0].split()[-1]) == 1


def resolve(root: str, path: str) -> str:
    fd = os.open("/", os.O_CLOEXEC|os.O_PATH|os.O_DIRECTORY)

    try:
        os.chroot(root)
        os.chdir("/")
        return os.path.join(root, os.path.realpath(path).lstrip("/"))
    finally:
        os.fchdir(fd)
        os.close(fd)
        os.chroot(".")


def splitpath(path: str) -> tuple[str, ...]:
    return tuple(p for p in path.split("/") if p)


def pop_all(list: list[str]) -> list[str]:
    result = []

    while list:
        result.append(list.pop())

    return result


def do_mount(operation: str, args: tuple[str, ...]) -> None:
    src, dst = args
    src = resolve("oldroot", src)
    dst = resolve("newroot", dst)

    if not os.path.exists(src) and operation.endswith("-try"):
        return

    with umask(~0o755):
        os.makedirs(os.path.dirname(dst), exist_ok=True)

    if not os.path.exists(dst):
        isfile = os.path.isfile(src)

        with umask(~0o644 if isfile else ~0o755):
            if isfile:
                os.close(os.open(dst, os.O_CREAT|os.O_CLOEXEC))
            else:
                os.mkdir(dst)

    mount_rbind(src, dst, attrs=MOUNT_ATTR_RDONLY if operation.startswith("--ro") else 0)


def do_proc(operation: str, args: tuple[str, ...]) -> None:
    dst = resolve("newroot", args[0])
    with umask(~0o755):
        os.makedirs(dst, exist_ok=True)

    mount_rbind("oldroot/proc", dst)


TTYNAME = os.ttyname(2) if os.isatty(2) else None


def do_dev(operation: str, args: tuple[str, ...]) -> None:
    # We don't put actual devices in /dev, just the API stuff in there that all manner of things depend on,
    # like /dev/null.
    dst = resolve("newroot", args[0])
    with umask(~0o755):
        os.makedirs(dst, exist_ok=True)

    # Note that the mode is curcial here. If the default mode (1777) is used, trying to access /dev/null fails
    # with EACCESS for unknown reasons.
    mount("tmpfs", dst, "tmpfs", 0, "mode=0755")

    for node in ("null", "zero", "full", "random", "urandom", "tty"):
        ndst = f"{dst}/{node}"
        os.close(os.open(ndst, os.O_CREAT|os.O_CLOEXEC))

        mount(f"oldroot/dev/{node}", ndst, "", MS_BIND, "")

    for i, node in enumerate(("stdin", "stdout", "stderr")):
        os.symlink(f"/proc/self/fd/{i}", f"{dst}/{node}")

    os.symlink("/proc/self/fd", f"{dst}/fd")
    os.symlink("/proc/kcore", f"{dst}/core")

    with umask(~0o1777):
        os.mkdir(f"{dst}/shm", mode=0o1777)
    with umask(~0o755):
        os.mkdir(f"{dst}/pts")

    mount("devpts", f"{dst}/pts", "devpts", 0, "newinstance,ptmxmode=0666,mode=620")

    os.symlink("pts/ptmx", f"{dst}/ptmx")

    if TTYNAME:
        os.close(os.open(f"{dst}/console", os.O_CREAT|os.O_CLOEXEC))
        mount(f"oldroot/{TTYNAME}", f"{dst}/console", "", MS_BIND, "")


def do_tmpfs(operation: str, args: tuple[str, ...]) -> None:
    dst = resolve("newroot", args[0])
    with umask(~0o755):
        os.makedirs(dst, exist_ok=True)

    options = "" if any(dst.endswith(suffix) for suffix in ("/tmp", "/var/tmp")) else "mode=0755"
    mount("tmpfs", dst, "tmpfs", 0, options)


def do_dir(operation: str, args: tuple[str, ...]) -> None:
    dst = resolve("newroot", args[0])
    with umask(~0o755):
        os.makedirs(os.path.dirname(dst), exist_ok=True)

    mode = 0o1777 if any(dst.endswith(suffix) for suffix in ("/tmp", "/var/tmp")) else 0o755
    if not os.path.exists(dst):
        with umask(~mode):
            os.mkdir(dst, mode=mode)


def do_symlink(operation: str, args: tuple[str, ...]) -> None:
    src, dst = args
    os.symlink(src, f"newroot/{dst}")


def do_write(operation: str, args: tuple[str, ...]) -> None:
    data, dst = args
    dst = resolve("newroot", dst)
    with umask(~0o755):
        os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "wb") as f:
        f.write(data.encode())


def do_overlay(operation: str, args: tuple[str, ...]) -> None:
    srcs, dst = args[:-1], args[-1]
    srcs = tuple(resolve("oldroot", p) for p in srcs)
    dst = resolve("newroot", dst)
    with umask(~0o755):
        os.makedirs(dst, exist_ok=True)

    mount("overlayfs", dst, "overlay", 0, f"lowerdir={':'.join(srcs)}")


def do_fsops(fsops: list[tuple[str, tuple[str, ...]]]) -> None:
    lookup = {
        "bind"        : do_mount,
        "ro-bind"     : do_mount,
        "bind-try"    : do_mount,
        "ro-bind-try" : do_mount,
        "proc"        : do_proc,
        "dev"         : do_dev,
        "tmpfs"       : do_tmpfs,
        "dir"         : do_dir,
        "symlink"     : do_symlink,
        "write"       : do_write,
        "overlay"     : do_overlay,
    }

    for operation, args in fsops:
        lookup[operation](operation, args)


ARG_BECOME_ROOT = 1 << 0
ARG_SUPPRESS_CHOWN = 1 << 1
ARG_UNSHARE_NET= 1 << 2
ARG_UNSHARE_IPC = 1 << 3


def main() -> None:
    # We don't use argparse as it takes +- 10ms to import and since this is purely for internal use, it's not necessary
    # to have good UX for this CLI interface so it's trivial to write ourselves.
    argv = list(reversed(sys.argv[1:]))
    fsops: list[tuple[str, tuple[str, ...]]] = []
    setenv = []
    unsetenv = []
    lowerdirs = []
    chdir = None
    flags = 0

    def parse_fsops_one(arg: str) -> None:
        fsops.append((arg, (argv.pop(),)))

    def parse_fsops_two(arg: str) -> None:
        fsops.append((arg, (argv.pop(), argv.pop())))

    def parse_chdir(arg: str) -> None:
        nonlocal chdir
        chdir = argv.pop()

    def parse_same_dir(arg: str) -> None:
        nonlocal chdir
        chdir = os.getcwd()

    def parse_flag(arg: str) -> None:
        nonlocal flags
        flags |= {
            "become-root"    : ARG_BECOME_ROOT,
            "suppress-chown" : ARG_SUPPRESS_CHOWN,
            "unshare-net"    : ARG_UNSHARE_NET,
            "unshare-ipc"    : ARG_UNSHARE_IPC,
        }[arg]

    lookup = {
        "--tmpfs"          : parse_fsops_one,
        "--dev"            : parse_fsops_one,
        "--proc"           : parse_fsops_one,
        "--dir"            : parse_fsops_one,
        "--bind"           : parse_fsops_two,
        "--ro-bind"        : parse_fsops_two,
        "--bind-try"       : parse_fsops_two,
        "--ro-bind-try"    : parse_fsops_two,
        "--symlink"        : parse_fsops_two,
        "--write"          : parse_fsops_two,
        "--overlay-src"    : lambda arg: lowerdirs.append(argv.pop()),
        "--overlay"        : lambda arg: fsops.append((arg, (*pop_all(lowerdirs), argv.pop()))),
        "--unsetenv"       : lambda arg: unsetenv.append(argv.pop()),
        "--setenv"         : lambda arg: setenv.append((argv.pop(), argv.pop())),
        "--chdir"          : parse_chdir,
        "--same-dir"       : parse_same_dir,
        "--become-root"    : parse_flag,
        "--suppress-chown" : parse_flag,
        "--unshare-net"    : parse_flag,
        "--unshare-ipc"    : parse_flag,
    }

    while len(argv) > 0:
        arg = argv.pop()

        if arg == '--':
            break

        if parse := lookup.get(arg):
            parse(arg.removeprefix("--"))
        else:
            argv.append(arg)
            break

    argv.reverse()

    if len(argv) == 0:
        argv = ["bash"]

    # Make sure all destination paths are absolute.
    for option, args in fsops:
        assert args[-1][0] == "/"

    # Sort file system operations by destination path.
    fsops.sort(key=lambda i: splitpath(i[-1][-1]))

    for k, v in setenv:
        os.environ[k] = v

    for e in unsetenv:
        if e in os.environ:
            del os.environ[e]

    # If $LISTEN_FDS is in the environment, let's automatically set $LISTEN_PID to the correct pid as well.
    if "LISTEN_FDS" in os.environ:
        os.environ["LISTEN_PID"] = str(os.getpid())

    namespaces = CLONE_NEWNS
    if flags & ARG_UNSHARE_NET and have_effective_cap(CAP_NET_ADMIN):
        namespaces |= CLONE_NEWNET
    if flags & ARG_UNSHARE_IPC:
        namespaces |= CLONE_NEWIPC

    userns = acquire_privileges(become_root=bool(flags & ARG_BECOME_ROOT))

    # If we're root in a user namespace with a single user, we're still not going to be able to chown() stuff, so check
    # for that and apply the seccomp filter as well in that case.
    if flags & ARG_SUPPRESS_CHOWN and (userns or userns_has_single_user()):
        seccomp_suppress_chown()

    unshare(namespaces)

    # If we unshared the user namespace the mount propagation of root is changed to slave automatically.
    if not userns:
        mount("", "/", "", MS_SLAVE|MS_REC, "")

    # We need a workspace to setup the sandbox, the easiest way to do this in a tmpfs, since it's automatically cleaned
    # up. We need a mountpoint to put the workspace on and it can't be root, so let's use /tmp which is almost
    # guaranteed to exist.
    mount("tmpfs", "/tmp", "tmpfs", 0, "")

    os.chdir("/tmp")

    with umask(~0o755):
        os.mkdir("newroot") # This is where we set up the sandbox rootfs
        os.mkdir("oldroot") # This is the old rootfs which is used as the source for mounts in the new rootfs.

    # Make sure that newroot is a mountpoint.
    mount("newroot", "newroot", "", MS_BIND|MS_REC, "")

    # Make the workspace in /tmp / and put the old rootfs in oldroot.
    if libc.pivot_root(b".", b"oldroot") < 0:
        # pivot_root() can fail in the initramfs since / isn't a mountpoint there', so let's fall back to MS_MOVE if
        # that's the case.

        # First we move the old rootfs to oldroot.
        mount("/", "oldroot", "", MS_BIND|MS_REC, "")

        # Then we move the workspace (/tmp) to /.
        mount(".", "/", "", MS_MOVE, "")

        # chroot and chdir to fully make the workspace the new root.
        os.chroot(".")
        os.chdir(".")

        # When we use MS_MOVE we have to unmount oldroot/tmp manually to reveal the original /tmp again as it might
        # contain stuff that we want to mount into the sandbox.
        umount2("oldroot/tmp", MNT_DETACH)

    do_fsops(fsops)

    # Now that we're done setting up the sandbox let's pivot root into newroot to make it the new root. We use the
    # pivot_root(".", ".") process described in the pivot_root() man page.

    os.chdir("newroot")

    # We're guaranteed to have / be a mount when we get here, so pivot_root() won't fail anymore, even if we're in the
    # initramfs.
    if libc.pivot_root(b".", b".") < 0:
        oserror()

    umount2(".", MNT_DETACH)

    # Avoid surprises by making sure the sandbox's mount propagation is shared. This doesn't actually mean mounts get
    # propagated into the host. Instead, a new mount propagation peer group is set up.
    mount("", ".", "", MS_SHARED|MS_REC, "")

    if chdir:
        os.chdir(chdir)

    try:
        os.execvp(argv[0], argv)
    except OSError as e:
        # Let's return a recognizable error when the binary we're going to execute is not found. We use 127 as that's
        # the exit code used by shells when a program to execute is not found.
        if e.errno == ENOENT:
            sys.exit(127)

        raise


if __name__ == "__main__":
    main()
