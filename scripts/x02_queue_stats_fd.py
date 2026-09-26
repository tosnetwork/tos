"""Fail-closed validation and fresh reads of the broker's private proc descriptor."""
import ctypes
import fcntl
import json
import os
import stat
from pathlib import Path

PROC = "/proc/self/net/netfilter/nfnetlink_queue"
CAPS = 0x3000


def require(condition, message):
    if not condition:
        raise ValueError(message)


def bounded_read(fd, limit):
    os.lseek(fd, 0, os.SEEK_SET)
    chunks, size = [], 0
    while True:
        raw = os.read(fd, min(4096, limit + 1 - size))
        if not raw:
            return b"".join(chunks)
        chunks.append(raw)
        size += len(raw)
        require(size <= limit, "descriptor payload exceeds bound")


class QueueStatsFD:
    def __init__(self, fd, receipt_fd, host_netns):
        require((fd, receipt_fd) == (3, 4), "fixed inherited descriptors required")
        self.fd, self.receipt_fd, self.host_netns = fd, receipt_fd, host_netns
        receipt = os.fstat(receipt_fd)
        require(stat.S_ISREG(receipt.st_mode) and receipt.st_uid == receipt.st_gid == 0
                and stat.S_IMODE(receipt.st_mode) == 0o400
                and fcntl.fcntl(receipt_fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
                and fcntl.fcntl(receipt_fd, fcntl.F_GET_SEALS) == 15,
                "receipt identity/permissions/seals differ")
        self.receipt = json.loads(bounded_read(receipt_fd, 4096))
        require(self.receipt["schema"] == "tos.x02.queue-stats-fd.v1"
                and self.receipt["broker_pid"] == os.getpid()
                and self.receipt["broker_euid"] == 0
                and self.receipt["entry_caps"] == 0x31c0
                and self.receipt["worker_uid"] == self.receipt["worker_gid"] == 1000
                and self.receipt["worker_caps"] == CAPS,
                "handoff identity differs")
        self.identity = (self.receipt["proc_dev"], self.receipt["proc_inode"])
        self.validate()

    def validate(self):
        require(os.getresuid() == (1000, 1000, 1000)
                and os.getresgid() == (1000, 1000, 1000) and os.getgroups() == [],
                "ordinary final credentials differ")
        status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
                      if ":" in line)
        require(all(int(status[key], 16) == CAPS for key in
                    ("CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd"))
                and int(status["NoNewPrivs"]) == 1, "final capabilities/NNP differ")
        net = os.stat("/proc/self/ns/net")
        user = os.stat("/proc/self/ns/user")
        require(os.readlink("/proc/self/ns/net") != self.host_netns
                and net.st_ino == self.receipt["netns_inode"]
                and user.st_ino == self.receipt["owner_userns_inode"]
                and self.receipt["owner_uid"] == 0, "private namespace continuity differs")
        current = os.fstat(self.fd)
        named = os.stat(PROC)
        require((current.st_dev, current.st_ino) == self.identity
                == (named.st_dev, named.st_ino)
                and stat.S_ISREG(current.st_mode) and current.st_uid == current.st_gid == 0
                and stat.S_IMODE(current.st_mode) == self.receipt["proc_mode"] == 0o440
                and self.receipt["proc_uid"] == self.receipt["proc_gid"] == 0
                and fcntl.fcntl(self.fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
                and not fcntl.fcntl(self.fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC,
                "proc descriptor identity/permissions/inheritance differ")
        libc = ctypes.CDLL(None, use_errno=True)
        buffer = ctypes.create_string_buffer(256)
        require(libc.fstatfs(self.fd, ctypes.byref(buffer)) == 0, "fstatfs failed")
        magic = ctypes.c_long.from_buffer(buffer).value
        require(magic == self.receipt["procfs_magic"] == 0x9fa0, "not kernel procfs")
        start = Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()[19]
        require(start == self.receipt["startticks"], "process start identity differs")

    def read(self):
        self.validate()
        return bounded_read(self.fd, 65536)

    def inverse_controls(self, ledger):
        # Real descriptor substitution; restoration is mandatory before any network setup.
        saved = os.dup(self.fd)
        fake = os.memfd_create("x02-fake-stats", os.MFD_CLOEXEC)
        try:
            for case in ("missing", "fake", "writable"):
                if case == "missing":
                    os.close(self.fd)
                elif case == "fake":
                    readonly = os.open(f"/proc/self/fd/{fake}", os.O_RDONLY)
                    try:
                        os.dup2(readonly, self.fd)
                    finally:
                        os.close(readonly)
                else:
                    os.dup2(fake, self.fd)
                try:
                    self.validate()
                except (OSError, ValueError) as error:
                    ledger.append({"event": "fd_guard_rejected", "case": case, "error": str(error)})
                else:
                    raise ValueError("invalid descriptor guard failed: " + case)
                finally:
                    os.dup2(saved, self.fd)
            original = self.receipt["netns_inode"]
            self.receipt["netns_inode"] = original + 1
            try:
                self.validate()
            except ValueError as error:
                require(str(error) == "private namespace continuity differs", "wrong namespace guard reason")
                ledger.append({"event": "fd_guard_rejected", "case": "wrong-namespace", "error": str(error)})
            else:
                raise ValueError("wrong namespace guard failed")
            finally:
                self.receipt["netns_inode"] = original
            self.validate()
        finally:
            os.dup2(saved, self.fd)
            os.close(saved)
            os.close(fake)

    def close(self):
        os.close(self.fd)
        os.close(self.receipt_fd)
