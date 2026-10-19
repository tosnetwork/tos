#define _GNU_SOURCE
/* Proposed root-owned launcher: delegate only one private proc read descriptor,
 * then exec the ordinary probe with exactly its original two capabilities.
 * Requires separately reviewed installation and explicit launcher authority. */
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <linux/memfd.h>
#include <linux/nsfs.h>
#include <linux/magic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>

#define TARGET_UID 1000
#define TARGET_GID 1000
#define WORKER_CAPS ((1U << CAP_NET_ADMIN) | (1U << CAP_NET_RAW))
#define ENTRY_CAPS (WORKER_CAPS | (1U << CAP_SETUID) | (1U << CAP_SETGID) | (1U << CAP_SETPCAP))

static void die(const char *message) {
  fprintf(stderr, "queue-stats broker: %s (errno=%d)\n", message, errno);
  exit(1);
}

static const char *option(int argc, char **argv, const char *key) {
  const char *value = NULL;
  for (int i = 1; i < argc; i += 2) {
    if (i + 1 >= argc) die("option missing value");
    if (!strcmp(argv[i], key)) {
      if (value) die("duplicate option");
      value = argv[i + 1];
    }
  }
  if (!value) die("required option missing");
  return value;
}

static void keep_fd(int fd, int target) {
  int saved = fcntl(fd, F_DUPFD_CLOEXEC, 10);
  if (saved < 0 || close(fd) || dup2(saved, target) < 0 || close(saved)) die("descriptor transfer");
  if (fcntl(target, F_SETFD, 0)) die("descriptor inheritance");
}

int main(int argc, char **argv) {
  uid_t ruid, euid, suid;
  gid_t rgid, egid, sgid;
  if (argc != 15 || getresuid(&ruid, &euid, &suid) || getresgid(&rgid, &egid, &sgid) ||
      ruid || euid || suid || rgid || egid || sgid) die("requires reviewed root launcher entry");
  const char *keys[] = {"--source-sha", "--host-netns", "--unit", "--run-id", "--case", "--output", "--driver-sha256"};
  for (int i = 1; i < argc; i += 2) {
    int known = 0;
    for (unsigned j = 0; j < sizeof(keys) / sizeof(keys[0]); ++j) known |= !strcmp(argv[i], keys[j]);
    if (!known) die("unknown option");
  }
  const char *source = option(argc, argv, "--source-sha");
  const char *host = option(argc, argv, "--host-netns");
  const char *unit = option(argc, argv, "--unit");
  const char *run = option(argc, argv, "--run-id");
  const char *test = option(argc, argv, "--case");
  const char *output = option(argc, argv, "--output");
  const char *driver_hash = option(argc, argv, "--driver-sha256");
  if (strlen(source) != 40 || strspn(source, "0123456789abcdef") != 40 ||
      strlen(driver_hash) != 64 || strspn(driver_hash, "0123456789abcdef") != 64 ||
      strlen(run) != 16 || strspn(run, "0123456789abcdef") != 16 ||
      strncmp(unit, "n6-heavy-x02-", 13) || strlen(unit) > 128 ||
      strspn(unit, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.") != strlen(unit) ||
      strncmp(output, "/datax/n6-unit-agents/X02/evidence/",
              sizeof("/datax/n6-unit-agents/X02/evidence/") - 1) ||
      strstr(output, "/../") || strstr(output, "/./") ||
      strspn(output, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/-_") != strlen(output))
    die("fixed argument boundary");
  if (strcmp(test, "positive") && strcmp(test, "install-race") &&
      strcmp(test, "wrong-flow") && strcmp(test, "late-ack")) die("unknown case");
  struct __user_cap_header_struct cap_header = {_LINUX_CAPABILITY_VERSION_3, 0};
  struct __user_cap_data_struct caps[2] = {{0}, {0}};
  if (syscall(SYS_capget, &cap_header, caps) || caps[0].effective != ENTRY_CAPS ||
      caps[0].permitted != ENTRY_CAPS || caps[0].inheritable ||
      caps[1].effective || caps[1].permitted || caps[1].inheritable ||
      prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) die("entry caps/no-new-privileges differ");
  for (int bit = 0; bit < 64; ++bit) {
    int present = prctl(PR_CAPBSET_READ, bit, 0, 0, 0);
    if (present < 0 && errno == EINVAL) break;
    if (present < 0 || present != (bit < 32 && (ENTRY_CAPS & (1U << bit)) != 0))
      die("entry bounding capabilities differ");
  }
  FILE *cgroup = fopen("/proc/self/cgroup", "r");
  char cgroup_line[4096];
  int in_unit = 0;
  if (!cgroup) die("cgroup evidence");
  while (fgets(cgroup_line, sizeof(cgroup_line), cgroup)) {
    size_t length = strcspn(cgroup_line, "\n");
    size_t unit_length = strlen(unit);
    if (length > unit_length && cgroup_line[length - unit_length - 1] == '/' &&
        !strncmp(cgroup_line + length - unit_length, unit, unit_length)) in_unit = 1;
  }
  if (fclose(cgroup) || !in_unit) die("outside fixed resource unit");
  int netfd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
  int userfd = open("/proc/self/ns/user", O_RDONLY | O_CLOEXEC);
  int ownerfd = netfd < 0 ? -1 : ioctl(netfd, NS_GET_USERNS);
  struct stat net, user, owner, proc, binary;
  unsigned owner_uid = ~0U;
  if (netfd < 0 || userfd < 0 || ownerfd < 0 || fstat(netfd, &net) ||
      fstat(userfd, &user) || fstat(ownerfd, &owner) ||
      ioctl(ownerfd, NS_GET_OWNER_UID, &owner_uid)) die("namespace owner evidence");
  char namespace_name[96];
  if (snprintf(namespace_name, sizeof(namespace_name), "net:[%lu]", (unsigned long)net.st_ino) < 0 ||
      !strcmp(host, namespace_name) || user.st_ino != owner.st_ino || owner_uid != 0)
    die("not reviewed private netns/initial owner namespace");
  if (stat("/proc/self/exe", &binary) || binary.st_uid != 0 ||
      !S_ISREG(binary.st_mode) || (binary.st_mode & 07777) != 0555) die("broker must be root-owned0555, not setuid");
  int stats = open("/proc/self/net/netfilter/nfnetlink_queue", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  struct statfs filesystem;
  if (stats < 0 || fstat(stats, &proc) || fstatfs(stats, &filesystem) ||
      !S_ISREG(proc.st_mode) || (proc.st_mode & 0777) != 0440 || proc.st_uid != 0 || proc.st_gid != 0 ||
      filesystem.f_type != PROC_SUPER_MAGIC || (fcntl(stats, F_GETFL) & O_ACCMODE) != O_RDONLY)
    die("fixed private proc identity/mode");
  int receipt = syscall(SYS_memfd_create, "x02-private-queue-stats", MFD_ALLOW_SEALING | MFD_CLOEXEC);
  if (receipt < 0) die("receipt memfd");
  FILE *process_stat = fopen("/proc/self/stat", "r");
  char process_line[4096];
  if (!process_stat || !fgets(process_line, sizeof(process_line), process_stat) || fclose(process_stat))
    die("process start evidence");
  char *tail = strrchr(process_line, ')');
  if (!tail) die("process stat format");
  char *token = strtok(tail + 1, " ");
  for (int field = 0; field < 19 && token; ++field) token = strtok(NULL, " ");
  if (!token || strspn(token, "0123456789") != strlen(token)) die("process startticks format");
  char json[1536];
  int length = snprintf(json, sizeof(json),
    "{\"schema\":\"tos.x02.queue-stats-fd.v1\",\"broker_pid\":%ld,\"broker_euid\":0,"
    "\"entry_caps\":%u,\"worker_uid\":1000,\"worker_gid\":1000,\"worker_caps\":%u,"
    "\"netns_inode\":%lu,\"owner_userns_inode\":%lu,\"owner_uid\":%u,"
    "\"proc_dev\":%lu,\"proc_inode\":%lu,\"proc_mode\":288,\"proc_uid\":0,\"proc_gid\":0,"
    "\"procfs_magic\":%lu,\"broker_dev\":%lu,\"broker_inode\":%lu,\"startticks\":\"%s\"}\n",
    (long)getpid(), ENTRY_CAPS, WORKER_CAPS, (unsigned long)net.st_ino,
    (unsigned long)owner.st_ino, owner_uid, (unsigned long)proc.st_dev,
    (unsigned long)proc.st_ino, (unsigned long)filesystem.f_type,
    (unsigned long)binary.st_dev, (unsigned long)binary.st_ino, token);
  if (length < 0 || (size_t)length >= sizeof(json)) die("receipt length");
  size_t offset = 0;
  while (offset < (size_t)length) {
    ssize_t written = write(receipt, json + offset, (size_t)length - offset);
    if (written <= 0) die("receipt write");
    offset += (size_t)written;
  }
  if (fchmod(receipt, 0400) || fcntl(receipt, F_ADD_SEALS,
      F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL)) die("receipt seals");
  char receipt_path[64];
  if (snprintf(receipt_path, sizeof(receipt_path), "/proc/self/fd/%d", receipt) < 0) die("receipt descriptor path");
  int readonly_receipt = open(receipt_path, O_RDONLY | O_CLOEXEC);
  if (readonly_receipt < 0 || close(receipt)) die("read-only sealed receipt");
  if (close(netfd) || close(userfd) || close(ownerfd)) die("namespace descriptors close");
  keep_fd(stats, 3); keep_fd(readonly_receipt, 4);
  if (setgroups(0, NULL) || setresgid(TARGET_GID, TARGET_GID, TARGET_GID)) die("ordinary group drop");
  for (int bit = 0; bit < 64; ++bit) {
    int present = prctl(PR_CAPBSET_READ, bit, 0, 0, 0);
    if (present < 0 && errno == EINVAL) break;
    if (present < 0 || (bit != CAP_NET_ADMIN && bit != CAP_NET_RAW && prctl(PR_CAPBSET_DROP, bit, 0, 0, 0)))
      die("bounding capability drop");
  }
  if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) || setresuid(TARGET_UID, TARGET_UID, TARGET_UID))
    die("ordinary credential drop");
  memset(caps, 0, sizeof(caps));
  caps[0].effective = caps[0].permitted = caps[0].inheritable = WORKER_CAPS;
  if (syscall(SYS_capset, &cap_header, caps) || prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0) ||
      prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) ||
      prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_ADMIN, 0, 0) ||
      prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_RAW, 0, 0)) die("two-capability worker setup");
  if (getresuid(&ruid, &euid, &suid) || getresgid(&rgid, &egid, &sgid) ||
      ruid != TARGET_UID || euid != TARGET_UID || suid != TARGET_UID ||
      rgid != TARGET_GID || egid != TARGET_GID || sgid != TARGET_GID || getgroups(0, NULL) != 0 ||
      syscall(SYS_capget, &cap_header, caps) || caps[0].effective != WORKER_CAPS ||
      caps[0].permitted != WORKER_CAPS || caps[0].inheritable != WORKER_CAPS ||
      caps[1].effective || caps[1].permitted || caps[1].inheritable ||
      prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 || prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0) != 0)
    die("final ordinary identity/capability verification");
  for (int bit = 0; bit < 64; ++bit) {
    int present = prctl(PR_CAPBSET_READ, bit, 0, 0, 0);
    if (present < 0 && errno == EINVAL) break;
    int expected = bit == CAP_NET_ADMIN || bit == CAP_NET_RAW;
    if (present < 0 || present != expected ||
        prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, bit, 0, 0) != expected)
      die("final bounding/ambient verification");
  }
  /* Only fixed bootstrap code executes before the driver digest is checked. */
  char bootstrap[] =
    "import hashlib,sys; p='/datax/n6-unit-agents/X02/src/scripts/x02_private_probe.py'; "
    "b=open(p,'rb').read(); h=sys.argv[1]; "
    "assert hashlib.sha256(b).hexdigest()==h,'driver bytes differ'; "
    "sys.argv=[p]+sys.argv[2:]; "
    "exec(compile(b,p,'exec'),{'__name__':'__main__','__file__':p})";
  char *child[] = {"/usr/bin/python3", "-I", "-S", "-B", "-c", bootstrap, (char *)driver_hash,
    "--source-sha", (char *)source, "--host-netns", (char *)host, "--unit", (char *)unit,
    "--run-id", (char *)run, "--case", (char *)test, "--output", (char *)output,
    "--queue-stats-fd", "3", "--queue-receipt-fd", "4", NULL};
  if (syscall(SYS_close_range, 5U, ~0U, 0U)) die("close non-handoff descriptors");
  char *environment[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "PYTHONHASHSEED=0", NULL};
  execve(child[0], child, environment);
  die("ordinary probe exec");
}
