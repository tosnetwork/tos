/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "jni.h"
#include "jni-util.h"

#ifdef PLATFORM_WINDOWS

#define UNICODE

#include <windows.h>
#include <io.h>
#include <direct.h>
#include <share.h>

#define ACCESS _waccess
#define CLOSE _close
#define READ _read
#define WRITE _write
#define STAT _wstat
#define FSTAT _fstat
#define LSEEK _lseeki64
#define STRUCT_STAT struct _stat
#define MKDIR(path, mode) _wmkdir(path)
#define CHMOD(path, mode) _wchmod(path, mode)
#define REMOVE _wremove
#define RENAME _wrename
#define OPEN_MASK O_BINARY

#define CHECK_X_OK R_OK

#ifdef _MSC_VER
#define S_ISREG(x) ((x)&_S_IFREG)
#define S_ISDIR(x) ((x)&_S_IFDIR)
#define S_IRUSR _S_IREAD
#define S_IWUSR _S_IWRITE
#define W_OK 2
#define R_OK 4
#else
#define OPEN _wopen
#endif

#define GET_CHARS GetStringChars
#define RELEASE_CHARS(path, chars) \
  ReleaseStringChars(path, reinterpret_cast<const jchar*>(chars))

typedef wchar_t char_t;

#if defined(WINAPI_FAMILY)
#if !WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)

#include "avata-interop.h"
#define SKIP_OPERATOR_NEW

#endif
#endif

#else  // not PLATFORM_WINDOWS

#include <dirent.h>
#include <unistd.h>
#include "sys/mman.h"

#define ACCESS access
#define OPEN open
#define CLOSE close
#define READ read
#define WRITE write
#define STAT stat
#define FSTAT fstat
#define LSEEK lseek
#define STRUCT_STAT struct stat
#define MKDIR mkdir
#define CHMOD chmod
#define REMOVE remove
#define RENAME rename
#define OPEN_MASK 0

#define CHECK_X_OK X_OK

#define GET_CHARS GetStringUTFChars
#define RELEASE_CHARS ReleaseStringUTFChars

typedef char char_t;

#ifdef __APPLE__
#define STAT_MTIME st_mtimespec
#else
#define STAT_MTIME st_mtim
#endif

#endif  // not PLATFORM_WINDOWS

#define RESTARTABLE(_cmd, _result) \
  do {                             \
    do {                           \
      _result = _cmd;              \
    } while (_result == -1 && errno == EINTR); \
  } while (0)

#ifndef WINAPI_FAMILY
#ifndef WINAPI_PARTITION_DESKTOP
#define WINAPI_PARTITION_DESKTOP 1
#endif

#ifndef WINAPI_FAMILY_PARTITION
#define WINAPI_FAMILY_PARTITION(x) (x)
#endif
#endif  // WINAPI_FAMILY

#if !defined(SKIP_OPERATOR_NEW)
inline void* operator new(size_t, void* p) throw()
{
  return p;
}
#endif

typedef const char_t* string_t;

namespace {

#ifdef _MSC_VER
inline int OPEN(string_t path, int mask, int mode)
{
  int fd;
  if (_wsopen_s(&fd, path, mask, _SH_DENYNO, mode) == 0) {
    return fd;
  } else {
    return -1;
  }
}
#endif

inline bool exists(string_t path)
{
#ifdef PLATFORM_WINDOWS
  return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;
#else
  STRUCT_STAT s;
  int r;
  RESTARTABLE(STAT(path, &s), r);
  return r == 0;
#endif
}

inline int doStat(string_t path, STRUCT_STAT* s)
{
  int r;
  RESTARTABLE(STAT(path, s), r);
  return r;
}

inline int doAccess(string_t path, int mode)
{
  int r;
  RESTARTABLE(ACCESS(path, mode), r);
  return r;
}

inline int doMkdir(string_t path, int mode)
{
  int r;
  RESTARTABLE(MKDIR(path, mode), r);
  return r;
}

inline int doChmod(string_t path, int mode)
{
  int r;
  RESTARTABLE(CHMOD(path, mode), r);
  return r;
}

inline int doRemove(string_t path)
{
  int r;
  RESTARTABLE(REMOVE(path), r);
  return r;
}

inline int doRename(string_t oldPath, string_t newPath)
{
  int r;
  RESTARTABLE(RENAME(oldPath, newPath), r);
  return r;
}

inline int doOpen(JNIEnv* e, string_t path, int mask, STRUCT_STAT* stats = 0)
{
  int fd;
  RESTARTABLE(OPEN(path, mask | OPEN_MASK, S_IRUSR | S_IWUSR), fd);
  if (fd != -1) {
    STRUCT_STAT s;
    int r;
    RESTARTABLE(FSTAT(fd, &s), r);
    if (r == -1) {
      int savedErrno = errno;
      CLOSE(fd);
      errno = savedErrno;
      fd = -1;
    } else if (S_ISDIR(s.st_mode)) {
      CLOSE(fd);
      errno = EISDIR;
      fd = -1;
    } else if (stats) {
      *stats = s;
    }
  }

  if (fd == -1) {
    throwNewErrno(e, "java/io/FileNotFoundException");
  }
  return fd;
}

inline void doClose(JNIEnv* e, jint fd)
{
  int r = CLOSE(fd);
  if (r == -1) {
    throwNewErrno(e, "java/io/IOException");
  }
}

inline bool doSeek(JNIEnv* e, jint fd, jlong position)
{
  jlong r;
  RESTARTABLE(LSEEK(fd, position, SEEK_SET), r);
  if (r == -1) {
    throwNewErrno(e, "java/io/IOException");
    return false;
  }
  return true;
}

inline int doRead(JNIEnv* e, jint fd, jbyte* data, jint length)
{
  int r;
  RESTARTABLE(READ(fd, data, length), r);
  if (r > 0) {
    return r;
  } else if (r == 0) {
    return -1;
  } else {
    throwNewErrno(e, "java/io/IOException");
    return 0;
  }
}

inline void doWrite(JNIEnv* e, jint fd, const jbyte* data, jint length)
{
  jint offset = 0;
  while (offset < length) {
    int r;
    RESTARTABLE(WRITE(fd, data + offset, length - offset), r);
    if (r < 0) {
      throwNewErrno(e, "java/io/IOException");
      return;
    } else if (r == 0) {
      throwNew(e, "java/io/IOException", "write returned zero");
      return;
    }
    offset += r;
  }
}

#ifndef PLATFORM_WINDOWS
char* duplicatePath(string_t path)
{
  size_t length = strlen(path);
  char* result = static_cast<char*>(malloc(length + 1));
  if (result) {
    memcpy(result, path, length + 1);
  }
  return result;
}

char* absolutePath(string_t path)
{
  if (path[0] == '/') {
    return duplicatePath(path);
  }

  char* cwd = getcwd(NULL, 0);
  if (cwd == 0) {
    return duplicatePath(path);
  }

  size_t cwdLength = strlen(cwd);
  size_t pathLength = strlen(path);
  bool needsSeparator = (cwdLength == 0 or cwd[cwdLength - 1] != '/');
  char* result = static_cast<char*>(
      malloc(cwdLength + (needsSeparator ? 1 : 0) + pathLength + 1));
  if (result) {
    memcpy(result, cwd, cwdLength);
    size_t offset = cwdLength;
    if (needsSeparator) {
      result[offset++] = '/';
    }
    memcpy(result + offset, path, pathLength + 1);
  }
  free(cwd);
  return result;
}

char* normalizePath(char* path)
{
  size_t length = strlen(path);
  char** parts = static_cast<char**>(malloc((length + 1) * sizeof(char*)));
  if (parts == 0) {
    return 0;
  }

  unsigned count = 0;
  size_t start = 0;
  while (start < length) {
    while (start < length and path[start] == '/') {
      ++start;
    }
    size_t end = start;
    while (end < length and path[end] != '/') {
      ++end;
    }
    if (end > start) {
      path[end] = 0;
      char* part = path + start;
      if (strcmp(part, ".") == 0) {
      } else if (strcmp(part, "..") == 0) {
        if (count > 0) {
          --count;
        }
      } else {
        parts[count++] = part;
      }
    }
    start = end + 1;
  }

  size_t resultLength = 1;
  for (unsigned i = 0; i < count; ++i) {
    resultLength += strlen(parts[i]) + (i == 0 ? 0 : 1);
  }

  char* result = static_cast<char*>(malloc(resultLength + 1));
  if (result) {
    size_t offset = 0;
    result[offset++] = '/';
    for (unsigned i = 0; i < count; ++i) {
      if (i != 0) {
        result[offset++] = '/';
      }
      size_t partLength = strlen(parts[i]);
      memcpy(result + offset, parts[i], partLength);
      offset += partLength;
    }
    result[offset] = 0;
  }
  free(parts);
  return result;
}
#endif

#ifdef PLATFORM_WINDOWS

class Directory {
 public:
  Directory() : handle(0), findNext(false)
  {
  }

  virtual string_t next()
  {
    if (handle and handle != INVALID_HANDLE_VALUE) {
      if (findNext) {
        if (FindNextFileW(handle, &data)) {
          return data.cFileName;
        }
      } else {
        findNext = true;
        return data.cFileName;
      }
    }
    return 0;
  }

  virtual void dispose()
  {
    if (handle and handle != INVALID_HANDLE_VALUE) {
      FindClose(handle);
    }
    free(this);
  }

  HANDLE handle;
  WIN32_FIND_DATAW data;
  bool findNext;
};

#else  // not PLATFORM_WINDOWS

#endif  // not PLATFORM_WINDOWS

}  // namespace

static inline string_t getChars(JNIEnv* e, jstring path)
{
  return reinterpret_cast<string_t>(e->GET_CHARS(path, 0));
}

static inline void releaseChars(JNIEnv* e, jstring path, string_t chars)
{
  e->RELEASE_CHARS(path, chars);
}

extern "C" JNIEXPORT jstring JNICALL
    Java_java_io_File_toCanonicalPath(JNIEnv* e, jclass, jstring path)
{
#ifdef PLATFORM_WINDOWS
  string_t chars = getChars(e, path);
  if (chars) {
#if !defined(WINAPI_FAMILY) || WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
    const unsigned BufferSize = MAX_PATH;
    char_t buffer[BufferSize];
    DWORD success = GetFullPathNameW(chars, BufferSize, buffer, 0);
    releaseChars(e, path, chars);
    if (success) {
      return e->NewString(reinterpret_cast<const jchar*>(buffer),
                          wcslen(buffer));
    }
#else
    std::wstring partialPath = chars;
    releaseChars(e, path, chars);
    std::wstring fullPath = AvataInterop::GetFullPath(partialPath);
    return e->NewString(reinterpret_cast<const jchar*>(fullPath.c_str()),
                        fullPath.length());
#endif
  }
#else
  string_t chars = getChars(e, path);
  if (chars) {
    char* resolved = realpath(chars, 0);
    if (resolved) {
      jstring result = e->NewStringUTF(resolved);
      free(resolved);
      releaseChars(e, path, chars);
      return result;
    }

    char* absolute = absolutePath(chars);
    releaseChars(e, path, chars);
    if (absolute) {
      char* normalized = normalizePath(absolute);
      free(absolute);
      if (normalized) {
        jstring result = e->NewStringUTF(normalized);
        free(normalized);
        return result;
      }
    }
  }
#endif
  return path;
}

extern "C" JNIEXPORT jstring JNICALL
    Java_java_io_File_toAbsolutePath(JNIEnv* e UNUSED, jclass, jstring path)
{
#ifdef PLATFORM_WINDOWS
#if !defined(WINAPI_FAMILY) || WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
  string_t chars = getChars(e, path);
  if (chars) {
    const unsigned BufferSize = MAX_PATH;
    char_t buffer[BufferSize];
    DWORD success = GetFullPathNameW(chars, BufferSize, buffer, 0);
    releaseChars(e, path, chars);

    if (success) {
      return e->NewString(reinterpret_cast<const jchar*>(buffer),
                          wcslen(buffer));
    }
  }

  return path;
#else
  string_t chars = getChars(e, path);
  if (chars) {
    std::wstring partialPath = chars;
    releaseChars(e, path, chars);

    std::wstring fullPath = AvataInterop::GetFullPath(partialPath);

    return e->NewString(reinterpret_cast<const jchar*>(fullPath.c_str()),
                        fullPath.length());
  }
  return path;
#endif
#else
  jstring result = path;
  string_t chars = getChars(e, path);
  if (chars) {
    if (chars[0] != '/') {
      char* cwd = getcwd(NULL, 0);
      if (cwd) {
        unsigned size = strlen(cwd) + strlen(chars) + 2;
        RUNTIME_ARRAY(char, buffer, size);
        snprintf(RUNTIME_ARRAY_BODY(buffer), size, "%s/%s", cwd, chars);
        result = e->NewStringUTF(RUNTIME_ARRAY_BODY(buffer));
        free(cwd);
      }
    }
    releaseChars(e, path, chars);
  }
  return result;
#endif
}

extern "C" JNIEXPORT jlong JNICALL
    Java_java_io_File_length(JNIEnv* e, jclass, jstring path)
{
#ifdef PLATFORM_WINDOWS
  // Option: without opening file
  // http://msdn.microsoft.com/en-us/library/windows/desktop/aa364946(v=vs.85).aspx
  string_t chars = getChars(e, path);
  if (chars) {
    LARGE_INTEGER fileSize;
#if !defined(WINAPI_FAMILY) || WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
    HANDLE file = CreateFileW(
        chars, FILE_READ_DATA, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
#else
    HANDLE file = CreateFile2(
        chars, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, nullptr);
#endif
    releaseChars(e, path, chars);
    if (file == INVALID_HANDLE_VALUE)
      return 0;
#if !defined(WINAPI_FAMILY) || WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
    if (!GetFileSizeEx(file, &fileSize)) {
      CloseHandle(file);
      return 0;
    }
#else
    FILE_STANDARD_INFO info;
    if (!GetFileInformationByHandleEx(
            file, FileStandardInfo, &info, sizeof(info))) {
      CloseHandle(file);
      return 0;
    }
    fileSize = info.EndOfFile;
#endif

    CloseHandle(file);
    return static_cast<jlong>(fileSize.QuadPart);
  }
#else

  string_t chars = getChars(e, path);
  if (chars) {
    STRUCT_STAT s;
    int r = doStat(chars, &s);
    releaseChars(e, path, chars);
    if (r == 0) {
      return s.st_size;
    }
  }

#endif

  return 0;
}

extern "C" JNIEXPORT void JNICALL
    Java_java_io_File_mkdir(JNIEnv* e, jclass, jstring path)
{
  string_t chars = getChars(e, path);
  if (chars) {
    int r = doMkdir(chars, 0777);
    if (r != 0) {
      throwNewErrno(e, "java/io/IOException");
    }
    releaseChars(e, path, chars);
  }
}

extern "C" JNIEXPORT jboolean JNICALL
    Java_java_io_File_createNewFile(JNIEnv* e, jclass, jstring path)
{
  bool result = false;
  string_t chars = getChars(e, path);
  if (chars) {
    int fd;
    RESTARTABLE(OPEN(chars, O_CREAT | O_WRONLY | O_EXCL | OPEN_MASK, 0666),
                fd);
    if (fd == -1) {
      if (errno != EEXIST) {
        throwNewErrno(e, "java/io/IOException");
      }
    } else {
      result = true;
      doClose(e, fd);
    }
    releaseChars(e, path, chars);
  }
  return result;
}

extern "C" JNIEXPORT void JNICALL
Java_java_io_File_delete(JNIEnv* e, jclass, jstring path)
{
  string_t chars = getChars(e, path);
  int r;
  if (chars) {
#ifdef PLATFORM_WINDOWS
    if (GetFileAttributes(chars) & FILE_ATTRIBUTE_DIRECTORY) {
      r = !RemoveDirectory(chars);
    } else {
      r = doRemove(chars);
    }
#else
    r = doRemove(chars);
#endif
    if (r != 0) {
      throwNewErrno(e, "java/io/IOException");
    }
    releaseChars(e, path, chars);
  }
}

extern "C" JNIEXPORT jboolean JNICALL
    Java_java_io_File_canRead(JNIEnv* e, jclass, jstring path)
{
  string_t chars = getChars(e, path);
  if (chars) {
    int r = doAccess(chars, R_OK);
    releaseChars(e, path, chars);
    return (r == 0);
  }
  return false;
}

extern "C" JNIEXPORT jboolean JNICALL
    Java_java_io_File_canWrite(JNIEnv* e, jclass, jstring path)
{
  string_t chars = getChars(e, path);
  if (chars) {
    int r = doAccess(chars, W_OK);
    releaseChars(e, path, chars);
    return (r == 0);
  }
  return false;
}

extern "C" JNIEXPORT jboolean JNICALL
    Java_java_io_File_canExecute(JNIEnv* e, jclass, jstring path)
{
  string_t chars = getChars(e, path);
  if (chars) {
    int r = doAccess(chars, CHECK_X_OK);
    releaseChars(e, path, chars);
    return (r == 0);
  }
  return false;
}

#ifndef PLATFORM_WINDOWS
extern "C" JNIEXPORT jboolean JNICALL
    Java_java_io_File_setExecutable(JNIEnv* e,
                                    jclass,
                                    jstring path,
                                    jboolean executable,
                                    jboolean ownerOnly)
{
  string_t chars = getChars(e, path);
  if (chars) {
    jboolean v;
    int mask;
    if (ownerOnly) {
      mask = S_IXUSR;
    } else {
      mask = S_IXUSR | S_IXGRP | S_IXOTH;
    }

    STRUCT_STAT s;
    int r = doStat(chars, &s);
    if (r == 0) {
      int mode = s.st_mode;
      if (executable) {
        mode |= mask;
      } else {
        mode &= ~mask;
      }
      if (doChmod(chars, mode) != 0) {
        v = false;
      } else {
        v = true;
      }
    } else {
      v = false;
    }
    releaseChars(e, path, chars);
    return v;
  }
  return false;
}

#else  // ifndef PLATFORM_WINDOWS

extern "C" JNIEXPORT jboolean JNICALL
    Java_java_io_File_setExecutable(JNIEnv*,
                                    jclass,
                                    jstring,
                                    jboolean executable,
                                    jboolean)
{
  return executable;
}

#endif

extern "C" JNIEXPORT jboolean JNICALL
    Java_java_io_File_rename(JNIEnv* e, jclass, jstring old, jstring new_)
{
  string_t oldChars = getChars(e, old);
  string_t newChars = getChars(e, new_);
  if (oldChars) {
    bool v;
    if (newChars) {
      v = doRename(oldChars, newChars) == 0;

      releaseChars(e, new_, newChars);
    } else {
      v = false;
    }
    releaseChars(e, old, oldChars);
    return v;
  } else {
    return false;
  }
}

extern "C" JNIEXPORT jboolean JNICALL
    Java_java_io_File_isDirectory(JNIEnv* e, jclass, jstring path)
{
  string_t chars = getChars(e, path);
  if (chars) {
    STRUCT_STAT s;
    int r = doStat(chars, &s);
    bool v = (r == 0 and S_ISDIR(s.st_mode));
    releaseChars(e, path, chars);
    return v;
  } else {
    return false;
  }
}

extern "C" JNIEXPORT jboolean JNICALL
    Java_java_io_File_isFile(JNIEnv* e, jclass, jstring path)
{
  string_t chars = getChars(e, path);
  if (chars) {
    STRUCT_STAT s;
    int r = doStat(chars, &s);
    bool v = (r == 0 and S_ISREG(s.st_mode));
    releaseChars(e, path, chars);
    return v;
  } else {
    return false;
  }
}

extern "C" JNIEXPORT jboolean JNICALL
    Java_java_io_File_exists(JNIEnv* e, jclass, jstring path)
{
  string_t chars = getChars(e, path);
  if (chars) {
    bool v = exists(chars);
    releaseChars(e, path, chars);
    return v;
  } else {
    return false;
  }
}

extern "C" JNIEXPORT jlong JNICALL
    Java_java_io_File_lastModified(JNIEnv* e, jclass, jstring path)
{
  string_t chars = getChars(e, path);
  if (chars) {
#ifdef PLATFORM_WINDOWS
// Option: without opening file
// http://msdn.microsoft.com/en-us/library/windows/desktop/aa364946(v=vs.85).aspx
#if !defined(WINAPI_FAMILY) || WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
    HANDLE hFile = CreateFileW(
        chars, FILE_READ_DATA, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
#else
    HANDLE hFile = CreateFile2(
        chars, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, nullptr);
#endif
    releaseChars(e, path, chars);
    if (hFile == INVALID_HANDLE_VALUE)
      return 0;
    LARGE_INTEGER fileDate, filetimeToUnixEpochAdjustment;
    filetimeToUnixEpochAdjustment.QuadPart = 11644473600000L * 10000L;
#if !defined(WINAPI_FAMILY) || WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
    FILETIME fileLastWriteTime;
    if (!GetFileTime(hFile, 0, 0, &fileLastWriteTime)) {
      CloseHandle(hFile);
      return 0;
    }
    fileDate.HighPart = fileLastWriteTime.dwHighDateTime;
    fileDate.LowPart = fileLastWriteTime.dwLowDateTime;
#else
    FILE_BASIC_INFO fileInfo;
    if (!GetFileInformationByHandleEx(
            hFile, FileBasicInfo, &fileInfo, sizeof(fileInfo))) {
      CloseHandle(hFile);
      return 0;
    }
    fileDate = fileInfo.ChangeTime;
#endif
    CloseHandle(hFile);
    fileDate.QuadPart -= filetimeToUnixEpochAdjustment.QuadPart;
    return fileDate.QuadPart / 10000L;
#else
    STRUCT_STAT fileStat;
    int res = doStat(chars, &fileStat);
    releaseChars(e, path, chars);

    if (res == -1) {
      return 0;
    }
    return (static_cast<jlong>(fileStat.STAT_MTIME.tv_sec) * 1000)
           + (static_cast<jlong>(fileStat.STAT_MTIME.tv_nsec) / 1000000);
#endif
  }

  return 0;
}

#ifdef PLATFORM_WINDOWS

extern "C" JNIEXPORT jlong JNICALL
    Java_java_io_File_openDir(JNIEnv* e, jclass, jstring path)
{
  string_t chars = getChars(e, path);
  if (chars) {
    unsigned length = wcslen(chars);
    unsigned size = length * sizeof(char_t);

    RUNTIME_ARRAY(char_t, buffer, length + 3);
    memcpy(RUNTIME_ARRAY_BODY(buffer), chars, size);
    memcpy(RUNTIME_ARRAY_BODY(buffer) + length, L"\\*", 6);

    releaseChars(e, path, chars);

    Directory* d = new (malloc(sizeof(Directory))) Directory;
#if !defined(WINAPI_FAMILY) || WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
    d->handle = FindFirstFileW(RUNTIME_ARRAY_BODY(buffer), &(d->data));
#else
    d->handle = FindFirstFileExW(RUNTIME_ARRAY_BODY(buffer),
                                 FindExInfoStandard,
                                 &(d->data),
                                 FindExSearchNameMatch,
                                 NULL,
                                 0);
#endif
    if (d->handle == INVALID_HANDLE_VALUE) {
      d->dispose();
      d = 0;
    }

    return reinterpret_cast<jlong>(d);
  } else {
    return 0;
  }
}

extern "C" JNIEXPORT jstring JNICALL
    Java_java_io_File_readDir(JNIEnv* e, jclass, jlong handle)
{
  Directory* d = reinterpret_cast<Directory*>(handle);

  while (true) {
    string_t s = d->next();
    if (s) {
      if (wcscmp(s, L".") == 0 || wcscmp(s, L"..") == 0) {
        // skip . or .. and try again
      } else {
        return e->NewString(reinterpret_cast<const jchar*>(s), wcslen(s));
      }
    } else {
      return 0;
    }
  }
}

extern "C" JNIEXPORT void JNICALL
    Java_java_io_File_closeDir(JNIEnv*, jclass, jlong handle)
{
  reinterpret_cast<Directory*>(handle)->dispose();
}

#else  // not PLATFORM_WINDOWS

extern "C" JNIEXPORT jlong JNICALL
    Java_java_io_File_openDir(JNIEnv* e, jclass, jstring path)
{
  string_t chars = getChars(e, path);
  if (chars) {
    DIR* dir;
    do {
      errno = 0;
      dir = opendir(chars);
    } while (dir == 0 and errno == EINTR);
    jlong handle = reinterpret_cast<jlong>(dir);
    releaseChars(e, path, chars);
    return handle;
  } else {
    return 0;
  }
}

extern "C" JNIEXPORT jstring JNICALL
    Java_java_io_File_readDir(JNIEnv* e, jclass, jlong handle)
{
  struct dirent* directoryEntry;

  if (handle != 0) {
    while (true) {
      errno = 0;
      directoryEntry = readdir(reinterpret_cast<DIR*>(handle));
      if (directoryEntry == NULL) {
        if (errno == EINTR) {
          continue;
        }
        return NULL;
      } else if (strcmp(directoryEntry->d_name, ".") == 0
                 || strcmp(directoryEntry->d_name, "..") == 0) {
        // skip . or .. and try again
      } else {
        return e->NewStringUTF(directoryEntry->d_name);
      }
    }
  }
  return NULL;
}

extern "C" JNIEXPORT void JNICALL
    Java_java_io_File_closeDir(JNIEnv*, jclass, jlong handle)
{
  if (handle != 0) {
    closedir(reinterpret_cast<DIR*>(handle));
  }
}

#endif  // not PLATFORM_WINDOWS

extern "C" JNIEXPORT jint JNICALL
    Java_java_io_FileInputStream_open(JNIEnv* e, jclass, jstring path)
{
  string_t chars = getChars(e, path);
  if (chars) {
    int fd = doOpen(e, chars, O_RDONLY);
    releaseChars(e, path, chars);
    return fd;
  } else {
    return -1;
  }
}

extern "C" JNIEXPORT jint JNICALL
    Java_java_io_FileInputStream_read__I(JNIEnv* e, jclass, jint fd)
{
  jbyte data;
  int r = doRead(e, fd, &data, 1);
  if (r <= 0) {
    return -1;
  } else {
    return data & 0xff;
  }
}

extern "C" JNIEXPORT jint JNICALL
    Java_java_io_FileInputStream_read__I_3BII(JNIEnv* e,
                                              jclass,
                                              jint fd,
                                              jbyteArray b,
                                              jint offset,
                                              jint length)
{
  jbyte* data = static_cast<jbyte*>(malloc(length));
  if (data == 0) {
    throwNew(e, "java/lang/OutOfMemoryError", 0);
    return 0;
  }

  int r = doRead(e, fd, data, length);

  if (r > 0) {
    e->SetByteArrayRegion(b, offset, r, data);
  }

  free(data);

  return r;
}

extern "C" JNIEXPORT void JNICALL
    Java_java_io_FileInputStream_close(JNIEnv* e, jclass, jint fd)
{
  doClose(e, fd);
}

extern "C" JNIEXPORT jint JNICALL
    Java_java_io_FileOutputStream_open(JNIEnv* e,
                                       jclass,
                                       jstring path,
                                       jboolean append)
{
  string_t chars = getChars(e, path);
  if (chars) {
    int fd = doOpen(e,
                    chars,
                    append ? (O_WRONLY | O_CREAT | O_APPEND)
                           : (O_WRONLY | O_CREAT | O_TRUNC));
    releaseChars(e, path, chars);
    return fd;
  } else {
    return -1;
  }
}

extern "C" JNIEXPORT void JNICALL
    Java_java_io_FileOutputStream_write__II(JNIEnv* e, jclass, jint fd, jint c)
{
  jbyte data = c;
  doWrite(e, fd, &data, 1);
}

extern "C" JNIEXPORT void JNICALL
    Java_java_io_FileOutputStream_write__I_3BII(JNIEnv* e,
                                                jclass,
                                                jint fd,
                                                jbyteArray b,
                                                jint offset,
                                                jint length)
{
  jbyte* data = static_cast<jbyte*>(malloc(length));

  if (data == 0) {
    throwNew(e, "java/lang/OutOfMemoryError", 0);
    return;
  }

  e->GetByteArrayRegion(b, offset, length, data);
  if (not e->ExceptionCheck()) {
    doWrite(e, fd, data, length);
  }

  free(data);
}

extern "C" JNIEXPORT void JNICALL
    Java_java_io_FileOutputStream_close(JNIEnv* e, jclass, jint fd)
{
  doClose(e, fd);
}

extern "C" JNIEXPORT void JNICALL
    Java_java_io_RandomAccessFile_open(JNIEnv* e,
                                       jclass,
                                       jstring path,
                                       jint mode,
                                       jlongArray result)
{
  string_t chars = getChars(e, path);
  if (chars) {
    jlong peer = 0;
    jlong length = 0;
    int flags = 0;
    if (mode & 1) {
      flags = O_RDONLY;
    } else {
      flags = O_RDWR | O_CREAT;
#ifdef O_SYNC
      if (mode & 4) {
        flags |= O_SYNC;
      }
#endif
#ifdef O_DSYNC
      if (mode & 8) {
        flags |= O_DSYNC;
      }
#endif
    }
#if !defined(WINAPI_FAMILY) || WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
    STRUCT_STAT fileStats;
    memset(&fileStats, 0, sizeof(fileStats));
    int fd = doOpen(e, chars, flags, &fileStats);
    releaseChars(e, path, chars);
    if (e->ExceptionCheck()) {
      return;
    }
    peer = fd;
    length = fileStats.st_size;
#else
    CREATEFILE2_EXTENDED_PARAMETERS parameters;
    memset(&parameters, 0, sizeof(parameters));
    parameters.dwSize = sizeof(parameters);
    if (mode & 12) {
      parameters.dwFileFlags = FILE_FLAG_WRITE_THROUGH;
    }
    HANDLE hFile = CreateFile2(chars,
                               GENERIC_READ | ((mode & 2) ? GENERIC_WRITE : 0),
                               FILE_SHARE_READ,
                               (mode & 2) ? OPEN_ALWAYS : OPEN_EXISTING,
                               &parameters);
    releaseChars(e, path, chars);
    if (hFile == INVALID_HANDLE_VALUE) {
      throwNewErrno(e, "java/io/FileNotFoundException");
      return;
    }

    FILE_STANDARD_INFO info;
    if (!GetFileInformationByHandleEx(
            hFile, FileStandardInfo, &info, sizeof(info))) {
      CloseHandle(hFile);
      throwNewErrno(e, "java/io/IOException");
      return;
    }
    if (info.Directory) {
      CloseHandle(hFile);
      errno = EISDIR;
      throwNewErrno(e, "java/io/FileNotFoundException");
      return;
    }

    peer = (jlong)hFile;
    length = info.EndOfFile.QuadPart;
#endif

    e->SetLongArrayRegion(result, 0, 1, &peer);
    e->SetLongArrayRegion(result, 1, 1, &length);
  }
}

extern "C" JNIEXPORT jint JNICALL
    Java_java_io_RandomAccessFile_readBytes(JNIEnv* e,
                                            jclass,
                                            jlong peer,
                                            jlong position,
                                            jbyteArray buffer,
                                            int offset,
                                            int length)
{
  if (length == 0) {
    return 0;
  }
#if !defined(WINAPI_FAMILY) || WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
  int fd = (int)peer;
  if (!doSeek(e, fd, position)) {
    return -1;
  }

  jbyte* data = static_cast<jbyte*>(malloc(length));
  if (data == 0) {
    throwNew(e, "java/lang/OutOfMemoryError", 0);
    return -1;
  }

  int bytesRead;
  RESTARTABLE(READ(fd, data, length), bytesRead);

  if (bytesRead == -1) {
    free(data);
    throwNewErrno(e, "java/io/IOException");
    return -1;
  } else if (bytesRead == 0) {
    free(data);
    return -1;
  }
  e->SetByteArrayRegion(buffer, offset, bytesRead, data);
  free(data);
#else
  HANDLE hFile = (HANDLE)peer;
  LARGE_INTEGER lPos;
  lPos.QuadPart = position;
  if (!SetFilePointerEx(hFile, lPos, nullptr, FILE_BEGIN)) {
    throwNewErrno(e, "java/io/IOException");
    return -1;
  }

  uint8_t* dst
      = reinterpret_cast<uint8_t*>(e->GetPrimitiveArrayCritical(buffer, 0));

  DWORD bytesRead = 0;
  if (!ReadFile(hFile, dst + offset, length, &bytesRead, nullptr)) {
    e->ReleasePrimitiveArrayCritical(buffer, dst, 0);
    throwNewErrno(e, "java/io/IOException");
    return -1;
  }
  e->ReleasePrimitiveArrayCritical(buffer, dst, 0);
  if (bytesRead == 0) {
    return -1;
  }
#endif

  return (jint)bytesRead;
}

extern "C" JNIEXPORT jint JNICALL
    Java_java_io_RandomAccessFile_writeBytes(JNIEnv* e,
                                             jclass,
                                             jlong peer,
                                             jlong position,
                                             jbyteArray buffer,
                                             int offset,
                                             int length)
{
  if (length == 0) {
    return 0;
  }
#if !defined(WINAPI_FAMILY) || WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
  int fd = (int)peer;
  if (!doSeek(e, fd, position)) {
    return -1;
  }

  jbyte* data = static_cast<jbyte*>(malloc(length));
  if (data == 0) {
    throwNew(e, "java/lang/OutOfMemoryError", 0);
    return -1;
  }

  e->GetByteArrayRegion(buffer, offset, length, data);
  if (!e->ExceptionCheck()) {
    doWrite(e, fd, data, length);
  }
  free(data);
  if (e->ExceptionCheck()) {
    return -1;
  }
  int bytesWritten = length;
#else
  HANDLE hFile = (HANDLE)peer;
  LARGE_INTEGER lPos;
  lPos.QuadPart = position;
  if (!SetFilePointerEx(hFile, lPos, nullptr, FILE_BEGIN)) {
    throwNewErrno(e, "java/io/IOException");
    return -1;
  }

  uint8_t* dst
      = reinterpret_cast<uint8_t*>(e->GetPrimitiveArrayCritical(buffer, 0));

  DWORD bytesWritten = 0;
  if (!WriteFile(hFile, dst + offset, length, &bytesWritten, nullptr)) {
    e->ReleasePrimitiveArrayCritical(buffer, dst, 0);
    throwNewErrno(e, "java/io/IOException");
    return -1;
  }
  e->ReleasePrimitiveArrayCritical(buffer, dst, 0);
#endif

  return (jint)bytesWritten;
}

extern "C" JNIEXPORT jlong JNICALL
    Java_java_io_RandomAccessFile_length(JNIEnv* e, jclass, jlong peer)
{
#if !defined(WINAPI_FAMILY) || WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
  int fd = (int)peer;
  STRUCT_STAT fileStats;
  int r;
  RESTARTABLE(FSTAT(fd, &fileStats), r);
  if (r == -1) {
    throwNewErrno(e, "java/io/IOException");
    return -1;
  }
  return fileStats.st_size;
#else
  HANDLE hFile = (HANDLE)peer;
  FILE_STANDARD_INFO info;
  if (!GetFileInformationByHandleEx(
          hFile, FileStandardInfo, &info, sizeof(info))) {
    throwNewErrno(e, "java/io/IOException");
    return -1;
  }
  return info.EndOfFile.QuadPart;
#endif
}

extern "C" JNIEXPORT void JNICALL
    Java_java_io_RandomAccessFile_setLength(JNIEnv* e,
                                            jclass,
                                            jlong peer,
                                            jlong newLength)
{
#if !defined(WINAPI_FAMILY) || WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
  int fd = (int)peer;
#if defined(PLATFORM_WINDOWS)
  intptr_t osHandle = _get_osfhandle(fd);
  if (osHandle == -1) {
    throwNewErrno(e, "java/io/IOException");
    return;
  }
  HANDLE hFile = reinterpret_cast<HANDLE>(osHandle);
  LARGE_INTEGER length;
  length.QuadPart = newLength;
  if (!SetFilePointerEx(hFile, length, nullptr, FILE_BEGIN)
      || !SetEndOfFile(hFile)) {
    throwNewErrno(e, "java/io/IOException");
  }
#else
  int r;
  RESTARTABLE(ftruncate(fd, newLength), r);
  if (r == -1) {
    throwNewErrno(e, "java/io/IOException");
  }
#endif
#else
  HANDLE hFile = (HANDLE)peer;
  LARGE_INTEGER length;
  length.QuadPart = newLength;
  if (!SetFilePointerEx(hFile, length, nullptr, FILE_BEGIN)
      || !SetEndOfFile(hFile)) {
    throwNewErrno(e, "java/io/IOException");
  }
#endif
}

extern "C" JNIEXPORT void JNICALL
    Java_java_io_RandomAccessFile_close(JNIEnv* e, jclass, jlong peer)
{
#if !defined(WINAPI_FAMILY) || WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
  int fd = (int)peer;
  doClose(e, fd);
#else
  HANDLE hFile = (HANDLE)peer;
  if (!CloseHandle(hFile)) {
    throwNewErrno(e, "java/io/IOException");
  }
#endif
}
