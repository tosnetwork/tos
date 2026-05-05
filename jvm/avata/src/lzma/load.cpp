#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "C/LzmaDec.h"

#if (defined __MINGW32__) || (defined _MSC_VER)
#define EXPORT __declspec(dllexport)
#include <windows.h>
#include <io.h>
#define open _open
#define write _write
#define close _close
#define unlink _unlink
#ifdef _MSC_VER
#define S_IRWXU (_S_IREAD | _S_IWRITE)
#define and &&
#endif
#else
#define EXPORT __attribute__((visibility("default")))
#include <dlfcn.h>
#include <unistd.h>
#include <errno.h>
#define O_BINARY 0
#endif

#if (!defined __x86_64__) && ((defined __MINGW32__) || (defined _MSC_VER))
#define SYMBOL(x) binary_exe_##x
#else
#define SYMBOL(x) _binary_exe_##x
#endif

extern "C" {
extern const uint8_t SYMBOL(start)[];
extern const uint8_t SYMBOL(end)[];

}  // extern "C"

namespace {

int32_t read4(const uint8_t* in)
{
  return (static_cast<int32_t>(in[3]) << 24)
         | (static_cast<int32_t>(in[2]) << 16)
         | (static_cast<int32_t>(in[1]) << 8) | (static_cast<int32_t>(in[0]));
}

void* myAllocate(void*, size_t size)
{
  return malloc(size);
}

void myFree(void*, void* address)
{
  free(address);
}

const unsigned TemporaryNameSize = 1024;

#if (defined __MINGW32__) || (defined _MSC_VER)

void* openLibrary(const char* name)
{
  return LoadLibrary(name);
}

void closeLibrary(void* library)
{
  FreeLibrary(static_cast<HMODULE>(library));
}

void* librarySymbol(void* library, const char* name)
{
  void* address;
  FARPROC p = GetProcAddress(static_cast<HMODULE>(library), name);
  memcpy(&address, &p, sizeof(void*));
  return address;
}

const char* libraryError(void*)
{
  return "unknown error";
}

const char* temporaryFileName(char* buffer, unsigned size)
{
  unsigned c = GetTempPathA(size, buffer);
  if (c) {
    if (GetTempFileNameA(buffer, "223", 0, buffer + c)) {
      DeleteFileA(buffer + c);
      return buffer + c;
    }
  }
  return 0;
}

#else

void* openLibrary(const char* name)
{
  return dlopen(name, RTLD_LAZY | RTLD_LOCAL);
}

void closeLibrary(void* library)
{
  dlclose(library);
}

void* librarySymbol(void* library, const char* name)
{
  return dlsym(library, name);
}

const char* libraryError(void*)
{
  return dlerror();
}

const char* temporaryFileName(char* buffer, unsigned size)
{
  const char* dir = getenv("TMPDIR");
  if (dir == 0 or strlen(dir) == 0) {
    dir = "/tmp";
  }

  if (snprintf(buffer, size, "%s/avata-lzma-XXXXXX", dir)
      >= static_cast<int>(size)) {
    return 0;
  }

  int fd = mkstemp(buffer);
  if (fd != -1) {
    close(fd);
    unlink(buffer);
    return buffer;
  }
  return 0;
}

#endif

void* temporaryLibrary = 0;
char temporaryLibraryName[TemporaryNameSize] = {0};
bool temporaryCleanupRegistered = false;

void cleanupTemporaryLibrary()
{
  void* library = temporaryLibrary;
  temporaryLibrary = 0;

  if (library) {
    closeLibrary(library);
  }

  if (temporaryLibraryName[0]) {
    unlink(temporaryLibraryName);
    temporaryLibraryName[0] = 0;
  }
}

void rememberTemporaryLibrary(const char* name, void* library)
{
  temporaryLibrary = library;
  strncpy(temporaryLibraryName, name, sizeof(temporaryLibraryName) - 1);
  temporaryLibraryName[sizeof(temporaryLibraryName) - 1] = 0;

  if (! temporaryCleanupRegistered) {
    temporaryCleanupRegistered = atexit(cleanupTemporaryLibrary) == 0;
  }
}

}  // namespace

int main(int ac, const char** av)
{
  const unsigned PropHeaderSize = 5;
  const unsigned HeaderSize = 13;

  SizeT inSize = SYMBOL(end) - SYMBOL(start);

  int32_t outSize32 = read4(SYMBOL(start) + PropHeaderSize);
  SizeT outSize = outSize32;

  uint8_t* out = static_cast<uint8_t*>(malloc(outSize));
  if (out) {
    ISzAlloc allocator = {myAllocate, myFree};
    ELzmaStatus status = LZMA_STATUS_NOT_SPECIFIED;

    if (SZ_OK == LzmaDecode(out,
                            &outSize,
                            SYMBOL(start) + HeaderSize,
                            &inSize,
                            SYMBOL(start),
                            PropHeaderSize,
                            LZMA_FINISH_END,
                            &status,
                            &allocator)) {
      char buffer[TemporaryNameSize];
      const char* name = temporaryFileName(buffer, TemporaryNameSize);
      if (name) {
        int file = open(name, O_CREAT | O_EXCL | O_WRONLY | O_BINARY, S_IRWXU);
        if (file != -1) {
          SizeT result = write(file, out, outSize);
          free(out);

          if (close(file) == 0 and outSize == result) {
            void* library = openLibrary(name);

            if (library) {
#if (!defined __MINGW32__) && (!defined _MSC_VER)
              if (unlink(name) == 0) {
                name = 0;
              }
#endif
              rememberTemporaryLibrary(name ? name : "", library);

              void* main = librarySymbol(library, "avataMain");
              if (main) {
                int (*mainFunction)(const char*, int, const char**);
                memcpy(&mainFunction, &main, sizeof(void*));
                int result = mainFunction(buffer, ac, av);
                cleanupTemporaryLibrary();
                return result;
              } else {
                fprintf(stderr, "unable to find main in %s", buffer);
                cleanupTemporaryLibrary();
              }
            } else {
              unlink(name);
              fprintf(stderr,
                      "unable to load %s: %s\n",
                      name,
                      libraryError(library));
            }
          } else {
            unlink(name);

            fprintf(stderr,
                    "close or write failed; tried %d, got %d; %s\n",
                    static_cast<int>(outSize),
                    static_cast<int>(result),
                    strerror(errno));
          }
        } else {
          fprintf(stderr, "unable to open %s\n", name);
        }
      } else {
        fprintf(stderr, "unable to make temporary file name\n");
      }
    } else {
      fprintf(stderr, "unable to decode LZMA data\n");
    }
  } else {
    fprintf(stderr,
            "unable to allocate buffer of size %d\n",
            static_cast<int>(outSize));
  }

  return -1;
}
