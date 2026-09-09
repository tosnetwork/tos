// Test-only runtime I/O controls. No production target links this library.
#ifdef _FILE_OFFSET_BITS
#undef _FILE_OFFSET_BITS
#endif
#include <atomic>
#include <cerrno>
#include <cstring>
#include <limits.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace {
std::atomic<int> mode{0}, phase{0};
std::atomic<unsigned long long> written{0}, synced{0}, failed_reads{0};
char directory[PATH_MAX]{};
bool matches(int fd, bool wal_only) {
  char link[64], target[PATH_MAX];
  const char prefix[] = "/proc/self/fd/";
  std::memcpy(link, prefix, sizeof(prefix)-1);
  char digits[24]; unsigned count=0; auto value=static_cast<unsigned>(fd);
  do {digits[count++]=static_cast<char>('0'+value%10);value/=10;} while(value);
  unsigned size=sizeof(prefix)-1;
  while(count) link[size++]=digits[--count];
  link[size]=0;
  auto length=::readlink(link,target,sizeof(target)-1);
  if(length<=0) return false;
  target[length]=0;
  const auto base=std::strlen(directory);
  if(!base || std::strncmp(target,directory,base) || target[base]!='/') return false;
  return !wal_only || (length>=4 && std::strcmp(target+length-4,".log")==0);
}
ssize_t positioned(int fd,const void* data,size_t size,off_t offset) {
  const auto selected=mode.load();
  if((selected==1||selected==3)&&matches(fd,true)) {
    if(selected==1&&phase.exchange(1)==0&&size>1) {
      auto result=::syscall(SYS_pwrite64,fd,data,size/2,offset);
      if(result>0) written.fetch_add(result);
      return result;
    }
    errno=EIO;return -1;
  }
  return ::syscall(SYS_pwrite64,fd,data,size,offset);
}
int sync_file(int fd,bool data_only) {
  if(mode.load()==2 && matches(fd,true) && phase.exchange(1)==0) {
    auto result=::syscall(data_only?SYS_fdatasync:SYS_fsync,fd);
    if(result!=0) return result;
    synced.fetch_add(1);
    errno=EIO;return -1;
  }
  return ::syscall(data_only?SYS_fdatasync:SYS_fsync,fd);
}
}
extern "C" void workchain_publication_fault_arm(int selected,const char* path) {
  mode.store(0);
  std::strncpy(directory,path,sizeof(directory)-1);directory[sizeof(directory)-1]=0;
  phase.store(0);written.store(0);synced.store(0);failed_reads.store(0);mode.store(selected);
}
extern "C" void workchain_publication_fault_clear() {mode.store(0);}
extern "C" unsigned long long workchain_publication_fault_written() {return written.load();}
extern "C" unsigned long long workchain_publication_fault_synced() {return synced.load();}
extern "C" unsigned long long workchain_publication_fault_failed_reads() {return failed_reads.load();}
extern "C" ssize_t pwrite(int fd,const void* data,size_t size,off_t offset) {return positioned(fd,data,size,offset);}
extern "C" ssize_t pwrite64(int fd,const void* data,size_t size,off64_t offset) {return positioned(fd,data,size,offset);}
extern "C" int fsync(int fd) {return sync_file(fd,false);}
extern "C" int fdatasync(int fd) {return sync_file(fd,true);}
extern "C" ssize_t pread(int fd,void* data,size_t size,off_t offset) {
  if(mode.load()==4&&matches(fd,false)) {failed_reads.fetch_add(1);errno=EIO;return -1;}
  return ::syscall(SYS_pread64,fd,data,size,offset);
}
extern "C" ssize_t pread64(int fd,void* data,size_t size,off64_t offset) {return pread(fd,data,size,offset);}
extern "C" ssize_t read(int fd,void* data,size_t size) {
  if(mode.load()==4&&matches(fd,false)) {failed_reads.fetch_add(1);errno=EIO;return -1;}
  return ::syscall(SYS_read,fd,data,size);
}

extern "C" ssize_t write(int fd,const void* data,size_t size) {
  const auto selected=mode.load();
  if((selected==1||selected==3)&&matches(fd,true)) {
    if(selected==1&&phase.exchange(1)==0&&size>1) {
      auto result=::syscall(SYS_write,fd,data,size/2);
      if(result>0)written.fetch_add(result);
      return result;
    }
    errno=EIO;return -1;
  }
  return ::syscall(SYS_write,fd,data,size);
}
