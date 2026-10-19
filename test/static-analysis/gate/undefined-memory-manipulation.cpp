// Positive control: memset over an object that is not trivially copyable.
#include <cstring>
#include <string>

struct Record {
  std::string name;
  int value = 0;
};

int main() {
  Record record;
  std::memset(&record, 0, sizeof(record));  // expect: bugprone-undefined-memory-manipulation
  return record.value;
}
