// Positive control: a dropped td::Status and a dropped td::Result. The check is
// configured by name, so minimal stand-ins with the real qualified names are
// enough. A kept value and an explicit (void) discard must not be reported.
namespace td {

class Status {
 public:
  bool is_error() const {
    return error_;
  }

 private:
  bool error_ = false;
};

template <class T>
class Result {
 public:
  bool is_error() const {
    return false;
  }
};

}  // namespace td

td::Status write_record(int key);
td::Result<int> read_record(int key);

int main() {
  write_record(1);  // expect: bugprone-unused-return-value
  read_record(2);   // expect: bugprone-unused-return-value
  td::Status kept = write_record(3);
  (void)read_record(4);  // an explicit discard is allowed
  return kept.is_error() ? 1 : 0;
}
