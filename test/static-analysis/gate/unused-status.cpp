// Positive control: a dropped td::Status and a dropped td::Result. The check is
// configured by name, so minimal stand-ins with the real qualified names are
// enough. Casts to void still report; keeping a value or using a reasoned,
// exact suppression does not.
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
  (void)write_record(4);               // expect: bugprone-unused-return-value
  (void)read_record(5);                // expect: bugprone-unused-return-value
  static_cast<void>(write_record(6));  // expect: bugprone-unused-return-value
  static_cast<void>(read_record(7));   // expect: bugprone-unused-return-value
  // NOLINTNEXTLINE(bugprone-unused-return-value): best-effort read; no value is needed
  (void)read_record(8);
  return kept.is_error() ? 1 : 0;
}
