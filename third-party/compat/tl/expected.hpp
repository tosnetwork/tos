// Minimal tl::expected shim for silkworm-core compilation.
// Provides tl::expected<T,E>, tl::expected<void,E>, and tl::unexpected.
#pragma once
#include <optional>
#include <type_traits>
#include <utility>

namespace tl {

template <typename E>
class unexpected {
  public:
    constexpr explicit unexpected(const E& e) : val_(e) {}
    constexpr explicit unexpected(E&& e) : val_(std::move(e)) {}
    constexpr const E& value() const& noexcept { return val_; }
    constexpr E& value() & noexcept { return val_; }
    constexpr E&& value() && noexcept { return std::move(val_); }

  private:
    E val_;
};

template <typename E>
unexpected(E) -> unexpected<E>;

// Primary template: expected<T, E> where T is not void.
template <typename T, typename E>
class expected {
  public:
    constexpr expected() : has_value_(true) { new (&val_) T{}; }
    constexpr expected(const T& v) : has_value_(true) { new (&val_) T(v); }
    constexpr expected(T&& v) : has_value_(true) { new (&val_) T(std::move(v)); }

    constexpr expected(const unexpected<E>& e) : has_value_(false) { new (&err_) E(e.value()); }
    constexpr expected(unexpected<E>&& e) : has_value_(false) { new (&err_) E(std::move(e).value()); }

    expected(const expected& o) : has_value_(o.has_value_) {
        if (has_value_) new (&val_) T(o.val_); else new (&err_) E(o.err_);
    }
    expected(expected&& o) noexcept : has_value_(o.has_value_) {
        if (has_value_) new (&val_) T(std::move(o.val_)); else new (&err_) E(std::move(o.err_));
    }
    expected& operator=(const expected& o) {
        if (this != &o) { destroy(); has_value_ = o.has_value_; if (has_value_) new (&val_) T(o.val_); else new (&err_) E(o.err_); }
        return *this;
    }
    expected& operator=(expected&& o) noexcept {
        if (this != &o) { destroy(); has_value_ = o.has_value_; if (has_value_) new (&val_) T(std::move(o.val_)); else new (&err_) E(std::move(o.err_)); }
        return *this;
    }
    ~expected() { destroy(); }

    constexpr bool has_value() const noexcept { return has_value_; }
    constexpr explicit operator bool() const noexcept { return has_value_; }

    constexpr const T& value() const& { return val_; }
    constexpr T& value() & { return val_; }
    constexpr const T& operator*() const& noexcept { return val_; }
    constexpr T& operator*() & noexcept { return val_; }
    constexpr const T* operator->() const noexcept { return &val_; }
    constexpr T* operator->() noexcept { return &val_; }

    constexpr const E& error() const& { return err_; }
    constexpr E& error() & { return err_; }

  private:
    void destroy() { if (has_value_) val_.~T(); else err_.~E(); }
    union { T val_; E err_; };
    bool has_value_;
};

// Specialization for void value type: expected<void, E>.
template <typename E>
class expected<void, E> {
  public:
    constexpr expected() noexcept : has_value_(true) {}

    constexpr expected(const unexpected<E>& e) : has_value_(false), err_(e.value()) {}
    constexpr expected(unexpected<E>&& e) : has_value_(false), err_(std::move(e).value()) {}

    constexpr bool has_value() const noexcept { return has_value_; }
    constexpr explicit operator bool() const noexcept { return has_value_; }

    constexpr const E& error() const& { return err_; }
    constexpr E& error() & { return err_; }

  private:
    bool has_value_;
    E err_{};
};

}  // namespace tl
