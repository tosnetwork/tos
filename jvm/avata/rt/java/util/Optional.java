/* Avata consensus-profile java.util.Optional — JDK8u deterministic subset. */

package java.util;

import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;

public final class Optional<T> {
  private static final Optional<?> EMPTY = new Optional<>(null);

  private final T value;

  private Optional(T value) {
    this.value = value;
  }

  public static <T> Optional<T> empty() {
    return (Optional<T>) EMPTY;
  }

  public static <T> Optional<T> of(T value) {
    if (value == null) throw new NullPointerException();
    return new Optional<>(value);
  }

  public static <T> Optional<T> ofNullable(T value) {
    return value == null ? (Optional<T>) EMPTY : new Optional<>(value);
  }

  public T get() {
    if (value == null) throw new NoSuchElementException("No value present");
    return value;
  }

  public boolean isPresent() {
    return value != null;
  }

  public void ifPresent(Consumer<? super T> consumer) {
    if (value != null) consumer.accept(value);
  }

  public Optional<T> filter(Predicate<? super T> predicate) {
    if (!isPresent()) return this;
    return predicate.test(value) ? this : (Optional<T>) EMPTY;
  }

  public <U> Optional<U> map(Function<? super T, ? extends U> mapper) {
    if (!isPresent()) return (Optional<U>) EMPTY;
    return Optional.ofNullable(mapper.apply(value));
  }

  public <U> Optional<U> flatMap(Function<? super T, Optional<U>> mapper) {
    if (!isPresent()) return (Optional<U>) EMPTY;
    Optional<U> result = mapper.apply(value);
    if (result == null) throw new NullPointerException();
    return result;
  }

  public T orElse(T other) {
    return value != null ? value : other;
  }

  public T orElseGet(Supplier<? extends T> other) {
    return value != null ? value : other.get();
  }

  public <X extends Throwable> T orElseThrow(Supplier<? extends X> exceptionSupplier) throws X {
    if (value != null) return value;
    throw exceptionSupplier.get();
  }

  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (!(obj instanceof Optional)) return false;
    Optional<?> other = (Optional<?>) obj;
    return (value == null ? other.value == null : value.equals(other.value));
  }

  public int hashCode() {
    return value == null ? 0 : value.hashCode();
  }

  public String toString() {
    return value != null ? "Optional[" + value + "]" : "Optional.empty";
  }
}
