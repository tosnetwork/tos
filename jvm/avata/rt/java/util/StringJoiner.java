/* Avata consensus-profile java.util.StringJoiner — JDK8u semantics. */

package java.util;

public final class StringJoiner {
  private final String delimiter;
  private final String prefix;
  private final String suffix;
  private String emptyValue;
  private StringBuilder value;

  public StringJoiner(CharSequence delimiter) {
    this(delimiter, "", "");
  }

  public StringJoiner(CharSequence delimiter, CharSequence prefix, CharSequence suffix) {
    if (delimiter == null || prefix == null || suffix == null)
      throw new NullPointerException();
    this.delimiter = delimiter.toString();
    this.prefix    = prefix.toString();
    this.suffix    = suffix.toString();
    this.emptyValue = this.prefix + this.suffix;
  }

  public StringJoiner setEmptyValue(CharSequence emptyValue) {
    if (emptyValue == null) throw new NullPointerException();
    this.emptyValue = emptyValue.toString();
    return this;
  }

  public StringJoiner add(CharSequence newElement) {
    prepareBuilder().append(newElement);
    return this;
  }

  public StringJoiner merge(StringJoiner other) {
    if (other.value != null) {
      // append other's content (strip prefix from other)
      String otherStr = other.value.toString();
      String otherContent = otherStr.substring(other.prefix.length());
      prepareBuilder().append(otherContent);
    }
    return this;
  }

  private StringBuilder prepareBuilder() {
    if (value != null) {
      value.append(delimiter);
    } else {
      value = new StringBuilder().append(prefix);
    }
    return value;
  }

  public int length() {
    return (value != null ? value.length() + suffix.length() : emptyValue.length());
  }

  public String toString() {
    if (value == null) {
      return emptyValue;
    }
    if (suffix.isEmpty()) {
      return value.toString();
    }
    return value.toString() + suffix;
  }
}
