/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.util;

import java.io.Serializable;

/**
 * @author zsombor
 * 
 */
public class BitSet implements Serializable, Cloneable {

  final static int  BITS_PER_LONG       = 64;
  final static int  BITS_PER_LONG_SHIFT = 6;
  final static long MASK                = 0xFFFFFFFFFFFFFFFFL;

  private long[]    bits;

  private static int longPosition(int index) {
    return index >> BITS_PER_LONG_SHIFT;
  }

  private static long bitPosition(int index) {
    return 1L << (index % BITS_PER_LONG);
  }

  private static long getTrueMask(int fromIndex, int toIndex) {
    int currentRange = toIndex - fromIndex;
    return (MASK >>> (BITS_PER_LONG - currentRange)) << (fromIndex % BITS_PER_LONG);
  }

  public BitSet(int bitLength) {
    if (bitLength < 0) {
      throw new NegativeArraySizeException();
    }

    if (bitLength % BITS_PER_LONG == 0) {
      enlarge(longPosition(bitLength));
    } else {
      enlarge(longPosition(bitLength) + 1);
    }
  }

  public BitSet() {
    enlarge(1);
  }

  public void and(BitSet otherBits) {
    int min = Math.min(bits.length, otherBits.bits.length);
    for (int i = 0; i < min; i++) {
      bits[i] &= otherBits.bits[i];
    }
    for (int i = min; i < bits.length; i++) { 
      bits[i] = 0;
    }
  }

  public void andNot(BitSet otherBits) {
    int max = Math.max(bits.length, otherBits.bits.length);
    enlarge(max);
    int min = Math.min(bits.length, otherBits.bits.length);
    for (int i = 0; i < min; i++) {
      bits[i] &= ~otherBits.bits[i];
    }
  }

  public void or(BitSet otherBits) {
    int max = Math.max(bits.length, otherBits.bits.length);
    enlarge(max);
    int min = Math.min(bits.length, otherBits.bits.length);
    for (int i = 0; i < min; i++) {
      bits[i] |= otherBits.bits[i];
    }
  }

  public void xor(BitSet otherBits) {
    int max = Math.max(bits.length, otherBits.bits.length);
    enlarge(max);
    int min = Math.min(bits.length, otherBits.bits.length);
    for (int i = 0; i < min; i++) {
      bits[i] ^= otherBits.bits[i];
    }
  }

  private void enlarge(int newPartition) {
    if (bits == null || bits.length < (newPartition + 1)) {
      long[] newBits = new long[newPartition + 1];
      if (bits != null) {
        System.arraycopy(bits, 0, newBits, 0, bits.length);
      }
      bits = newBits;
    }
  }

  public boolean get(int index) {
    if (index < 0) {
      throw new IndexOutOfBoundsException();
    }

    int pos = longPosition(index);
    if (pos < bits.length) {
      return (bits[pos] & bitPosition(index)) != 0;
    }
    return false;
  }

  public void flip(int index) {
    flip(index, index+1);
  }

  public void flip(int fromIndex, int toIndex) {
    if (fromIndex > toIndex || fromIndex < 0 || toIndex < 0) {
      throw new IndexOutOfBoundsException();
    } else if (fromIndex != toIndex) {
      MaskInfoIterator iter = new MaskInfoIterator(fromIndex, toIndex);
      enlarge(iter.getLastPartition());
      while (iter.hasNext()) {
        MaskInfo info = iter.next();
        bits[info.partitionIndex] ^= info.mask;
      }
    }
  }

  public void set(int index) {
    if (index < 0) {
      throw new IndexOutOfBoundsException();
    }

    int pos = longPosition(index);
    enlarge(pos);
    bits[pos] |= bitPosition(index);
  }

  public void set(int start, int end) {
    checkRange(start, end);
    if (start == end) {
      return;
    }

    MaskInfoIterator iter = new MaskInfoIterator(start, end);
    enlarge(iter.getLastPartition());
    while (iter.hasNext()) {
      MaskInfo info = iter.next();
      bits[info.partitionIndex] |= info.mask;
    }
  }

  public void clear(int index) {
    if (index < 0) {
      throw new IndexOutOfBoundsException();
    }

    int pos = longPosition(index);
    if (pos < bits.length) {
      bits[pos] &= (MASK ^ bitPosition(index));
    }
  }

  public void clear(int start, int end) {
    checkRange(start, end);
    if (start == end) {
      return;
    }

    MaskInfoIterator iter = new MaskInfoIterator(start, end);
    while (iter.hasNext()) {
      MaskInfo info = iter.next();
      if (info.partitionIndex < bits.length) {
        bits[info.partitionIndex] &= (MASK ^ info.mask);
      }
    }
  }

  public void clear() {
    for (int i = 0; i < bits.length; i++) {
      bits[i] = 0;
    }
  }

  public boolean isEmpty() {
    for (int i = 0; i < bits.length; i++) {
      if (bits[i] != 0) {
        return false;
      }
    }
    return true;
  }

  public boolean intersects(BitSet otherBits) {
    int min = Math.min(bits.length, otherBits.bits.length);
    for (int i = 0; i < min; i++) {
      if ((bits[i] & otherBits.bits[i]) != 0) {
        return true;
      }
    }
    return false;
  }

  public int length() {
    for (int i = bits.length - 1; i >= 0; --i) {
      long word = bits[i];
      if (word != 0) {
        return (i << BITS_PER_LONG_SHIFT)
          + BITS_PER_LONG - numberOfLeadingZeros(word);
      }
    }
    return 0;
  }

  public int nextSetBit(int fromIndex) {
    return nextBit(fromIndex, false);
  }

  private int nextBit(int fromIndex, boolean bitClear) {
    if (fromIndex < 0) {
      throw new IndexOutOfBoundsException();
    }

    int pos = longPosition(fromIndex);
    if (pos >= bits.length) {
      return bitClear ? fromIndex : -1;
    }

    long word = (bitClear ? ~bits[pos] : bits[pos])
      & (MASK << (fromIndex % BITS_PER_LONG));
    while (true) {
      if (word != 0) {
        return (pos << BITS_PER_LONG_SHIFT) + numberOfTrailingZeros(word);
      }

      if (++pos == bits.length) {
        return bitClear ? pos << BITS_PER_LONG_SHIFT : -1;
      }
      word = bitClear ? ~bits[pos] : bits[pos];
    }
  }

  public int nextClearBit(int fromIndex) {
    return nextBit(fromIndex, true);
  }

  public int cardinality() {
    int numSetBits = 0;
    for (int i = nextSetBit(0); i >= 0; i = nextSetBit(i+1)) {
      ++numSetBits;
    }
    
    return numSetBits;
  }

  private static void checkRange(int fromIndex, int toIndex) {
    if (fromIndex < 0 || toIndex < 0 || fromIndex > toIndex) {
      throw new IndexOutOfBoundsException();
    }
  }

  private static int numberOfLeadingZeros(long value) {
    int count = 0;
    for (int i = BITS_PER_LONG - 1; i >= 0; --i) {
      if ((value & (1L << i)) != 0) {
        return count;
      }
      count++;
    }
    return BITS_PER_LONG;
  }

  private static int numberOfTrailingZeros(long value) {
    int count = 0;
    for (int i = 0; i < BITS_PER_LONG; ++i) {
      if ((value & (1L << i)) != 0) {
        return count;
      }
      count++;
    }
    return BITS_PER_LONG;
  }

  private static class MaskInfoIterator implements Iterator<MaskInfo> {
    private int basePartition;
    private int numPartitionsToTraverse;
    private int currentPartitionOffset;
    private int toIndex;
    private int currentFirstIndex;

    public MaskInfoIterator(int fromIndex, int toIndex) {
      this.basePartition = longPosition(fromIndex);
      this.numPartitionsToTraverse = longPosition(toIndex - 1) - basePartition + 1;
      this.currentPartitionOffset = 0;
      this.toIndex = toIndex;
      this.currentFirstIndex = fromIndex;
    }

    public MaskInfo next() {
      int currentToIndex = Math.min(toIndex, (basePartition + currentPartitionOffset + 1) * BITS_PER_LONG);
      long mask = getTrueMask(currentFirstIndex, currentToIndex);
      MaskInfo info = new MaskInfo(mask, basePartition + currentPartitionOffset);
      currentFirstIndex = currentToIndex;
      currentPartitionOffset++;
      return info;
    }

    public boolean hasNext() {
      return currentPartitionOffset < numPartitionsToTraverse;
    }

    public void remove() {
      throw new UnsupportedOperationException();
    }

    public int getLastPartition() {
      return basePartition + numPartitionsToTraverse - 1;
    }
  }

  private static class MaskInfo {
    public long mask;
    public int partitionIndex;

    public MaskInfo(long mask, int partitionIndex) {
      this.mask = mask;
      this.partitionIndex = partitionIndex;
    }
  }
}
