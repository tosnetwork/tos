const unsigned NAME(BootMask) = (~static_cast<unsigned>(0))
                                / NAME(BytesPerWord);

const unsigned NAME(BootShift) UNUSED = 32 - avata::util::log(NAME(BytesPerWord));

inline unsigned LABEL(codeMapSize)(unsigned codeSize)
{
  return avata::util::ceilingDivide(codeSize, TargetBitsPerWord)
         * TargetBytesPerWord;
}

inline unsigned LABEL(heapMapSize)(unsigned heapSize)
{
  return avata::util::ceilingDivide(heapSize,
                                    TargetBitsPerWord * TargetBytesPerWord)
         * TargetBytesPerWord;
}

inline object LABEL(bootObject)(LABEL(uintptr_t) * heap, unsigned offset)
{
  if (offset) {
    return reinterpret_cast<object>(heap + offset - 1);
  } else {
    return 0;
  }
}
