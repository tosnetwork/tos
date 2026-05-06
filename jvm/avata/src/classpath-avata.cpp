/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

#include "avata/machine.h"
#include "avata/classpath-common.h"
#include "avata/process.h"

#include <avata/util/runtime-array.h>
#include <stdio.h>

using namespace vm;

namespace {

namespace local {

class MyClasspath : public Classpath {
 public:
  MyClasspath(Allocator* allocator) : allocator(allocator)
  {
  }

  virtual GcJclass* makeJclass(Thread* t, GcClass* class_)
  {
    return vm::makeJclass(t, class_);
  }

  virtual GcString* makeString(Thread* t,
                               object array,
                               int32_t offset,
                               int32_t length)
  {
    return vm::makeString(t, array, offset, length, 0);
  }

  virtual GcExecutionContext* makeThread(Thread* t, Thread* parent)
  {
    GcExecutionGroup* group;
    if (parent) {
      group = parent->javaThread->group();
    } else {
      group = makeExecutionGroup(t, 0, 0, 0);
    }

    const unsigned NewState = 0;
    const unsigned NormalPriority = 5;

    return vm::makeExecutionContext(t,
                                    0,
                                    0,
                                    0,
                                    0,
                                    0,
                                    NewState,
                                    NormalPriority,
                                    0,
                                    0,
                                    roots(t)->appClassSpace(),
                                    0,
                                    0,
                                    group,
                                    0);
  }

  virtual void clearInterrupted(Thread*)
  {
    // ignore
  }

  virtual void runThread(Thread* t)
  {
    GcMethod* method = resolveMethod(t,
                                     roots(t)->bootClassSpace(),
                                     "java/internal/ExecutionContext",
                                     "run",
                                     "(Ljava/internal/ExecutionContext;)V");

    t->m->processor->invoke(t, method, 0, t->javaThread);
  }

  virtual void resolveNative(Thread* t, GcMethod* method)
  {
    vm::resolveNative(t, method);
  }

  virtual void interceptMethods(Thread*)
  {
    // ignore
  }

  virtual void preBoot(Thread*)
  {
    // ignore
  }

  virtual bool mayInitClasses()
  {
    return true;
  }

  virtual void boot(Thread*)
  {
    // ignore
  }

  virtual const char* bootClasspath()
  {
    return AVATA_CLASSPATH;
  }

  virtual bool canTailCall(Thread* t UNUSED,
                           GcMethod*,
                           GcByteArray* calleeClassName,
                           GcByteArray* calleeMethodName,
                           GcByteArray*)
  {
    // Native library loading is trapped in java.lang.System before reaching
    // this path, so normal tail-call eligibility is enough for the rt profile.
    return true;
  }

  virtual GcClassSpace* libraryClassSpace(Thread* t, GcMethod* caller)
  {
    return (caller->class_() == type(t, Gc::ClassSpaceType)
            and t->libraryLoadStack)
               ? t->libraryLoadStack->classSpace
               : caller->class_()->loader();
  }

  virtual void shutDown(Thread*)
  {
    // ignore
  }

  virtual void dispose()
  {
    allocator->free(this, sizeof(*this));
  }

  Allocator* allocator;
};

}  // namespace local

}  // namespace

namespace vm {

Classpath* makeClasspath(System*,
                         Allocator* allocator,
                         const char*)
{
  return new (allocator->allocate(sizeof(local::MyClasspath)))
      local::MyClasspath(allocator);
}

}  // namespace vm

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_internal_Classes_getCallerMethod(Thread* t, object, uintptr_t*)
{
  return reinterpret_cast<int64_t>(getCaller(t, 2));
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_internal_Classes_invokeVMMethod(Thread* t,
                                       object,
                                       uintptr_t* arguments)
{
  GcMethod* method = cast<GcMethod>(t, reinterpret_cast<object>(arguments[0]));
  unsigned returnCode = method->returnCode();

  return reinterpret_cast<int64_t>(translateInvokeResult(
      t,
      returnCode,
      t->m->processor->invokeArray(t,
                                   method,
                                   reinterpret_cast<object>(arguments[1]),
                                   reinterpret_cast<object>(arguments[2]))));
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_internal_VMArray_getLength(Thread* t, object, uintptr_t* arguments)
{
  object array = reinterpret_cast<object>(arguments[0]);

  if (LIKELY(array)) {
    unsigned elementSize = objectClass(t, array)->arrayElementSize();

    if (LIKELY(elementSize)) {
      return fieldAtOffset<uintptr_t>(array, BytesPerWord);
    } else {
      throwNew(t, GcIllegalArgumentException::Type);
    }
  } else {
    throwNew(t, GcNullPointerException::Type);
  }
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_internal_VMArray_makeObjectArray(Thread* t,
                                        object,
                                        uintptr_t* arguments)
{
  GcJclass* elementType
      = cast<GcJclass>(t, reinterpret_cast<object>(arguments[0]));
  int length = arguments[1];

  return reinterpret_cast<int64_t>(
      makeObjectArray(t, elementType->vmClass(), length));
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_lang_Float_floatToRawIntBits(Thread*,
                                            object,
                                            uintptr_t* arguments)
{
  return static_cast<int32_t>(*arguments);
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_lang_Float_intBitsToFloat(Thread*, object, uintptr_t* arguments)
{
  return static_cast<int32_t>(*arguments);
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_lang_Double_doubleToRawLongBits(Thread*,
                                               object,
                                               uintptr_t* arguments)
{
  int64_t v;
  memcpy(&v, arguments, 8);
  return v;
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_lang_Double_longBitsToDouble(Thread*,
                                            object,
                                            uintptr_t* arguments)
{
  int64_t v;
  memcpy(&v, arguments, 8);
  return v;
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_lang_String_intern(Thread* t, object, uintptr_t* arguments)
{
  object this_ = reinterpret_cast<object>(arguments[0]);

  return reinterpret_cast<int64_t>(intern(t, this_));
}

namespace {

FILE* systemStream(bool error)
{
  return error ? stderr : stdout;
}

void writeStandardBytes(FILE* stream, GcByteArray* buffer, int32_t offset,
                        int32_t length)
{
  fwrite(&buffer->body()[offset], 1, length, stream);
  fflush(stream);
}

}  // namespace

extern "C" AVATA_EXPORT void JNICALL
    Avata_java_lang_System_writeStdoutByte(Thread*,
                                           object,
                                           uintptr_t* arguments)
{
  fputc(static_cast<unsigned char>(arguments[0]), stdout);
  fflush(stdout);
}

extern "C" AVATA_EXPORT void JNICALL
    Avata_java_lang_System_writeStdout(Thread* t,
                                       object,
                                       uintptr_t* arguments)
{
  GcByteArray* buffer
      = cast<GcByteArray>(t, reinterpret_cast<object>(arguments[0]));
  writeStandardBytes(systemStream(false), buffer, arguments[1], arguments[2]);
}

extern "C" AVATA_EXPORT void JNICALL
    Avata_java_lang_System_writeStderrByte(Thread*,
                                           object,
                                           uintptr_t* arguments)
{
  fputc(static_cast<unsigned char>(arguments[0]), stderr);
  fflush(stderr);
}

extern "C" AVATA_EXPORT void JNICALL
    Avata_java_lang_System_writeStderr(Thread* t,
                                       object,
                                       uintptr_t* arguments)
{
  GcByteArray* buffer
      = cast<GcByteArray>(t, reinterpret_cast<object>(arguments[0]));
  writeStandardBytes(systemStream(true), buffer, arguments[1], arguments[2]);
}

extern "C" AVATA_EXPORT void JNICALL
    Avata_java_lang_System_arraycopy(Thread* t, object, uintptr_t* arguments)
{
  arrayCopy(t,
            reinterpret_cast<object>(arguments[0]),
            arguments[1],
            reinterpret_cast<object>(arguments[2]),
            arguments[3],
            arguments[4]);
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_lang_System_identityHashCode(Thread* t,
                                            object,
                                            uintptr_t* arguments)
{
  object o = reinterpret_cast<object>(arguments[0]);

  if (LIKELY(o)) {
    return objectHash(t, o);
  } else {
    throwNew(t, GcNullPointerException::Type);
  }
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_lang_Throwable_trace(Thread* t, object, uintptr_t* arguments)
{
  return reinterpret_cast<int64_t>(getTrace(t, arguments[0]));
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_lang_Throwable_resolveTrace(Thread* t,
                                           object,
                                           uintptr_t* arguments)
{
  object trace = reinterpret_cast<object>(*arguments);
  PROTECT(t, trace);

  unsigned length = objectArrayLength(t, trace);
  GcClass* elementType = type(t, GcStackTraceElement::Type);
  object array = makeObjectArray(t, elementType, length);
  PROTECT(t, array);

  for (unsigned i = 0; i < length; ++i) {
    GcStackTraceElement* ste = makeStackTraceElement(
        t, cast<GcTraceElement>(t, objectArrayBody(t, trace, i)));
    reinterpret_cast<GcArray*>(array)->setBodyElement(t, i, ste);
  }

  return reinterpret_cast<int64_t>(array);
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_internal_Classes_isAssignableFrom(Thread* t,
                                         object,
                                         uintptr_t* arguments)
{
  GcClass* this_ = cast<GcClass>(t, reinterpret_cast<object>(arguments[0]));
  GcClass* that = cast<GcClass>(t, reinterpret_cast<object>(arguments[1]));

  if (LIKELY(that)) {
    return vm::isAssignableFrom(t, this_, that);
  } else {
    throwNew(t, GcNullPointerException::Type);
  }
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_internal_Memory_used(Thread* t, object, uintptr_t*)
{
  return contractMemoryUsed(t);
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_internal_Memory_remaining(Thread* t, object, uintptr_t*)
{
  return contractMemoryRemaining(t);
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_internal_Memory_limit(Thread* t, object, uintptr_t*)
{
  return contractMemoryLimit(t);
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_internal_Classes_getVMClass(Thread* t, object, uintptr_t* arguments)
{
  return reinterpret_cast<int64_t>(
      objectClass(t, reinterpret_cast<object>(arguments[0])));
}
