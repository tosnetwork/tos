/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

#include "avata/machine.h"
#include "avata/constants.h"
#include "avata/processor.h"
#include "avata/util.h"

#include <avata/util/runtime-array.h>

using namespace vm;

namespace {

int64_t search(Thread* t,
               GcClassSpace* loader,
               GcString* name,
               GcClass* (*op)(Thread*, GcClassSpace*, GcByteArray*),
               bool replaceDots)
{
  if (LIKELY(name)) {
    PROTECT(t, loader);
    PROTECT(t, name);

    GcByteArray* n = makeByteArray(t, name->length(t) + 1);
    char* s = reinterpret_cast<char*>(n->body().begin());
    stringChars(t, name, s);

    if (replaceDots) {
      replace('.', '/', s);
    }

    return reinterpret_cast<int64_t>(op(t, loader, n));
  } else {
    throwNew(t, GcNullPointerException::Type);
  }
}

GcClass* resolveSystemClassThrow(Thread* t,
                                 GcClassSpace* loader,
                                 GcByteArray* spec)
{
  return resolveSystemClass(
      t, loader, spec, true, GcClassNotFoundException::Type);
}

}  // namespace

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_internal_Classes_toVMClass(Thread* t, object, uintptr_t* arguments)
{
  return reinterpret_cast<intptr_t>(
      cast<GcJclass>(t, reinterpret_cast<object>(arguments[0]))->vmClass());
}

extern "C" AVATA_EXPORT void JNICALL
    Avata_java_internal_Classes_initialize(Thread* t, object, uintptr_t* arguments)
{
  GcClass* this_ = cast<GcClass>(t, reinterpret_cast<object>(arguments[0]));

  initClass(t, this_);
}

extern "C" AVATA_EXPORT void JNICALL
    Avata_java_internal_Classes_acquireClassLock(Thread* t, object, uintptr_t*)
{
  acquire(t, t->m->classLock);
}

extern "C" AVATA_EXPORT void JNICALL
    Avata_java_internal_Classes_releaseClassLock(Thread* t, object, uintptr_t*)
{
  release(t, t->m->classLock);
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_internal_Classes_resolveVMClass(Thread* t, object, uintptr_t* arguments)
{
  GcClassSpace* loader
      = cast<GcClassSpace>(t, reinterpret_cast<object>(arguments[0]));
  GcByteArray* spec
      = cast<GcByteArray>(t, reinterpret_cast<object>(arguments[1]));

  return reinterpret_cast<int64_t>(
      resolveClass(t, loader, spec, true, GcClassNotFoundException::Type));
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_internal_Classes_defineVMClass(Thread* t, object, uintptr_t* arguments)
{
  GcClassSpace* loader
      = cast<GcClassSpace>(t, reinterpret_cast<object>(arguments[0]));
  GcByteArray* b = cast<GcByteArray>(t, reinterpret_cast<object>(arguments[1]));
  int offset = arguments[2];
  int length = arguments[3];

  uint8_t* buffer = static_cast<uint8_t*>(t->m->heap->allocate(length));

  THREAD_RESOURCE2(
      t, uint8_t*, buffer, int, length, t->m->heap->free(buffer, length));

  memcpy(buffer, &b->body()[offset], length);

  return reinterpret_cast<int64_t>(defineClass(t, loader, buffer, length));
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_internal_Classes_makeString(Thread* t, object, uintptr_t* arguments)
{
  GcByteArray* array
      = cast<GcByteArray>(t, reinterpret_cast<object>(arguments[0]));
  int offset = arguments[1];
  int length = arguments[2];

  return reinterpret_cast<int64_t>(
      t->m->classpath->makeString(t, array, offset, length));
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_internal_SystemClassSpace_appClassSpace(Thread* t, object, uintptr_t*)
{
  return reinterpret_cast<int64_t>(roots(t)->appClassSpace());
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_internal_SystemClassSpace_findLoadedVMClass(Thread* t,
                                                    object,
                                                    uintptr_t* arguments)
{
  GcClassSpace* loader
      = cast<GcClassSpace>(t, reinterpret_cast<object>(arguments[0]));
  GcString* name = cast<GcString>(t, reinterpret_cast<object>(arguments[1]));

  return search(t, loader, name, findLoadedClass, true);
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_internal_SystemClassSpace_vmClass(Thread* t,
                                          object,
                                          uintptr_t* arguments)
{
  return reinterpret_cast<int64_t>(
      cast<GcJclass>(t, reinterpret_cast<object>(arguments[0]))->vmClass());
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_internal_SystemClassSpace_findVMClass(Thread* t,
                                              object,
                                              uintptr_t* arguments)
{
  GcClassSpace* loader
      = cast<GcClassSpace>(t, reinterpret_cast<object>(arguments[0]));
  GcString* name = cast<GcString>(t, reinterpret_cast<object>(arguments[1]));

  return search(t, loader, name, resolveSystemClassThrow, true);
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_internal_SystemClassSpace_getClass(Thread* t,
                                           object,
                                           uintptr_t* arguments)
{
  return reinterpret_cast<int64_t>(
      getJClass(t, cast<GcClass>(t, reinterpret_cast<object>(arguments[0]))));
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_internal_Singleton_getObject(Thread* t, object, uintptr_t* arguments)
{
  return reinterpret_cast<int64_t>(singletonObject(
      t,
      cast<GcSingleton>(t, reinterpret_cast<object>(arguments[0])),
      arguments[1]));
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_internal_Singleton_getInt(Thread* t, object, uintptr_t* arguments)
{
  return singletonValue(
      t,
      cast<GcSingleton>(t, reinterpret_cast<object>(arguments[0])),
      arguments[1]);
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_internal_Singleton_getLong(Thread* t, object, uintptr_t* arguments)
{
  int64_t v;
  memcpy(&v,
         &singletonValue(
             t,
             cast<GcSingleton>(t, reinterpret_cast<object>(arguments[0])),
             arguments[1]),
         8);
  return v;
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_internal_Classes_primitiveClass(Thread* t, object, uintptr_t* arguments)
{
  return reinterpret_cast<int64_t>(primitiveClass(t, arguments[0]));
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_lang_Object_toString(Thread* t, object, uintptr_t* arguments)
{
  object this_ = reinterpret_cast<object>(arguments[0]);

  unsigned hash = objectHash(t, this_);
  GcString* s = makeString(
      t, "%s@0x%x", objectClass(t, this_)->name()->body().begin(), hash);

  return reinterpret_cast<int64_t>(s);
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_lang_Object_getVMClass(Thread* t, object, uintptr_t* arguments)
{
  return reinterpret_cast<int64_t>(
      objectClass(t, reinterpret_cast<object>(arguments[0])));
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_lang_Object_hashCode(Thread* t, object, uintptr_t* arguments)
{
  return objectHash(t, reinterpret_cast<object>(arguments[0]));
}

extern "C" AVATA_EXPORT int64_t JNICALL
    Avata_java_lang_Object_clone(Thread* t, object, uintptr_t* arguments)
{
  return reinterpret_cast<int64_t>(
      clone(t, reinterpret_cast<object>(arguments[0])));
}
