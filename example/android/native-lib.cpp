/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2017-2020 Telegram Systems LLP
    Copyright 2025-2026 TOS Blockchain Teams
*/
// The JNI bridge between the Java Client (src/org/tos/toslib/Client.java) and
// toslib. The native methods are registered by name in JNI_OnLoad, so the Java
// package is the one PACKAGE_NAME gives at build time.
#include <cstdint>
#include <cstdlib>
#include <jni.h>
#include <string>
#include <utility>

#include "auto/tl/toslib_api.h"
#include "tl/tl_jni_object.h"
#include "toslib/Client.h"

namespace td_jni {

// A function the Java side could not have built is a programming error in the
// binding, not a runtime condition, so it stops the process like any other
// broken invariant.
static toslib_api::object_ptr<toslib_api::Function> fetch_function(JNIEnv *env, jobject function) {
  td::jni::reset_parse_error();
  auto result = toslib_api::Function::fetch(env, function);
  if (td::jni::have_parse_error() || result == nullptr) {
    std::abort();
  }
  return result;
}

static toslib::Client *get_client(jlong client_id) {
  return reinterpret_cast<toslib::Client *>(static_cast<std::uintptr_t>(client_id));
}

static jlong Client_createNativeClient(JNIEnv *, jclass) {
  return static_cast<jlong>(reinterpret_cast<std::uintptr_t>(new toslib::Client()));
}

static void Client_nativeClientSend(JNIEnv *env, jclass, jlong client_id, jlong id, jobject function) {
  get_client(client_id)->send({static_cast<std::uint64_t>(id), fetch_function(env, function)});
}

// Fills ids and events with the answers ready within timeout, at most as many as
// the arrays hold, and returns how many it filled.
static jint Client_nativeClientReceive(JNIEnv *env, jclass, jlong client_id, jlongArray ids, jobjectArray events,
                                       jdouble timeout) {
  auto client = get_client(client_id);
  const jsize capacity = env->GetArrayLength(ids);
  if (capacity == 0 || env->GetArrayLength(events) < capacity) {
    return 0;
  }
  jsize filled = 0;

  auto response = client->receive(timeout);
  while (response.object) {
    const auto result_id = static_cast<jlong>(response.id);
    env->SetLongArrayRegion(ids, filled, 1, &result_id);

    jobject object = nullptr;
    response.object->store(env, object);
    env->SetObjectArrayElement(events, filled, object);
    env->DeleteLocalRef(object);

    filled++;
    if (filled == capacity) {
      break;
    }
    response = client->receive(0);
  }
  return filled;
}

static jobject Client_nativeClientExecute(JNIEnv *env, jclass, jobject function) {
  jobject result = nullptr;
  toslib::Client::execute({0, fetch_function(env, function)}).object->store(env, result);
  return result;
}

static void Client_destroyNativeClient(JNIEnv *, jclass, jlong client_id) {
  delete get_client(client_id);
}

static jstring Object_toString(JNIEnv *env, jobject object) {
  return td::jni::to_jstring(env, to_string(toslib_api::Object::fetch(env, object)));
}

static jstring Function_toString(JNIEnv *env, jobject object) {
  return td::jni::to_jstring(env, to_string(toslib_api::Function::fetch(env, object)));
}

static constexpr jint JAVA_VERSION = JNI_VERSION_1_6;

static jint register_native(JavaVM *vm) {
  JNIEnv *env = nullptr;
  if (vm->GetEnv(reinterpret_cast<void **>(&env), JAVA_VERSION) != JNI_OK) {
    return -1;
  }

  auto register_method = [env](jclass clazz, std::string name, std::string signature, auto function_ptr) {
    td::jni::register_native_method(env, clazz, std::move(name), std::move(signature),
                                    reinterpret_cast<void *>(function_ptr));
  };

  auto client_class = td::jni::get_jclass(env, PACKAGE_NAME "/Client");
  auto object_class = td::jni::get_jclass(env, PACKAGE_NAME "/TosApi$Object");
  auto function_class = td::jni::get_jclass(env, PACKAGE_NAME "/TosApi$Function");

#define TD_OBJECT "L" PACKAGE_NAME "/TosApi$Object;"
#define TD_FUNCTION "L" PACKAGE_NAME "/TosApi$Function;"
  register_method(client_class, "createNativeClient", "()J", Client_createNativeClient);
  register_method(client_class, "nativeClientSend", "(JJ" TD_FUNCTION ")V", Client_nativeClientSend);
  register_method(client_class, "nativeClientReceive", "(J[J[" TD_OBJECT "D)I", Client_nativeClientReceive);
  register_method(client_class, "nativeClientExecute", "(" TD_FUNCTION ")" TD_OBJECT, Client_nativeClientExecute);
  register_method(client_class, "destroyNativeClient", "(J)V", Client_destroyNativeClient);

  register_method(object_class, "toString", "()Ljava/lang/String;", Object_toString);
  register_method(function_class, "toString", "()Ljava/lang/String;", Function_toString);
#undef TD_FUNCTION
#undef TD_OBJECT

  td::jni::init_vars(env, PACKAGE_NAME);
  toslib_api::Object::init_jni_vars(env, PACKAGE_NAME);
  toslib_api::Function::init_jni_vars(env, PACKAGE_NAME);
  return JAVA_VERSION;
}

}  // namespace td_jni

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *) {
  static jint jni_version = td_jni::register_native(vm);  // once per process
  return jni_version;
}
