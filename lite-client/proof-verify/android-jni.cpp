/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <jni.h>
#include <vector>
#include "embedded.h"
namespace {
constexpr size_t kMaxMaterial = 64u << 20;
constexpr size_t kMaxJson = 1u << 20;
bool read(JNIEnv *env, jbyteArray array, size_t limit, std::vector<uint8_t> &out) {
  if (!array) return false;
  const auto n = env->GetArrayLength(array);
  if (n < 0 || static_cast<size_t>(n) > limit) return false;
  out.resize(static_cast<size_t>(n));
  if (n) env->GetByteArrayRegion(array, 0, n, reinterpret_cast<jbyte *>(out.data()));
  return !env->ExceptionCheck();
}
jobjectArray refuse(JNIEnv *env) {
  if (!env->ExceptionCheck()) {
    auto type = env->FindClass("java/lang/SecurityException");
    if (type) env->ThrowNew(type, "Proof verification refused");
  }
  return nullptr;
}
}
extern "C" JNIEXPORT jobjectArray JNICALL
Java_network_tos_security_pq_V5R2ProofNative_nativeVerify(JNIEnv *env, jobject,
    jbyteArray anchor, jbyteArray request, jbyteArray state, jlong now,
    jintArray kinds, jobjectArray material) {
  try {
    if (!kinds || !material || now <= 0) return refuse(env);
    const auto count = env->GetArrayLength(kinds);
    if (count < 0 || count > 1045 || env->GetArrayLength(material) != count) return refuse(env);
    std::vector<uint8_t> a, r, s;
    if (!read(env, anchor, kMaxJson, a) || !read(env, request, kMaxJson, r) || !read(env, state, kMaxJson, s)) return refuse(env);
    std::vector<jint> tags(static_cast<size_t>(count));
    if (count) env->GetIntArrayRegion(kinds, 0, count, tags.data());
    if (env->ExceptionCheck()) return nullptr;
    std::vector<std::vector<uint8_t>> storage(static_cast<size_t>(count));
    std::vector<tos_proof_material> parts;
    size_t total = 0;
    for (jsize i = 0; i < count; ++i) {
      auto item = static_cast<jbyteArray>(env->GetObjectArrayElement(material, i));
      if (!item || tags[i] < 1 || tags[i] > 7) { if (item) env->DeleteLocalRef(item); return refuse(env); }
      const bool ok = read(env, item, kMaxMaterial - total, storage[i]);
      env->DeleteLocalRef(item);
      if (!ok || storage[i].empty()) return refuse(env);
      total += storage[i].size();
      parts.push_back({static_cast<uint32_t>(tags[i]), storage[i].data(), storage[i].size()});
    }
    std::vector<char> output(kMaxMaterial), next(kMaxJson);
    size_t output_size = 0, next_size = 0;
    const int status = tos_proof_verify_embedded(reinterpret_cast<const char *>(a.data()), a.size(),
        reinterpret_cast<const char *>(r.data()), r.size(), reinterpret_cast<const char *>(s.data()), s.size(),
        now, parts.data(), parts.size(), output.data(), output.size(), &output_size, next.data(), next.size(), &next_size);
    if (status != 0) return refuse(env);
    auto bytes = env->FindClass("[B");
    if (!bytes) return nullptr;
    auto result = env->NewObjectArray(2, bytes, nullptr);
    env->DeleteLocalRef(bytes);
    if (!result) return nullptr;
    for (int i = 0; i < 2; ++i) {
      const size_t size = i == 0 ? output_size : next_size;
      auto value = env->NewByteArray(static_cast<jsize>(size));
      if (!value) return nullptr;
      env->SetByteArrayRegion(value, 0, static_cast<jsize>(size), reinterpret_cast<const jbyte *>(i == 0 ? output.data() : next.data()));
      if (!env->ExceptionCheck()) env->SetObjectArrayElement(result, i, value);
      env->DeleteLocalRef(value);
      if (env->ExceptionCheck()) return nullptr;
    }
    return result;
  } catch (...) { return refuse(env); }
}

#include <string>
#include "persisted.h"
extern "C" JNIEXPORT jbyteArray JNICALL
Java_network_tos_security_pq_V5R2ProofNative_nativeVerifyLivePersisted(JNIEnv *env, jobject,
    jstring directory, jboolean initialize, jbyteArray anchor, jbyteArray request,
    jlong now, jintArray kinds, jobjectArray material) {
  auto fail = [&]() -> jbyteArray { refuse(env); return nullptr; };
  try {
    if (!directory || env->GetStringUTFLength(directory) > 4096 || !kinds || !material || now <= 0) return fail();
    const char *chars = env->GetStringUTFChars(directory, nullptr);
    if (!chars) return nullptr;
    std::string path;
    try { path.assign(chars); } catch (...) { env->ReleaseStringUTFChars(directory, chars); throw; }
    env->ReleaseStringUTFChars(directory, chars);
    if (path.empty()) return fail();
    const auto count = env->GetArrayLength(kinds);
    if (count < 0 || count > 1045 || env->GetArrayLength(material) != count) return fail();
    std::vector<uint8_t> a, r;
    if (!read(env, anchor, kMaxJson, a) || !read(env, request, kMaxJson, r)) return fail();
    std::vector<jint> tags(static_cast<size_t>(count));
    if (count) env->GetIntArrayRegion(kinds, 0, count, tags.data());
    if (env->ExceptionCheck()) return nullptr;
    std::vector<std::vector<uint8_t>> storage(static_cast<size_t>(count));
    std::vector<tos_proof_material> parts;
    size_t total = 0;
    for (jsize i = 0; i < count; ++i) {
      auto item = static_cast<jbyteArray>(env->GetObjectArrayElement(material, i));
      if (!item || tags[i] < 1 || tags[i] > 7) { if (item) env->DeleteLocalRef(item); return fail(); }
      const bool ok = read(env, item, kMaxMaterial - total, storage[i]);
      env->DeleteLocalRef(item);
      if (!ok || storage[i].empty()) return fail();
      total += storage[i].size();
      parts.push_back({static_cast<uint32_t>(tags[i]), storage[i].data(), storage[i].size()});
    }
    std::vector<char> output(kMaxMaterial);
    size_t size = 0;
    const int status = tos_proof_verify_live_persisted(path.c_str(), initialize == JNI_TRUE ? 1 : 0,
        reinterpret_cast<const char *>(a.data()), a.size(), reinterpret_cast<const char *>(r.data()), r.size(),
        now, parts.data(), parts.size(), output.data(), output.size(), &size);
    if (status != 0) return fail();
    auto result = env->NewByteArray(static_cast<jsize>(size));
    if (!result) return nullptr;
    env->SetByteArrayRegion(result, 0, static_cast<jsize>(size), reinterpret_cast<const jbyte *>(output.data()));
    return env->ExceptionCheck() ? nullptr : result;
  } catch (...) { return fail(); }
}
