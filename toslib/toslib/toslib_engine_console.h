#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "toslib/toslibjson_export.h"

#ifdef __cplusplus
#include <string>

namespace toslib {

class FFIEventLoop;
template <typename T>
class FFIAwaitable;

}  // namespace toslib

using ToslibEventLoop = toslib::FFIEventLoop;
using ToslibResponse = toslib::FFIAwaitable<std::string>;
#else
typedef struct ToslibEventLoop ToslibEventLoop;
typedef struct ToslibResponse ToslibResponse;
#endif

typedef struct ToslibEngineConsole ToslibEngineConsole;

#ifdef __cplusplus
extern "C" {
#endif

// ===== Event Loop =====
// An interaction with the engine console client starts by creating an ToslibEventLoop object that
// allows foreign caller to wait for asynchronous event completion in a mostly non-blocking
// manner. In particular, after suspending ToslibResponse, toslib_event_loop_wait will return when
// the awaitable ToslibResponse is resolved.
//
// toslib_event_loop_wait does nothing for `timeout` seconds if there is nothing to process, so a
// typical interaction flow goes as follows:
//
// 1. Create an event loop before first library usage.
// 2. Spawn a background thread that continuously polls toslib_event_loop_wait and resumes
//    continuations of resolved responses.
// 3. Call asynchronous functions, providing a continuation that the background thread knows how to
//    resume.
//
// There must be a total happens-before order in which toslib functions (except
// `toslib_event_loop_wait`) bound to a single event loop are called (i. e. the event loop is
// thread-aware but not thread-safe). `toslib_event_loop_wait` calls must be happens-before ordered
// with respect to each other as well but are not required to be ordered with the respect to other
// functions. However, last call to `toslib_event_loop_wait` must happen before
// `toslib_event_loop_destroy` call. To facilitate this, `toslib_event_loop_cancel` can be used to
// cancel wait without destroying the loop.

// Creates a new event loop instance. Never fails.
TOSLIBJSON_EXPORT ToslibEventLoop *toslib_event_loop_create(int threads);

// Destroys the event loop.
//
// Non-destroyed instances of engine console client will deadlock the function. (Calling
// `toslib_engine_console_destroy` during `toslib_event_loop_destroy` is UB as it violates the
// global happens-before ordering requirement.)
TOSLIBJSON_EXPORT void toslib_event_loop_destroy(ToslibEventLoop *loop);

// Puts event loop into the cancelled state.
TOSLIBJSON_EXPORT void toslib_event_loop_cancel(ToslibEventLoop *loop);

// Waits for the next event for `timeout` seconds. If no event happens within the timeout, returns
// nullptr. If the event loop is cancelled on function entry, returns immediately with nullptr. If
// the event loop is cancelled during wait, the function eventually (as soon as scheduled) returns
// nullptr as well. timeout=-1.0 is no timeout.
TOSLIBJSON_EXPORT const void *toslib_event_loop_wait(ToslibEventLoop *loop, double timeout);

// ===== Response =====
// ToslibResponse is an awaitable that will resolve with the response of the connected validator
// engine. It can be obtained from `toslib_engine_console_request`.

// Destroys the response. If `await_suspend` was called on the response and response is not yet
// resolved, continuation will arrive as soon as scheduled.
TOSLIBJSON_EXPORT void toslib_response_destroy(ToslibResponse *response);

// Returns true if the response is resolved. You can use this immediately after creation to check if
// synchronous result is available.
TOSLIBJSON_EXPORT bool toslib_response_await_ready(ToslibResponse *response);

// Records continuation that will be returned by `toslib_event_loop_wait` when response is resolved.
// `toslib_event_loop_wait` will not return because of this response until this function is called.
//
// Can only be called one time on a particular response instance. Can be called on a resolved
// instance as well, in which case the continuation will be returned as soon as scheduled (this is
// allowed as `await_ready` + `await_suspend` sequence is obviously not atomic).
//
// uintptr_t(continuation) must be in [1, UINTPTR_MAX - 1] range.
TOSLIBJSON_EXPORT void toslib_response_await_suspend(ToslibResponse *response, const void *continuation);

// Returns true if the response is an error. Can only be called on resolved response. Only errors
// produced locally will be reported here; errors returned by the remote side are returned using a
// "success" path as an `engine.validator.controlQueryError` object.
TOSLIBJSON_EXPORT bool toslib_response_is_error(ToslibResponse *response);

// Returns the error code. Can only be called on resolved error response.
TOSLIBJSON_EXPORT int toslib_response_get_error_code(ToslibResponse *response);

// Returns the error message. Can only be called on resolved error response.
TOSLIBJSON_EXPORT const char *toslib_response_get_error_message(ToslibResponse *response);

// Returns the JSON-encoded remote TL response. Can only be called on resolved response. Might be
// either a successful response with type determined by the TL scheme or an
// `engine.validator.controlQueryError` object if remote has encountered an error.
TOSLIBJSON_EXPORT const char *toslib_response_get_response(ToslibResponse *response);

// ===== Engine Console =====
// ToslibEngineConsole represents an instance of the engine console client. It allows sending
// control queries to the connected validator engine.

// Creates a new engine console client instance.
//
// `config` should be a JSON-encoded `engineConsoleClient.config` object. If creation of the
// instance fails, the error can be obtained from `toslib_engine_console_is_error` and related
// functions.
TOSLIBJSON_EXPORT ToslibEngineConsole *toslib_engine_console_create(ToslibEventLoop *loop, const char *config);

// Destroys the engine console client instance. Error instances must be destroyed as well.
TOSLIBJSON_EXPORT void toslib_engine_console_destroy(ToslibEngineConsole *console);

// Returns true if the engine console instance did not initialize properly.
TOSLIBJSON_EXPORT bool toslib_engine_console_is_error(ToslibEngineConsole *console);

// Returns the error code. Can only be called if `toslib_engine_console_is_error` returned true.
TOSLIBJSON_EXPORT int toslib_engine_console_get_error_code(ToslibEngineConsole *console);

// Returns the error message. Can only be called if `toslib_engine_console_is_error` returned true.
TOSLIBJSON_EXPORT const char *toslib_engine_console_get_error_message(ToslibEngineConsole *console);

// Sends a control query to the connected validator engine. Can only be called if
// `toslib_engine_console_is_error` returned false.
//
// `query` must be a JSON-encoded control query object.
TOSLIBJSON_EXPORT ToslibResponse *toslib_engine_console_request(ToslibEngineConsole *console, const char *query);

#ifdef __cplusplus
}  // extern "C"
#endif
