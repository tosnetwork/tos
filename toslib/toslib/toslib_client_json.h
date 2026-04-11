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
#pragma once

#include "toslib/toslibjson_export.h"

#ifdef __cplusplus
extern "C" {
#endif

TOSLIBJSON_EXPORT void *toslib_client_json_create();

TOSLIBJSON_EXPORT void toslib_client_set_verbosity_level(int verbosity_level);

TOSLIBJSON_EXPORT void toslib_client_json_send(void *client, const char *request);

TOSLIBJSON_EXPORT const char *toslib_client_json_receive(void *client, double timeout);

TOSLIBJSON_EXPORT const char *toslib_client_json_execute(void *client, const char *request);

TOSLIBJSON_EXPORT void toslib_client_json_cancel_requests(void *client);

TOSLIBJSON_EXPORT void toslib_client_json_destroy(void *client);

#ifdef __cplusplus
}  // extern "C"
#endif
