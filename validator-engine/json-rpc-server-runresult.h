/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

// Renders a liteserver get-method answer as the JSON-RPC smc.runResult body
// that runGetMethod and runGetMethodStd return. Pure and actor-free, so the
// reply both endpoints send can be unit tested from a liteserver answer.

#include <string>

#include "auto/tl/lite_api.h"
#include "td/utils/Status.h"

namespace tos {

enum class RunResultFormat { Legacy, Std };

// The smc.runResult body for a liteServer.runMethodResult requested with
// mode 4, or a -32603 error when its result stack cannot be resolved. An
// unreadable result is never reported as an empty stack.
td::Result<std::string> render_run_method_result(const lite_api::liteServer_runMethodResult& answer,
                                                 RunResultFormat format);

std::string format_block_id_json(const lite_api::tosNode_blockIdExt& blk);

}  // namespace tos
