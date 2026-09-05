#pragma once

#include "td/utils/buffer.h"
#include "td/utils/Status.h"
#include "validator/state-download-buffer.h"

// Test-only TCP transport through the production persistent-state downloader.
td::Result<td::BufferSlice> download_uno_snapshot_over_tcp(td::BufferSlice source, bool truncate = false);
td::Result<tos::validator::fullnode::DownloadedPersistentState> download_uno_snapshot_state_over_tcp(
    td::BufferSlice source, bool truncate = false);
