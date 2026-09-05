#pragma once

#include "td/utils/buffer.h"
#include "td/utils/Status.h"

// Test-only TCP transport through the production persistent-state downloader.
td::Result<td::BufferSlice> download_uno_snapshot_over_tcp(td::BufferSlice source, bool truncate = false);
