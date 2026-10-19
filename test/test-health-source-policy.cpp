#include "metrics/source-admission.h"
#include "quic/health-metrics-policy.h"
#include "td/utils/check.h"

int main() {
  CHECK(!tos::quic::health_metrics_policy::build_per_path);
  CHECK(tos::metrics::SourceAdmission::min_refresh_seconds == 15.0);
  CHECK(tos::metrics::SourceAdmission::work_budget_seconds == 2.0);
  CHECK(tos::metrics::SourceAdmission::http_budget_seconds == 3.0);
  CHECK(tos::metrics::SourceAdmission::max_waiters == 1);
  tos::metrics::SourceAdmission admission;
  CHECK(admission.begin(1));
  CHECK(admission.finish(1.5, true, 2 * 1024 * 1024));
  CHECK(admission.begin(16));
  CHECK(!admission.finish(16.5, true, 2 * 1024 * 1024 + 1));

  tos::metrics::SourceAdmission lease;
  CHECK(lease.begin(0));
  CHECK(lease.expired(2));
  CHECK(!lease.begin(15));
  CHECK(lease.inflight());
  CHECK(!lease.finish(16, false, 0));
  CHECK(!lease.inflight());
}
