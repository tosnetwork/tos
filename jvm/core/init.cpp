/*
    JVM workchain initialization.
*/
#include "jvm/core/init.h"

#include "block/workchain-execution-dispatch.h"
#include "jvm/core/avata-runtime.h"
#include "jvm/core/dispatch-engine.h"
#include "td/utils/logging.h"

#include <cstdlib>
#include <memory>
#include <utility>

#ifndef TOS_AVATA_DEFAULT_RT_JAR
#define TOS_AVATA_DEFAULT_RT_JAR ""
#endif

namespace jvm_workchain {

namespace {

std::string getenv_or_empty(const char* name) {
    const char* value = std::getenv(name);
    return value == nullptr ? std::string{} : std::string{value};
}

}  // namespace

bool init_jvm_workchain(const char* /*db_root*/) {
    JvmLinkedAvataRuntimeOptions options;
    options.boot_classpath = getenv_or_empty("TOS_JVM_AVATA_RT_JAR");
    if (options.boot_classpath.empty()) {
        options.boot_classpath = TOS_AVATA_DEFAULT_RT_JAR;
    }
    options.classpath = getenv_or_empty("TOS_JVM_AVATA_CONTRACT_CLASSPATH");
    auto heap = getenv_or_empty("TOS_JVM_AVATA_HEAP");
    if (!heap.empty()) {
        options.max_heap = std::move(heap);
    }

    std::shared_ptr<const JvmComputeRuntime> runtime;
    auto linked_runtime = make_linked_jvm_avata_runtime(options);
    if (linked_runtime.is_ok()) {
        runtime = linked_runtime.move_as_ok();
    } else {
        LOG(WARNING)
            << "jvm-workchain: Avata runtime init failed; wc=3 will fail closed: "
            << linked_runtime.error().message();
    }

    register_jvm_workchain_engine(block::default_workchain_execution_registry(),
                                  std::move(runtime));
    return true;
}

}  // namespace jvm_workchain
