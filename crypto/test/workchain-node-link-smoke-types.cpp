// Debug information only. This object is never linked into or loaded by a node.
// It supplies the matching C++ layouts to the passive debugger observer.
#include "crypto/block/workchain-execution-dispatch.h"

block::Config* config_type;
block::WorkchainExecutionRegistry* registry_type;
static_assert(sizeof(block::Config) > 0);
static_assert(sizeof(block::WorkchainExecutionRegistry) > 0);
using OrdinaryNode = std::_Rb_tree_node<std::pair<const block::WorkchainEngineKey, std::unique_ptr<block::WorkchainEngine>>>;
using BlockNode = std::_Rb_tree_node<std::pair<const block::WorkchainEngineKey, std::unique_ptr<block::RegisteredWorkchainBlockEngine>>>;
using AccountNode = std::_Rb_tree_node<std::pair<const block::WorkchainEngineKey, std::unique_ptr<block::RegisteredWorkchainAccountEngine>>>;
OrdinaryNode ordinary_node;
BlockNode block_node;
AccountNode account_node;
