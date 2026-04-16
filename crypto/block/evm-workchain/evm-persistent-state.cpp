/*
    EVM Workchain — persistent state adapter implementation.

    Uses td::RocksDb (the host chain's RocksDB wrapper) to store EVM
    account state, contract code, storage slots, and transaction receipts.

    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm-persistent-state.h"

#include "td/db/RocksDb.h"
#include "td/utils/logging.h"

#include <silkworm/core/common/endian.hpp>
#include <cstring>

namespace evm_workchain {

// --- Key prefixes ---
static constexpr char kPrefixAccount  = 'A';
static constexpr char kPrefixStorage  = 'S';
static constexpr char kPrefixCode     = 'C';
static constexpr char kPrefixReceipt  = 'R';
static constexpr char kPrefixMeta     = 'M';

// --- Key builders ---

static std::string account_key(const evmc::address& addr) {
    std::string k(1 + 20, '\0');
    k[0] = kPrefixAccount;
    std::memcpy(&k[1], addr.bytes, 20);
    return k;
}

static std::string storage_key(const evmc::address& addr, uint64_t incarnation, const evmc::bytes32& location) {
    std::string k(1 + 20 + 8 + 32, '\0');
    k[0] = kPrefixStorage;
    std::memcpy(&k[1], addr.bytes, 20);
    // big-endian incarnation for sort order
    for (int i = 7; i >= 0; --i) {
        k[21 + (7 - i)] = static_cast<char>((incarnation >> (i * 8)) & 0xFF);
    }
    std::memcpy(&k[29], location.bytes, 32);
    return k;
}

static std::string code_key(const evmc::bytes32& code_hash) {
    std::string k(1 + 32, '\0');
    k[0] = kPrefixCode;
    std::memcpy(&k[1], code_hash.bytes, 32);
    return k;
}

static std::string receipt_key(const evmc::bytes32& tx_hash) {
    std::string k(1 + 32, '\0');
    k[0] = kPrefixReceipt;
    std::memcpy(&k[1], tx_hash.bytes, 32);
    return k;
}

static std::string meta_key(const std::string& name) {
    return std::string(1, kPrefixMeta) + name;
}

// --- Account serialisation (simple fixed layout) ---
// Layout: nonce(8) + balance(32) + code_hash(32) + incarnation(8) = 80 bytes

static std::string encode_account(const silkworm::Account& acct) {
    std::string out(80, '\0');
    // nonce (big-endian)
    for (int i = 7; i >= 0; --i)
        out[7 - i] = static_cast<char>((acct.nonce >> (i * 8)) & 0xFF);
    // balance (big-endian uint256 → 32 bytes)
    auto bal = intx::be::store<evmc::uint256be>(acct.balance);
    std::memcpy(&out[8], bal.bytes, 32);
    // code_hash
    std::memcpy(&out[40], acct.code_hash.bytes, 32);
    // incarnation (big-endian)
    for (int i = 7; i >= 0; --i)
        out[72 + (7 - i)] = static_cast<char>((acct.incarnation >> (i * 8)) & 0xFF);
    return out;
}

static std::optional<silkworm::Account> decode_account(const std::string& data) {
    if (data.size() != 80) return std::nullopt;
    silkworm::Account acct;
    // nonce
    acct.nonce = 0;
    for (int i = 0; i < 8; ++i)
        acct.nonce = (acct.nonce << 8) | static_cast<uint8_t>(data[i]);
    // balance
    evmc::uint256be bal_be;
    std::memcpy(bal_be.bytes, &data[8], 32);
    acct.balance = intx::be::load<intx::uint256>(bal_be);
    // code_hash
    std::memcpy(acct.code_hash.bytes, &data[40], 32);
    // incarnation
    acct.incarnation = 0;
    for (int i = 0; i < 8; ++i)
        acct.incarnation = (acct.incarnation << 8) | static_cast<uint8_t>(data[72 + i]);
    return acct;
}

// --- Receipt serialisation (simple binary) ---
// Layout: success(1) + gas_used(8) + block_number(8) + from(20) + has_to(1) + to(20)
//         + has_contract(1) + contract(20) + num_logs(4) + [logs...] + return_data_len(4) + return_data

static std::string encode_receipt(const StoredReceipt& r) {
    std::string out;
    out.reserve(256);
    out += static_cast<char>(r.success ? 1 : 0);
    for (int i = 7; i >= 0; --i) out += static_cast<char>((r.gas_used >> (i * 8)) & 0xFF);
    for (int i = 7; i >= 0; --i) out += static_cast<char>((r.block_number >> (i * 8)) & 0xFF);
    out.append(reinterpret_cast<const char*>(r.from.bytes), 20);
    out += static_cast<char>(r.to.has_value() ? 1 : 0);
    if (r.to) out.append(reinterpret_cast<const char*>(r.to->bytes), 20);
    else out.append(20, '\0');
    out += static_cast<char>(r.contract_address.has_value() ? 1 : 0);
    if (r.contract_address) out.append(reinterpret_cast<const char*>(r.contract_address->bytes), 20);
    else out.append(20, '\0');
    // logs count
    uint32_t num_logs = static_cast<uint32_t>(r.logs.size());
    for (int i = 3; i >= 0; --i) out += static_cast<char>((num_logs >> (i * 8)) & 0xFF);
    for (const auto& log : r.logs) {
        out.append(reinterpret_cast<const char*>(log.address.bytes), 20);
        uint32_t nt = static_cast<uint32_t>(log.topics.size());
        for (int i = 3; i >= 0; --i) out += static_cast<char>((nt >> (i * 8)) & 0xFF);
        for (const auto& t : log.topics)
            out.append(reinterpret_cast<const char*>(t.bytes), 32);
        uint32_t dl = static_cast<uint32_t>(log.data.size());
        for (int i = 3; i >= 0; --i) out += static_cast<char>((dl >> (i * 8)) & 0xFF);
        out.append(reinterpret_cast<const char*>(log.data.data()), log.data.size());
    }
    // return data
    uint32_t rdl = static_cast<uint32_t>(r.return_data.size());
    for (int i = 3; i >= 0; --i) out += static_cast<char>((rdl >> (i * 8)) & 0xFF);
    out.append(reinterpret_cast<const char*>(r.return_data.data()), r.return_data.size());
    return out;
}

// --- PersistentEvmState implementation ---

PersistentEvmState::PersistentEvmState(std::unique_ptr<td::RocksDb> db)
    : db_(std::move(db)) {}

PersistentEvmState::~PersistentEvmState() = default;

std::unique_ptr<PersistentEvmState> PersistentEvmState::open(const std::string& db_path) {
    auto r = td::RocksDb::open(db_path);
    if (r.is_error()) {
        LOG(ERROR) << "evm-workchain: failed to open state DB at " << db_path << ": " << r.error();
        return nullptr;
    }
    auto db = std::make_unique<td::RocksDb>(r.move_as_ok());
    LOG(WARNING) << "evm-workchain: opened persistent state at " << db_path;
    return std::unique_ptr<PersistentEvmState>(new PersistentEvmState(std::move(db)));
}

// --- Readers ---

std::optional<silkworm::Account> PersistentEvmState::read_account(const evmc::address& address) const noexcept {
    std::string value;
    auto r = db_->get(account_key(address), value);
    if (r.is_error() || r.ok() == td::KeyValue::GetStatus::NotFound) return std::nullopt;
    return decode_account(value);
}

silkworm::ByteView PersistentEvmState::read_code(const evmc::address& /*address*/, const evmc::bytes32& code_hash) const noexcept {
    static const evmc::bytes32 empty_hash = silkworm::kEmptyHash;
    if (code_hash == empty_hash) return {};
    std::string value;
    auto r = db_->get(code_key(code_hash), value);
    if (r.is_error() || r.ok() == td::KeyValue::GetStatus::NotFound) return {};
    code_read_buf_.assign(reinterpret_cast<const uint8_t*>(value.data()),
                          reinterpret_cast<const uint8_t*>(value.data()) + value.size());
    return code_read_buf_;
}

evmc::bytes32 PersistentEvmState::read_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& location) const noexcept {
    std::string value;
    auto r = db_->get(storage_key(address, incarnation, location), value);
    if (r.is_error() || r.ok() == td::KeyValue::GetStatus::NotFound) {
        return {};
    }
    evmc::bytes32 result{};
    if (value.size() == 32) {
        std::memcpy(result.bytes, value.data(), 32);
    }
    return result;
}

uint64_t PersistentEvmState::previous_incarnation(const evmc::address& /*address*/) const noexcept {
    return 0;
}

evmc::bytes32 PersistentEvmState::state_root_hash() const {
    return {};  // not computed for MVP
}

silkworm::BlockNum PersistentEvmState::current_canonical_block() const {
    return block_number();
}

std::optional<evmc::bytes32> PersistentEvmState::canonical_hash(silkworm::BlockNum /*block_num*/) const {
    return std::nullopt;
}

// --- Writers ---

void PersistentEvmState::insert_block(const silkworm::Block& /*block*/, const evmc::bytes32& /*hash*/) {}
void PersistentEvmState::canonize_block(silkworm::BlockNum /*block_num*/, const evmc::bytes32& /*block_hash*/) {}
void PersistentEvmState::decanonize_block(silkworm::BlockNum /*block_num*/) {}
void PersistentEvmState::insert_call_traces(silkworm::BlockNum /*block_num*/, const silkworm::CallTraces& /*traces*/) {}
void PersistentEvmState::begin_block(silkworm::BlockNum /*block_num*/, size_t /*updated_accounts_count*/) {}
void PersistentEvmState::unwind_state_changes(silkworm::BlockNum /*block_num*/) {}

void PersistentEvmState::update_account(const evmc::address& address,
                                         std::optional<silkworm::Account> /*initial*/,
                                         std::optional<silkworm::Account> current) {
    if (current) {
        db_->set(account_key(address), encode_account(*current));
    } else {
        db_->erase(account_key(address));
    }
}

void PersistentEvmState::update_account_code(const evmc::address& /*address*/, uint64_t /*incarnation*/,
                                              const evmc::bytes32& code_hash, silkworm::ByteView code) {
    db_->set(code_key(code_hash), td::Slice(reinterpret_cast<const char*>(code.data()), code.size()));
}

void PersistentEvmState::update_storage(const evmc::address& address, uint64_t incarnation,
                                         const evmc::bytes32& location,
                                         const evmc::bytes32& /*initial*/,
                                         const evmc::bytes32& current) {
    static const evmc::bytes32 zero{};
    if (current == zero) {
        db_->erase(storage_key(address, incarnation, location));
    } else {
        db_->set(storage_key(address, incarnation, location),
                 td::Slice(reinterpret_cast<const char*>(current.bytes), 32));
    }
}

// --- Receipts ---

void PersistentEvmState::store_receipt(const evmc::bytes32& tx_hash, const StoredReceipt& receipt) {
    db_->set(receipt_key(tx_hash), encode_receipt(receipt));
}

std::optional<StoredReceipt> PersistentEvmState::get_receipt(const evmc::bytes32& tx_hash) const {
    std::string value;
    auto r = db_->get(receipt_key(tx_hash), value);
    if (r.is_error() || r.ok() == td::KeyValue::GetStatus::NotFound) return std::nullopt;
    // Decode receipt (simplified — just return success/gas for now, full decode later)
    if (value.size() < 17) return std::nullopt;
    StoredReceipt receipt;
    receipt.success = (value[0] != 0);
    receipt.gas_used = 0;
    for (int i = 0; i < 8; ++i)
        receipt.gas_used = (receipt.gas_used << 8) | static_cast<uint8_t>(value[1 + i]);
    receipt.block_number = 0;
    for (int i = 0; i < 8; ++i)
        receipt.block_number = (receipt.block_number << 8) | static_cast<uint8_t>(value[9 + i]);
    std::memcpy(receipt.from.bytes, &value[17], 20);
    if (value[37] != 0) {
        evmc::address to{};
        std::memcpy(to.bytes, &value[38], 20);
        receipt.to = to;
    }
    if (value[58] != 0) {
        evmc::address ca{};
        std::memcpy(ca.bytes, &value[59], 20);
        receipt.contract_address = ca;
    }
    return receipt;
}

// --- Block number ---

uint64_t PersistentEvmState::block_number() const {
    std::string value;
    auto r = db_->get(meta_key("block_number"), value);
    if (r.is_error() || r.ok() == td::KeyValue::GetStatus::NotFound) return 0;
    if (value.size() != 8) return 0;
    uint64_t n = 0;
    for (int i = 0; i < 8; ++i)
        n = (n << 8) | static_cast<uint8_t>(value[i]);
    return n;
}

void PersistentEvmState::set_block_number(uint64_t n) {
    std::string val(8, '\0');
    for (int i = 7; i >= 0; --i)
        val[7 - i] = static_cast<char>((n >> (i * 8)) & 0xFF);
    db_->set(meta_key("block_number"), val);
}

}  // namespace evm_workchain
