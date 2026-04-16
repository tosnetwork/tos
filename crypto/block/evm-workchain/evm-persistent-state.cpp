/*
    EVM Workchain — persistent state adapter implementation.

    Uses td::RocksDb (the host chain's RocksDB wrapper) to store EVM
    account state, contract code, storage slots, and transaction receipts.

    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm-persistent-state.h"

#include "td/db/RocksDb.h"
#include "td/utils/logging.h"

#include <ethash/keccak.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/trie/nibbles.hpp>
#include <cstring>

namespace evm_workchain {

// --- Key prefixes (plain state) ---
static constexpr char kPrefixAccount  = 'A';
static constexpr char kPrefixStorage  = 'S';
static constexpr char kPrefixCode     = 'C';
static constexpr char kPrefixReceipt  = 'R';
static constexpr char kPrefixMeta     = 'M';

// --- Key prefixes (hashed state / trie cache) ---
static const std::string kPrefixHashedAccount  = "H";    // "H" + hashed_addr(32)
static const std::string kPrefixHashedStorage  = "HS";   // "HS" + hashed_addr(32) + incarnation(8) + hashed_slot(32)
static const std::string kPrefixTrieAccount    = "TA";   // "TA" + nibbled_key
static const std::string kPrefixTrieStorage    = "TS";   // "TS" + hashed_addr(32) + incarnation(8) + nibbled_key

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

// --- Helper: write big-endian uint64 into a string at offset ---
static void write_be64(std::string& s, size_t offset, uint64_t val) {
    for (int i = 7; i >= 0; --i)
        s[offset + (7 - i)] = static_cast<char>((val >> (i * 8)) & 0xFF);
}

// --- Hashed state key builders (static methods) ---

std::string PersistentEvmState::hashed_account_key(const evmc::bytes32& hashed_addr) {
    std::string k;
    k.reserve(kPrefixHashedAccount.size() + 32);
    k += kPrefixHashedAccount;
    k.append(reinterpret_cast<const char*>(hashed_addr.bytes), 32);
    return k;
}

std::string PersistentEvmState::hashed_storage_key(const evmc::bytes32& hashed_addr,
                                                    uint64_t incarnation,
                                                    const evmc::bytes32& hashed_slot) {
    // "HS" + hashed_addr(32) + incarnation(8) + hashed_slot(32) = 2 + 32 + 8 + 32 = 74
    std::string k(kPrefixHashedStorage.size() + 32 + 8 + 32, '\0');
    size_t pos = 0;
    std::memcpy(&k[pos], kPrefixHashedStorage.data(), kPrefixHashedStorage.size());
    pos += kPrefixHashedStorage.size();
    std::memcpy(&k[pos], hashed_addr.bytes, 32);
    pos += 32;
    write_be64(k, pos, incarnation);
    pos += 8;
    std::memcpy(&k[pos], hashed_slot.bytes, 32);
    return k;
}

std::string PersistentEvmState::trie_account_key(const silkworm::Bytes& nibbled_key) {
    std::string k;
    k.reserve(kPrefixTrieAccount.size() + nibbled_key.size());
    k += kPrefixTrieAccount;
    k.append(reinterpret_cast<const char*>(nibbled_key.data()), nibbled_key.size());
    return k;
}

std::string PersistentEvmState::trie_storage_key(const evmc::bytes32& hashed_addr,
                                                  uint64_t incarnation,
                                                  const silkworm::Bytes& nibbled_key) {
    // "TS" + hashed_addr(32) + incarnation(8) + nibbled_key
    std::string k(kPrefixTrieStorage.size() + 32 + 8 + nibbled_key.size(), '\0');
    size_t pos = 0;
    std::memcpy(&k[pos], kPrefixTrieStorage.data(), kPrefixTrieStorage.size());
    pos += kPrefixTrieStorage.size();
    std::memcpy(&k[pos], hashed_addr.bytes, 32);
    pos += 32;
    write_be64(k, pos, incarnation);
    pos += 8;
    std::memcpy(&k[pos], nibbled_key.data(), nibbled_key.size());
    return k;
}

// --- Hashed account encoding ---
// Same layout as plain account: nonce(8) + balance(32) + code_hash(32) + incarnation(8) = 80 bytes.
// Re-uses the same fixed format so that decode_account() works for both.

std::string PersistentEvmState::encode_hashed_account(const silkworm::Account& acct) {
    std::string out(80, '\0');
    // nonce (big-endian)
    write_be64(out, 0, acct.nonce);
    // balance (big-endian uint256 -> 32 bytes)
    auto bal = intx::be::store<evmc::uint256be>(acct.balance);
    std::memcpy(&out[8], bal.bytes, 32);
    // code_hash
    std::memcpy(&out[40], acct.code_hash.bytes, 32);
    // incarnation (big-endian)
    write_be64(out, 72, acct.incarnation);
    return out;
}

std::optional<silkworm::Account> PersistentEvmState::decode_hashed_account(const std::string& data) {
    // Same format as plain account
    if (data.size() != 80) return std::nullopt;
    silkworm::Account acct;
    acct.nonce = 0;
    for (int i = 0; i < 8; ++i)
        acct.nonce = (acct.nonce << 8) | static_cast<uint8_t>(data[i]);
    evmc::uint256be bal_be;
    std::memcpy(bal_be.bytes, &data[8], 32);
    acct.balance = intx::be::load<intx::uint256>(bal_be);
    std::memcpy(acct.code_hash.bytes, &data[40], 32);
    acct.incarnation = 0;
    for (int i = 0; i < 8; ++i)
        acct.incarnation = (acct.incarnation << 8) | static_cast<uint8_t>(data[72 + i]);
    return acct;
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
// Layout: success(1) + gas_used(8) + cumulative_gas_used(8) + block_number(8) + tx_index(4)
//         + from(20) + has_to(1) + to(20)
//         + has_contract(1) + contract(20) + num_logs(4) + [logs...] + return_data_len(4) + return_data

static std::string encode_receipt(const StoredReceipt& r) {
    std::string out;
    out.reserve(256);
    out += static_cast<char>(r.success ? 1 : 0);
    for (int i = 7; i >= 0; --i) out += static_cast<char>((r.gas_used >> (i * 8)) & 0xFF);
    for (int i = 7; i >= 0; --i) out += static_cast<char>((r.cumulative_gas_used >> (i * 8)) & 0xFF);
    for (int i = 7; i >= 0; --i) out += static_cast<char>((r.block_number >> (i * 8)) & 0xFF);
    for (int i = 3; i >= 0; --i) out += static_cast<char>((r.tx_index >> (i * 8)) & 0xFF);
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
    // Use thread_local buffer to avoid data race on shared mutable member.
    // Pattern from ~/s: each state instance caches code privately.
    thread_local silkworm::Bytes tl_code_buf;
    tl_code_buf.assign(reinterpret_cast<const uint8_t*>(value.data()),
                       reinterpret_cast<const uint8_t*>(value.data()) + value.size());
    return tl_code_buf;
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

    // Mirror to hashed state table for incremental trie computation
    auto hashed = ethash::keccak256(address.bytes, 20);
    evmc::bytes32 hashed_addr;
    std::memcpy(hashed_addr.bytes, hashed.bytes, 32);
    if (current) {
        db_->set(hashed_account_key(hashed_addr), encode_hashed_account(*current));
    } else {
        db_->erase(hashed_account_key(hashed_addr));
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

    // Mirror to hashed storage table for incremental trie computation
    auto addr_hash = ethash::keccak256(address.bytes, 20);
    evmc::bytes32 hashed_addr;
    std::memcpy(hashed_addr.bytes, addr_hash.bytes, 32);

    auto slot_hash = ethash::keccak256(location.bytes, 32);
    evmc::bytes32 hashed_slot;
    std::memcpy(hashed_slot.bytes, slot_hash.bytes, 32);

    if (current == zero) {
        db_->erase(hashed_storage_key(hashed_addr, incarnation, hashed_slot));
    } else {
        db_->set(hashed_storage_key(hashed_addr, incarnation, hashed_slot),
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
    if (value.size() < 95) return std::nullopt;  // minimum: 1+8+8+8+4+20+1+20+1+20+4 = 95
    StoredReceipt receipt;
    size_t pos = 0;
    receipt.success = (value[pos++] != 0);
    receipt.gas_used = 0;
    for (int i = 0; i < 8; ++i)
        receipt.gas_used = (receipt.gas_used << 8) | static_cast<uint8_t>(value[pos++]);
    receipt.cumulative_gas_used = 0;
    for (int i = 0; i < 8; ++i)
        receipt.cumulative_gas_used = (receipt.cumulative_gas_used << 8) | static_cast<uint8_t>(value[pos++]);
    receipt.block_number = 0;
    for (int i = 0; i < 8; ++i)
        receipt.block_number = (receipt.block_number << 8) | static_cast<uint8_t>(value[pos++]);
    receipt.tx_index = 0;
    for (int i = 0; i < 4; ++i)
        receipt.tx_index = (receipt.tx_index << 8) | static_cast<uint8_t>(value[pos++]);
    std::memcpy(receipt.from.bytes, &value[pos], 20); pos += 20;
    if (value[pos++] != 0) {
        evmc::address to{};
        std::memcpy(to.bytes, &value[pos], 20);
        receipt.to = to;
    }
    pos += 20;
    if (value[pos++] != 0) {
        evmc::address ca{};
        std::memcpy(ca.bytes, &value[pos], 20);
        receipt.contract_address = ca;
    }
    pos += 20;
    // Decode logs (cap at 10K to prevent OOM from corrupted data)
    if (pos + 4 <= value.size()) {
        uint32_t num_logs = 0;
        for (int i = 0; i < 4; ++i)
            num_logs = (num_logs << 8) | static_cast<uint8_t>(value[pos++]);
        if (num_logs > 10'000) num_logs = 10'000;
        for (uint32_t li = 0; li < num_logs && pos < value.size(); ++li) {
            silkworm::Log log;
            if (pos + 20 > value.size()) break;
            std::memcpy(log.address.bytes, &value[pos], 20); pos += 20;
            if (pos + 4 > value.size()) break;
            uint32_t nt = 0;
            for (int i = 0; i < 4; ++i)
                nt = (nt << 8) | static_cast<uint8_t>(value[pos++]);
            for (uint32_t ti = 0; ti < nt && pos + 32 <= value.size(); ++ti) {
                evmc::bytes32 topic{};
                std::memcpy(topic.bytes, &value[pos], 32); pos += 32;
                log.topics.push_back(topic);
            }
            if (pos + 4 > value.size()) break;
            uint32_t dl = 0;
            for (int i = 0; i < 4; ++i)
                dl = (dl << 8) | static_cast<uint8_t>(value[pos++]);
            if (pos + dl > value.size()) break;
            log.data.assign(reinterpret_cast<const uint8_t*>(&value[pos]),
                            reinterpret_cast<const uint8_t*>(&value[pos]) + dl);
            pos += dl;
            receipt.logs.push_back(std::move(log));
        }
    }
    // Decode return data
    if (pos + 4 <= value.size()) {
        uint32_t rdl = 0;
        for (int i = 0; i < 4; ++i)
            rdl = (rdl << 8) | static_cast<uint8_t>(value[pos++]);
        if (pos + rdl <= value.size()) {
            receipt.return_data.assign(reinterpret_cast<const uint8_t*>(&value[pos]),
                                       reinterpret_cast<const uint8_t*>(&value[pos]) + rdl);
        }
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

// --- Hashed state iteration ---

void PersistentEvmState::for_each_hashed_account(
    std::function<void(const evmc::bytes32& hashed_addr,
                       const silkworm::Account& acct)> callback) const {
    // Range: "H" (exclusive upper bound = "H" + 0xFF*32 + 1 byte beyond)
    // We use "H" as begin and compute an end that is just past the last
    // possible "H" + 32 bytes key.  Since all hashed account keys are
    // exactly prefix_len + 32 bytes, we use prefix "I" as upper bound
    // (next byte after 'H' in ASCII).
    std::string begin = kPrefixHashedAccount;
    std::string end = kPrefixHashedAccount;
    // Increment last byte to get exclusive upper bound
    end.back() = static_cast<char>(end.back() + 1);

    db_->for_each_in_range(begin, end, [&](td::Slice key, td::Slice value) -> td::Status {
        if (key.size() != static_cast<size_t>(kPrefixHashedAccount.size() + 32)) {
            return td::Status::OK();  // skip malformed keys
        }
        evmc::bytes32 hashed_addr{};
        std::memcpy(hashed_addr.bytes, key.data() + kPrefixHashedAccount.size(), 32);

        auto acct = decode_hashed_account(value.str());
        if (acct) {
            callback(hashed_addr, *acct);
        }
        return td::Status::OK();
    });
}

void PersistentEvmState::for_each_hashed_storage(
    const evmc::bytes32& hashed_addr, uint64_t incarnation,
    std::function<void(const evmc::bytes32& hashed_slot,
                       const evmc::bytes32& value)> callback) const {
    // Build the prefix: "HS" + hashed_addr(32) + incarnation(8)
    std::string prefix(kPrefixHashedStorage.size() + 32 + 8, '\0');
    size_t pos = 0;
    std::memcpy(&prefix[pos], kPrefixHashedStorage.data(), kPrefixHashedStorage.size());
    pos += kPrefixHashedStorage.size();
    std::memcpy(&prefix[pos], hashed_addr.bytes, 32);
    pos += 32;
    write_be64(prefix, pos, incarnation);

    // Upper bound: prefix with last byte incremented
    std::string end = prefix;
    // Increment the prefix to get an exclusive upper bound.
    // Since incarnation is big-endian, incrementing the last byte works.
    for (int i = static_cast<int>(end.size()) - 1; i >= 0; --i) {
        if (static_cast<unsigned char>(end[i]) < 0xFF) {
            end[i] = static_cast<char>(static_cast<unsigned char>(end[i]) + 1);
            break;
        }
        end[i] = '\0';
    }

    db_->for_each_in_range(prefix, end, [&](td::Slice key, td::Slice val) -> td::Status {
        // Expected key length: prefix + 32 (hashed_slot)
        if (key.size() != prefix.size() + 32) {
            return td::Status::OK();  // skip malformed keys
        }
        evmc::bytes32 hashed_slot{};
        std::memcpy(hashed_slot.bytes, key.data() + prefix.size(), 32);

        evmc::bytes32 storage_val{};
        if (val.size() == 32) {
            std::memcpy(storage_val.bytes, val.data(), 32);
        }
        callback(hashed_slot, storage_val);
        return td::Status::OK();
    });
}

// --- Trie node cache ---

void PersistentEvmState::write_trie_account_node(const silkworm::Bytes& nibbled_key,
                                                   const silkworm::Bytes& encoded_node) {
    db_->set(trie_account_key(nibbled_key),
             td::Slice(reinterpret_cast<const char*>(encoded_node.data()), encoded_node.size()));
}

void PersistentEvmState::delete_trie_account_node(const silkworm::Bytes& nibbled_key) {
    db_->erase(trie_account_key(nibbled_key));
}

std::optional<silkworm::Bytes> PersistentEvmState::read_trie_account_node(
    const silkworm::Bytes& nibbled_key) const {
    std::string value;
    auto r = db_->get(trie_account_key(nibbled_key), value);
    if (r.is_error() || r.ok() == td::KeyValue::GetStatus::NotFound) return std::nullopt;
    return silkworm::Bytes(reinterpret_cast<const uint8_t*>(value.data()),
                           reinterpret_cast<const uint8_t*>(value.data()) + value.size());
}

void PersistentEvmState::write_trie_storage_node(const evmc::bytes32& hashed_addr,
                                                   uint64_t incarnation,
                                                   const silkworm::Bytes& nibbled_key,
                                                   const silkworm::Bytes& encoded_node) {
    db_->set(trie_storage_key(hashed_addr, incarnation, nibbled_key),
             td::Slice(reinterpret_cast<const char*>(encoded_node.data()), encoded_node.size()));
}

void PersistentEvmState::delete_trie_storage_node(const evmc::bytes32& hashed_addr,
                                                    uint64_t incarnation,
                                                    const silkworm::Bytes& nibbled_key) {
    db_->erase(trie_storage_key(hashed_addr, incarnation, nibbled_key));
}

std::optional<silkworm::Bytes> PersistentEvmState::read_trie_storage_node(
    const evmc::bytes32& hashed_addr, uint64_t incarnation,
    const silkworm::Bytes& nibbled_key) const {
    std::string value;
    auto r = db_->get(trie_storage_key(hashed_addr, incarnation, nibbled_key), value);
    if (r.is_error() || r.ok() == td::KeyValue::GetStatus::NotFound) return std::nullopt;
    return silkworm::Bytes(reinterpret_cast<const uint8_t*>(value.data()),
                           reinterpret_cast<const uint8_t*>(value.data()) + value.size());
}

}  // namespace evm_workchain
