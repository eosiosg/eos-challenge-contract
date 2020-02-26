// EVMC: Ethereum Client-VM Connector API.
// Copyright 2019 The EVMC Authors.
// Licensed under the Apache License, Version 2.0.
#pragma once

#include <evmc/evmc.hpp>
#include <algorithm>
#include <string>
#include <unordered_map>
#include <vector>
#include <eosio/eosio.hpp>
#include <eosio/action.hpp>
#include <test_contract.hpp>
#include <utils.hpp>

using namespace eosio;
namespace evmc {
/// The string of bytes.
using bytes = std::basic_string<uint8_t>;
typedef eosio::checksum256 eosio_addr;
typedef eosio::checksum256 eth_addr;

/// Extended value (by dirty flag) for account storage.
struct storage_value {
  /// The storage value.
  bytes32 value;

  /// True means this value has been modified already by the current transaction.
  bool dirty{false};

  /// Default constructor.
  storage_value() noexcept = default;

  /// Constructor.
  storage_value(const bytes32 &_value, bool _dirty = false) noexcept  // NOLINT
	  : value{_value}, dirty{_dirty} {}
};

/// Mocked account.
struct MockedAccount {
  /// The account nonce.
  int nonce = 0;

  /// The account code.
  bytes code;

  /// The code hash. Can be a value not related to the actual code.
  bytes32 codehash;

  /// The account balance.
  uint256be balance;

  /// The account storage map.
  std::map<bytes32, storage_value> storage;

  /// Helper method for setting balance by numeric type.
  void set_balance(uint64_t x) noexcept {
	balance = uint256be{};
	for (std::size_t i = 0; i < sizeof(x); ++i)
	  balance.bytes[sizeof(balance) - 1 - i] = static_cast<uint8_t>(x >> (8 * i));
  }
};

/// Mocked EVMC Host implementation.
class EOSHostContext : public Host {
 public:
  /// LOG record.
  struct log_record {
	/// The address of the account which created the log.
	address creator;

	/// The data attached to the log.
	bytes data;

	/// The log topics.
	std::vector<bytes32> topics;

	/// Equal operator.
	bool operator==(const log_record &other) const noexcept {
	  return creator == other.creator && data == other.data && topics == other.topics;
	}
  };

  /// SELFDESTRUCT record.
  struct selfdestuct_record {
	/// The address of the account which has self-destructed.
	address selfdestructed;

	/// The address of the beneficiary account.
	address beneficiary;

	/// Equal operator.
	bool operator==(const selfdestuct_record &other) const noexcept {
	  return selfdestructed == other.selfdestructed && beneficiary == other.beneficiary;
	}
  };

  /// contract
  EOSHostContext(std::shared_ptr<eosio::contract> contract_ptr) : _contract(contract_ptr) {};
  std::shared_ptr<eosio::contract> _contract;

  /// The set of all accounts in the Host, organized by their addresses.
  std::unordered_map<address, MockedAccount> accounts;

  /// The EVMC transaction context to be returned by get_tx_context().
  evmc_tx_context tx_context = {};

  /// The block header hash value to be returned by get_block_hash().
  bytes32 block_hash = {};

  /// The call result to be returned by the call() method.
  evmc_result call_result = {};

  /// The record of all block numbers for which get_block_hash() was called.
  mutable std::vector<int64_t> recorded_blockhashes;

  /// The record of all account accesses.
  mutable std::vector<address> recorded_account_accesses;

  /// The maximum number of entries in recorded_account_accesses record.
  /// This is arbitrary value useful in fuzzing when we don't want the record to explode.
  static constexpr auto max_recorded_account_accesses = 200;

  /// The record of all call messages requested in the call() method.
  std::vector<evmc_message> recorded_calls;

  /// The maximum number of entries in recorded_calls record.
  /// This is arbitrary value useful in fuzzing when we don't want the record to explode.
  static constexpr auto max_recorded_calls = 100;

  /// The record of all LOGs passed to the emit_log() method.
  std::vector<log_record> recorded_logs;

  /// The record of all SELFDESTRUCTs from the selfdestruct() method.
  std::vector<selfdestuct_record> recorded_selfdestructs;

 protected:
  /// The copy of call inputs for the recorded_calls record.
  std::vector<bytes> m_recorded_calls_inputs;

  /// Record an account access.
  /// @param addr  The address of the accessed account.
  void record_account_access(const address &addr) const {
	if (recorded_account_accesses.empty())
	  recorded_account_accesses.reserve(max_recorded_account_accesses);

	if (recorded_account_accesses.size() < max_recorded_account_accesses)
	  recorded_account_accesses.emplace_back(addr);
  }

  eosio::checksum256 byte_array_addr_to_eth_addr(const address &addr) const {
    auto addr_bytes = addr.bytes;
    std::array<uint8_t, 32> eth_array;
    std::copy_n(&addr_bytes[0], 20, eth_array.begin());
    eth_addr _addr = eosio::fixed_bytes<32>(eth_array);
    return _addr;
  }

  /// Returns true if an account exists (EVMC Host method).
  bool account_exists(const address &addr) const noexcept override {
	record_account_access(addr);
	eth_addr _addr = byte_array_addr_to_eth_addr(addr);
	test_contract::tb_account _account(_contract->get_self(), _contract->get_self().value);
	auto by_eth_account_index = _account.get_index<eosio::name("byeth")>();
	auto itr_eth_addr = by_eth_account_index.find(_addr);
	return itr_eth_addr != by_eth_account_index.end();
  }

  /// Get the account's storage value at the given key (EVMC Host method).
  bytes32 get_storage(const address &addr, const bytes32 &key) const noexcept override {
	record_account_access(addr);
        /// copy address to _addr(eosio::checksum256)
        std::array<uint8_t, 32> eth_array;
        eth_array.fill({});
        std::copy_n(&addr.bytes[0], 20, eth_array.begin());
        eosio::checksum256 _addr = eosio::fixed_bytes<32>(eth_array);
	test_contract::tb_account _account(_contract->get_self(), _contract->get_self().value);
	auto by_eth_account_index = _account.get_index<eosio::name("byeth")>();
	auto itr_eth_addr = by_eth_account_index.find(_addr);
	if (itr_eth_addr == by_eth_account_index.end()) return {};

	test_contract::tb_account_storage _account_store(_contract->get_self(), itr_eth_addr->eosio_account.value);
	auto by_eth_account_storage_index = _account_store.get_index<eosio::name("bystorekey")>();
	/// key to checksum256
	  std::array<uint8_t, 32> key_array;
	  std::copy(&key.bytes[0], &key.bytes[0] + 32, key_array.begin());
	  eosio::checksum256 key_eosio = eosio::fixed_bytes<32>(key_array);

	auto itr_eth_addr_store = by_eth_account_storage_index.find(key_eosio);
	if (itr_eth_addr_store != by_eth_account_storage_index.end()) {
		bytes32 value{};
		auto storage_value = itr_eth_addr_store->storage_val;
		auto storage_value_array = storage_value.extract_as_byte_array();
		std::copy(storage_value_array.begin(), storage_value_array.end(), &value.bytes[0]);
		return value;
	}
	return {};
  }

  /// Set the account's storage value (EVMC Host method).
  evmc_storage_status set_storage(const address &addr,
								  const bytes32 &key,
								  const bytes32 &value) noexcept override {
	record_account_access(addr);
	/// copy address to _addr(eosio::checksum256)
	std::array<uint8_t, 32> eth_array;
	eth_array.fill({});
	std::copy_n(&addr.bytes[0], 20, eth_array.begin());
	eosio::checksum256 _addr = eosio::fixed_bytes<32>(eth_array);
	test_contract::tb_account _account(_contract->get_self(), _contract->get_self().value);
	auto by_eth_account_index = _account.get_index<eosio::name("byeth")>();

	auto itr_eth_addr = by_eth_account_index.find(_addr);
	if (itr_eth_addr == by_eth_account_index.end())
		return EVMC_STORAGE_UNCHANGED;
	eosio::print("\n set2");

	  test_contract::tb_account_storage _account_store(_contract->get_self(), itr_eth_addr->eosio_account.value);
	  auto by_eth_account_storage_index = _account_store.get_index<eosio::name("bystorekey")>();
	  /// key to checksum256
	  std::array<uint8_t, 32> key_array;
	  std::copy(&key.bytes[0], &key.bytes[0] + 32, key_array.begin());
	  eosio::checksum256 key_eosio = eosio::fixed_bytes<32>(key_array);
	  auto itr_eth_addr_store = by_eth_account_storage_index.find(key_eosio);
	  /// value to checksum256
	  std::array<uint8_t, 32> new_value_array;
	  std::copy(&value.bytes[0], &value.bytes[0] + 32, new_value_array.begin());
	  eosio::checksum256 new_value_eosio = eosio::fixed_bytes<32>(new_value_array);

	  evmc_storage_status status{};
	  if (itr_eth_addr_store == by_eth_account_storage_index.end()) {
	  	_account_store.emplace(itr_eth_addr->eosio_account, [&](auto &the_store){
			the_store.id = _account_store.available_primary_key();
			the_store.storage_key = key_eosio;
	  		the_store.storage_val = new_value_eosio;
	  	});
	  	status = EVMC_STORAGE_ADDED;
	  	return  status;
	  } else {
		  auto old_value = itr_eth_addr_store->storage_val;
		  if (old_value == new_value_eosio) {
			  status = EVMC_STORAGE_UNCHANGED;
			  return status;
		  }
		  _account_store.modify(*itr_eth_addr_store, itr_eth_addr->eosio_account, [&](auto &the_store){
			  the_store.storage_val = new_value_eosio;
		  });
		  status = EVMC_STORAGE_MODIFIED;
		  return status;
	  }

//	const auto it = accounts.find(addr);
//	if (it == accounts.end())
//	  return EVMC_STORAGE_UNCHANGED;
//
//	auto old = it->second.storage[key];
//
//	// Follow https://eips.ethereum.org/EIPS/eip-1283 specification.
//	// WARNING! This is not complete implementation as refund is not handled here.
//
//	if (old.value == value)
//	  return EVMC_STORAGE_UNCHANGED;
//
//	evmc_storage_status status{};
//	if (!old.dirty) {
//	  old.dirty = true;
//	  if (!old.value)
//		status = EVMC_STORAGE_ADDED;
//	  else if (value)
//		status = EVMC_STORAGE_MODIFIED;
//	  else
//		status = EVMC_STORAGE_DELETED;
//	} else
//	  status = EVMC_STORAGE_MODIFIED_AGAIN;
//
//	old.value = value;
//	return status;
  }

  /// Get the account's balance (EVMC Host method).
  uint256be get_balance(const address &addr) const noexcept override {
	eth_addr _addr = byte_array_addr_to_eth_addr(addr);
	test_contract::tb_account _account(_contract->get_self(), _contract->get_self().value);
	auto by_eth_account_index = _account.get_index<eosio::name("byeth")>();
	auto itr_eth_addr = by_eth_account_index.find(_addr);

	asset eos_balance = itr_eth_addr->eosio_balance;
	uint64_t eos_value = eos_balance.amount;
	uint256be balance;
	std::string balance_str = int2hex(eos_value);
	auto hex_balance = HexToBytes(balance_str);
	std::copy(hex_balance.begin(), hex_balance.end(), &balance.bytes[20]);
	/// convert contract_balance to bytes32
	return balance;
  }

  /// Get the account's code size (EVMC host method).
  size_t get_code_size(const address &addr) const noexcept override {
	eth_addr _addr = byte_array_addr_to_eth_addr(addr);
	test_contract::tb_account_code _account_code(_contract->get_self(), _contract->get_self().value);
	auto by_eth_account_code_index = _account_code.get_index<eosio::name("byeth")>();
	auto itr_eth_code = by_eth_account_code_index.find(_addr);
	assert_b(itr_eth_code != by_eth_account_code_index.end(), "no such address");
	auto bytecode = itr_eth_code->bytecode;
	return bytecode.size();
  }

  /// Get the account's code hash (EVMC host method).
  bytes32 get_code_hash(const address &addr) const noexcept override {
	eth_addr _addr = byte_array_addr_to_eth_addr(addr);
	test_contract::tb_account_code _account_code(_contract->get_self(), _contract->get_self().value);
	auto by_eth_account_code_index = _account_code.get_index<eosio::name("byeth")>();
	auto itr_eth_code = by_eth_account_code_index.find(_addr);
	assert_b(itr_eth_code != by_eth_account_code_index.end(), "no such address");
	auto code = itr_eth_code->bytecode;
	/// TODO code to hex string then sha256
//  eosio::checksum256 hash_val = eosio::sha256(salt.c_str(), 32);

	/// convert eosio::checksum256 to evmc::byte32
	evmc::bytes32 hash;
	return hash;
  }

  /// Copy the account's code to the given buffer (EVMC host method).
  size_t copy_code(const address &addr,
				   size_t code_offset,
				   uint8_t *buffer_data,
				   size_t buffer_size) const noexcept override {
	record_account_access(addr);
	eth_addr _addr = byte_array_addr_to_eth_addr(addr);
	test_contract::tb_account_code _account_code(_contract->get_self(), _contract->get_self().value);
	auto by_eth_account_code_index = _account_code.get_index<eosio::name("byeth")>();
	auto itr_eth_code = by_eth_account_code_index.find(_addr);
	assert_b(itr_eth_code != by_eth_account_code_index.end(), "no such address");
	auto code = itr_eth_code->bytecode;

	if (code_offset >= code.size()) return 0;

	const auto n = std::min(buffer_size, code.size() - code_offset);
	if (n > 0) {
	  std::copy_n(&code[code_offset], n, buffer_data);
	}
	return n;
  }

  /// Selfdestruct the account (EVMC host method).
  void selfdestruct(const address &addr, const address &beneficiary) noexcept override {
	record_account_access(addr);
	recorded_selfdestructs.push_back({addr, beneficiary});
  }

  /// Call/create other contract (EVMC host method).
  result call(const evmc_message &msg) noexcept override {
	record_account_access(msg.destination);

	if (recorded_calls.empty()) {
	  recorded_calls.reserve(max_recorded_calls);
	  m_recorded_calls_inputs.reserve(max_recorded_calls);  // Iterators will not invalidate.
	}

	if (recorded_calls.size() < max_recorded_calls) {
	  recorded_calls.emplace_back(msg);
	  auto &call_msg = recorded_calls.back();
	  if (call_msg.input_size > 0) {
		m_recorded_calls_inputs.emplace_back(call_msg.input_data, call_msg.input_size);
		const auto &input_copy = m_recorded_calls_inputs.back();
		call_msg.input_data = input_copy.data();
	  }
	}
	return result{call_result};
  }

  /// Get transaction context (EVMC host method).
  evmc_tx_context get_tx_context() const noexcept override {
	evmc_tx_context result = {};
//    result.tx_gas_price = toEvmC(m_extVM.gasPrice); /**< The transaction gas price. */
//    result.tx_origin = toEvmC(m_extVM.origin); /**< The transaction origin account. */
//    result.block_coinbase = toEvmC(envInfo.author());  /**< The miner of the block. */
//    result.block_number = envInfo.number();          /**< The block number. */
//    result.block_timestamp = envInfo.timestamp();    /**< The block timestamp. */
//    result.block_gas_limit = static_cast<int64_t>(envInfo.gasLimit());
//    result.block_difficulty = toEvmC(envInfo.difficulty());
//    result.chain_id = toEvmC(envInfo.chainID());  /**< The blockchain's ChainID. */

//	result.tx_gas_price = 100;
//	result.tx_origin = current_receiver();
//	result.block_coinbase = name{eosio};
//	result.block_number = eosio::tapos_block_num();
//	result.block_timestamp = eosio::publication_time();
//	result.block_gas_limit = 10000;
//	result.block_difficulty = 10;

    return result;
  }

  /// Get the block header hash (EVMC host method).
  bytes32 get_block_hash(int64_t block_number) const noexcept override {
	recorded_blockhashes.emplace_back(block_number);
	return block_hash;
  }

  /// Emit LOG (EVMC host method).
  void emit_log(const address &addr,
				const uint8_t *data,
				size_t data_size,
				const bytes32 topics[],
				size_t topics_count) noexcept override {
	recorded_logs.push_back({addr, {data, data_size}, {topics, topics + topics_count}});
  }

  void assert_b(bool test, const char *msg) const {
	eosio::internal_use_do_not_use::eosio_assert(static_cast<uint32_t>(test), msg);
  }
};
}  // namespace evmc


