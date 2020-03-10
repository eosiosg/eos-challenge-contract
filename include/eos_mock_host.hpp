// Copyright 2019 The EVMC Authors.
// Licensed under the Apache License, Version 2.0.
#pragma once

#include <evmc/evmc.hpp>
#include <algorithm>
#include <string>
#include <vector>
#include <eosio/eosio.hpp>
#include <eosio/action.hpp>
#include <eosio/transaction.hpp>
#include <eos_evm.hpp>
#include <utils.hpp>

using namespace eosio;
namespace evmc {
/// The string of bytes.
using bytes = std::basic_string<uint8_t>;

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
    eth_array.fill({});
    std::copy_n(&addr_bytes[0], 20, eth_array.begin() + PADDING);
    eth_addr_256 _addr = eosio::fixed_bytes<32>(eth_array);
    return _addr;
  }

  /// Returns true if an account exists (EVMC Host method).
  bool account_exists(const address &addr) const noexcept override {
	record_account_access(addr);
	eth_addr_256 _addr = byte_array_addr_to_eth_addr(addr);
	eos_evm::tb_account _account(_contract->get_self(), _contract->get_self().value);
	auto by_eth_account_index = _account.get_index<eosio::name("byeth")>();
	auto itr_eth_addr = by_eth_account_index.find(_addr);
	return itr_eth_addr != by_eth_account_index.end();
  }

  /// Get the account's storage value at the given key (EVMC Host method).
  bytes32 get_storage(const address &addr, const bytes32 &key) const noexcept override {
	record_account_access(addr);
    eth_addr_256 _addr = byte_array_addr_to_eth_addr(addr);
	eos_evm::tb_account _account(_contract->get_self(), _contract->get_self().value);
	auto by_eth_account_index = _account.get_index<eosio::name("byeth")>();
	auto itr_eth_addr = by_eth_account_index.find(_addr);
	if (itr_eth_addr == by_eth_account_index.end()) return {};

	eos_evm::tb_account_storage _account_store(_contract->get_self(), itr_eth_addr->id);
	auto by_eth_account_storage_index = _account_store.get_index<eosio::name("bystorekey")>();
	/// key to checksum256
	std::array<uint8_t, 32> key_array;
	std::copy_n(&key.bytes[0], sizeof(bytes32), key_array.begin());
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
	eth_addr_256 _addr = byte_array_addr_to_eth_addr(addr);

	eos_evm::tb_account _account(_contract->get_self(), _contract->get_self().value);
	auto by_eth_account_index = _account.get_index<eosio::name("byeth")>();

	auto itr_eth_addr = by_eth_account_index.find(_addr);
	if (itr_eth_addr == by_eth_account_index.end())
		return EVMC_STORAGE_UNCHANGED;
	eosio::print("\n setting storage...");

	  eos_evm::tb_account_storage _account_store(_contract->get_self(), itr_eth_addr->id);
	  auto by_eth_account_storage_index = _account_store.get_index<eosio::name("bystorekey")>();
	  /// key to checksum256
	  std::array<uint8_t, 32> key_array;
	  std::copy(&key.bytes[0], &key.bytes[0] + sizeof(bytes32), key_array.begin());
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
  }

  /// Get the account's balance (EVMC Host method).
  uint256be get_balance(const address &addr) const noexcept override {
	  eth_addr_256 _addr = byte_array_addr_to_eth_addr(addr);

	  eos_evm::tb_account _account(_contract->get_self(), _contract->get_self().value);
	  auto by_eth_account_index = _account.get_index<eosio::name("byeth")>();

	  auto itr_eth_addr = by_eth_account_index.find(_addr);
	  eos_evm::tb_account_storage _account_store(_contract->get_self(), itr_eth_addr->id);
	  auto by_eth_account_storage_index = _account_store.get_index<eosio::name("bystorekey")>();

	  /// TODO need to test
	  auto itr_eth_addr_store = by_eth_account_storage_index.find(_addr);
	  auto _balance = itr_eth_addr_store->storage_val;
	  /// copy eosio::checksum256 balance to uint256be
	  uint256be balance;
	  auto store_value_array = _balance.extract_as_byte_array();
	  std::copy(store_value_array.begin(), store_value_array.end(), &balance.bytes[0]);
	  return balance;
  }

  /// Get the account's code size (EVMC host method).
  size_t get_code_size(const address &addr) const noexcept override {
	eth_addr_256 _addr = byte_array_addr_to_eth_addr(addr);
	eos_evm::tb_account_code _account_code(_contract->get_self(), _contract->get_self().value);
	auto by_eth_account_code_index = _account_code.get_index<eosio::name("byeth")>();
	auto itr_eth_code = by_eth_account_code_index.find(_addr);
	if (itr_eth_code == by_eth_account_code_index.end()) {
	    return {};
	} else {
        auto bytecode = itr_eth_code->bytecode;
        return bytecode.size();
	}
  }

  /// Get the account's code hash (EVMC host method).
  bytes32 get_code_hash(const address &addr) const noexcept override {
	eth_addr_256 _addr = byte_array_addr_to_eth_addr(addr);
	eos_evm::tb_account_code _account_code(_contract->get_self(), _contract->get_self().value);
	auto by_eth_account_code_index = _account_code.get_index<eosio::name("byeth")>();
	auto itr_eth_code = by_eth_account_code_index.find(_addr);
	if (itr_eth_code == by_eth_account_code_index.end()) {
	    return {};
	} else {
        auto code = itr_eth_code->bytecode;
        eosio::checksum256 code_hash = eosio::sha256((const char *)code.data(), (uint32_t)code.size());
        /// convert eosio::checksum256 to evmc::byte32
        evmc::bytes32 hash;
        auto code_hash_arr = code_hash.extract_as_byte_array();
        std::copy(code_hash_arr.begin(), code_hash_arr.end(), &hash.bytes[0]);
        return hash;
    }
  }

  /// Copy the account's code to the given buffer (EVMC host method).
  size_t copy_code(const address &addr,
				   size_t code_offset,
				   uint8_t *buffer_data,
				   size_t buffer_size) const noexcept override {
	record_account_access(addr);
	eth_addr_256 _addr = byte_array_addr_to_eth_addr(addr);
	eos_evm::tb_account_code _account_code(_contract->get_self(), _contract->get_self().value);
	auto by_eth_account_code_index = _account_code.get_index<eosio::name("byeth")>();
	auto itr_eth_code = by_eth_account_code_index.find(_addr);
	if (itr_eth_code == by_eth_account_code_index.end()) {
	    return 0;
	} else {
        auto code = itr_eth_code->bytecode;

        if (code_offset >= code.size()) return 0;

        const auto n = std::min(buffer_size, code.size() - code_offset);
        if (n > 0) {
            std::copy_n(&code[code_offset], n, buffer_data);
        }
        return n;
	}
  }

  /// Selfdestruct the account (EVMC host method).
  void selfdestruct(const address &addr, const address &beneficiary) noexcept override {
      eth_addr_256 _addr = byte_array_addr_to_eth_addr(addr);
      /// 1. remove account table record
      eos_evm::tb_account _account(_contract->get_self(), _contract->get_self().value);
      auto by_eth_account_index = _account.get_index<eosio::name("byeth")>();
      auto itr_eth_addr = by_eth_account_index.find(_addr);
      if (itr_eth_addr != by_eth_account_index.end()) {
          by_eth_account_index.erase(itr_eth_addr);
      }
      /// 2. remove account code table record
      eos_evm::tb_account_code _account_code(_contract->get_self(), _contract->get_self().value);
      auto by_eth_account_code_index = _account_code.get_index<eosio::name("byeth")>();
      auto itr_eth_code = by_eth_account_code_index.find(_addr);
      if (itr_eth_code != by_eth_account_code_index.end()) {
          by_eth_account_code_index.erase(itr_eth_code);
      }
      /// 3. remove account storage record
      eos_evm::tb_account_storage _account_store(_contract->get_self(), itr_eth_addr->id);
      auto by_eth_account_storage_index = _account_store.get_index<eosio::name("bystorekey")>();
      auto itr_eth_addr_store = by_eth_account_storage_index.begin();
      while(itr_eth_addr_store != by_eth_account_storage_index.end()) {
          /// TODO: if have large amount of data need to batch delete
          by_eth_account_storage_index.erase(itr_eth_addr_store);
      }
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
	result.block_coinbase = evmc_address({0});
	result.block_number = eosio::tapos_block_num();
	result.block_timestamp = eosio::time_point().sec_since_epoch();
	result.block_gas_limit = 10000000;
	result.block_difficulty = evmc_uint256be({0});

    return result;
  }

  /// Get the block header hash (EVMC host method).
  bytes32 get_block_hash(int64_t block_number) const noexcept override {
    bytes32 block_hash({0});
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


