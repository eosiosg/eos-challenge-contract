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
  /// contract
  EOSHostContext(std::shared_ptr<eosio::contract> contract_ptr) : _contract(contract_ptr) {};
  std::shared_ptr<eosio::contract> _contract;

  /// The EVMC transaction context to be returned by get_tx_context().
  evmc_tx_context tx_context = {};

  /// The block header hash value to be returned by get_block_hash().
  bytes32 block_hash = {};

  /// eth emit logs
  std::vector<eos_evm::eth_log> eth_emit_logs = {};

  evmc_result create_contract(const address &eth_contract_addr, const evmc_message &message) {
	eosio::check(message.kind == EVMC_CREATE, "message kind must be create");
	eosio::check(message.input_size > 0, "message input size must be > 0");

	eth_addr_160 eth_contract_160 = evmc_address_to_checksum160(eth_contract_addr);
	eth_addr_256 eth_contract_256 = evmc_address_to_checksum256(eth_contract_addr);
	evmc_message msg = message;
	std::vector<uint8_t> code;
	evmc_result result;
	if (!get_code_size(eth_contract_addr)) {
		std::vector<uint8_t> create_code = std::vector<uint8_t>(msg.input_data, msg.input_data + msg.input_size);
		msg.destination = eth_contract_addr;

		/// add account to table
		eos_evm::tb_account _account(_contract->get_self(), _contract->get_self().value);
		auto by_eth_account_index = _account.get_index<eosio::name("byeth")>();
		auto itr_eth_account = by_eth_account_index.find(eth_contract_256);
		if (itr_eth_account == by_eth_account_index.end()) {
			eos_evm::tb_token_contract _token_contract(_contract->get_self(), _contract->get_self().value);
			_account.emplace(_contract->get_self(), [&](auto &the_account) {
				the_account.id = _account.available_primary_key();
				the_account.eth_address = eth_contract_160;
				the_account.nonce = std::static_pointer_cast<eos_evm>(_contract)->get_init_nonce();
				the_account.balance = std::static_pointer_cast<eos_evm>(_contract)->get_init_balance();
				the_account.eosio_account = name();
			});
		}

		result.create_address = eth_contract_addr;

		/// execute create code
		result = vm_execute(create_code, msg);
		/// get raw evm code from result output
		std::vector<uint8_t> raw_evm_code;
		std::copy_n(result.output_data, result.output_size, std::back_inserter(raw_evm_code));

		if (result.status_code == EVMC_SUCCESS) {
			/// add code to table
			eos_evm::tb_account_code _account_code(_contract->get_self(), _contract->get_self().value);
			auto by_eth_account_code_index = _account_code.get_index<eosio::name("byeth")>();
			auto itr_eth_code = by_eth_account_code_index.find(eth_contract_256);
			if (itr_eth_code != by_eth_account_code_index.end()) {
				result.status_code = EVMC_FAILURE;
			}
			_account_code.emplace(_contract->get_self(), [&](auto &the_account_code){
				the_account_code.id = _account_code.available_primary_key();
				the_account_code.eth_address = eth_contract_160;
				the_account_code.bytecode = raw_evm_code;
			});

			result.create_address = eth_contract_addr;
		}
	}
	return result;
  }

	/// get contract address
	address contract_destination(const address &sender, const intx::uint256 &nonce) {
		RLPBuilder rlp_builder;
		rlp_builder.start_list();
		if (nonce == 0) {
			std::vector<uint8_t> empty_nonce;
			rlp_builder.add(empty_nonce);
		} else {
			rlp_builder.add(nonce);
		}
		rlp_builder.add(&sender.bytes[0], sizeof(address));
		std::vector<uint8_t> eth_rlp = rlp_builder.build();

		auto eth = ethash::keccak256(eth_rlp.data(), eth_rlp.size());

		address contract_address;
		std::copy_n(&eth.bytes[0] + PADDING, 20, &contract_address.bytes[0]);

		return contract_address;
	}

  void transfer_fund(const evmc_message &message, evmc_result &result) {
	/// get token symbol
	eos_evm::tb_token_contract _token_contract(_contract->get_self(), _contract->get_self().value);
	/// get transfer amount
	auto transfer_value = message.value;

	/// get balance from and dst
	uint256be sender_balance = get_balance(message.sender);
	uint256be dst_balance = get_balance(message.destination);
	/// check from eth account must exist
	if (!account_exists(message.sender)) {
		result.status_code = EVMC_FAILURE;
		eosio::print("no such sender");
	} else if (sender_balance < transfer_value) {
		result.status_code = EVMC_FAILURE;
		eosio::print("not enough balance");
	} else {
		/// modify table
		eos_evm::tb_account _account(_contract->get_self(), _contract->get_self().value);
		auto by_eth_account_index = _account.get_index<eosio::name("byeth")>();
		auto itr_sender = by_eth_account_index.find(evmc_address_to_checksum256(message.sender));
		/// sub sender balance
		auto transfer_amount_256 = intx::be::unsafe::load<intx::uint256>(&transfer_value.bytes[0]);
		_account.modify(*itr_sender, eosio::same_payer, [&](auto &the_account){
			intx::uint256 old_balance = intx::be::unsafe::load<intx::uint256>(the_account.balance.extract_as_byte_array().data());
			intx::uint256 new_balance = old_balance - transfer_amount_256;
			the_account.balance = intx_uint256_to_uint256_t(new_balance);
		});
		auto itr_dest = by_eth_account_index.find(evmc_address_to_checksum256(message.destination));
		/// add destination balance
		if (itr_dest == by_eth_account_index.end()) {
			_account.emplace(_contract->get_self(), [&](auto &the_account) {
				the_account.id = _account.available_primary_key();
				the_account.eth_address = evmc_address_to_checksum160(message.destination);
				the_account.nonce = std::static_pointer_cast<eos_evm>(_contract)->get_init_nonce();
				/// add balance
				intx::uint256 balance = transfer_amount_256;
				the_account.balance = intx_uint256_to_uint256_t(balance);
				the_account.eosio_account = name();
			});
		} else {
			_account.modify(*itr_dest, eosio::same_payer, [&](auto &the_account) {
				intx::uint256 old_balance = intx::be::unsafe::load<intx::uint256>(the_account.balance.extract_as_byte_array().data());
				intx::uint256 new_balance = old_balance + transfer_amount_256;
				the_account.balance = intx_uint256_to_uint256_t(new_balance);
			});
		}
		result.status_code = EVMC_SUCCESS;
	}
  }

  evmc_result vm_execute(std::vector<uint8_t> &code, const evmc_message &msg) {
	evmc_revision rev = EVMC_BYZANTIUM;
	auto vm = evmc_create_evmone();
	evmc_result result = vm->execute(vm, &get_interface(), this->to_context(), rev, &msg, code.data(), code.size());
	return result;
  }
 protected:

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
	  print(" \n account exists");

	eth_addr_256 _addr = byte_array_addr_to_eth_addr(addr);
	eos_evm::tb_account _account(_contract->get_self(), _contract->get_self().value);
	auto by_eth_account_index = _account.get_index<eosio::name("byeth")>();
	auto itr_eth_addr = by_eth_account_index.find(_addr);
	return itr_eth_addr != by_eth_account_index.end();
  }

  /// Get the account's storage value at the given key (EVMC Host method).
  bytes32 get_storage(const address &addr, const bytes32 &key) const noexcept override {
    eth_addr_256 _addr = byte_array_addr_to_eth_addr(addr);
	eos_evm::tb_account _account(_contract->get_self(), _contract->get_self().value);
	auto by_eth_account_index = _account.get_index<eosio::name("byeth")>();
	auto itr_eth_addr = by_eth_account_index.find(_addr);
	if (itr_eth_addr == by_eth_account_index.end()) return {};

	eos_evm::tb_account_state _account_state(_contract->get_self(), itr_eth_addr->id);
	auto by_eth_account_state_index = _account_state.get_index<eosio::name("bystatekey")>();
	/// key to checksum256
	std::array<uint8_t, 32> key_array;
	std::copy_n(&key.bytes[0], sizeof(bytes32), key_array.begin());
	eosio::checksum256 key_eosio = eosio::fixed_bytes<32>(key_array);
	auto itr_eth_addr_state = by_eth_account_state_index.find(key_eosio);
	if (itr_eth_addr_state != by_eth_account_state_index.end()) {
		bytes32 value{};
		auto state_value = itr_eth_addr_state->value;
		auto state_value_array = state_value.extract_as_byte_array();
		std::copy(state_value_array.begin(), state_value_array.end(), &value.bytes[0]);
		return value;
	}
	return {};
  }

  /// Set the account's storage value (EVMC Host method).
  evmc_storage_status set_storage(const address &addr,
								  const bytes32 &key,
								  const bytes32 &value) noexcept override {
	/// copy address to _addr(eosio::checksum256)
	eth_addr_256 _addr = byte_array_addr_to_eth_addr(addr);
	eos_evm::tb_account _account(_contract->get_self(), _contract->get_self().value);
	auto by_eth_account_index = _account.get_index<eosio::name("byeth")>();

	auto itr_eth_addr = by_eth_account_index.find(_addr);
	if (itr_eth_addr == by_eth_account_index.end())
		return EVMC_STORAGE_UNCHANGED;
	eosio::print("\n setting storage...");

	  eos_evm::tb_account_state _account_state(_contract->get_self(), itr_eth_addr->id);
	  auto by_eth_account_state_index = _account_state.get_index<eosio::name("bystatekey")>();
	  /// key to checksum256
	  std::array<uint8_t, 32> key_array;
	  std::copy(&key.bytes[0], &key.bytes[0] + sizeof(bytes32), key_array.begin());
	  eosio::checksum256 key_eosio = eosio::fixed_bytes<32>(key_array);
	  auto itr_eth_addr_state = by_eth_account_state_index.find(key_eosio);
	  /// value to checksum256
	  std::array<uint8_t, 32> new_value_array;
	  std::copy(&value.bytes[0], &value.bytes[0] + 32, new_value_array.begin());
	  eosio::checksum256 new_value_eosio = eosio::fixed_bytes<32>(new_value_array);

	  evmc_storage_status status{};
	  if (itr_eth_addr_state == by_eth_account_state_index.end()) {
		_account_state.emplace(_contract->get_self(), [&](auto &the_state){
			the_state.id = _account_state.available_primary_key();
			the_state.key = key_eosio;
			the_state.value = new_value_eosio;
		});
		status = EVMC_STORAGE_ADDED;
		return  status;
	  } else {
		  auto old_value = itr_eth_addr_state->value;
		  if (old_value == new_value_eosio) {
			  status = EVMC_STORAGE_UNCHANGED;
			  return status;
		  }
		  _account_state.modify(*itr_eth_addr_state, eosio::same_payer, [&](auto &the_state){
			  the_state.value = new_value_eosio;
		  });
		  status = EVMC_STORAGE_MODIFIED;
		  return status;
	  }
  }

  /// Get the account's balance (EVMC Host method).
  uint256be get_balance(const address &addr) const noexcept override {
	  print(" \n get balance");
	  eth_addr_256 _addr = byte_array_addr_to_eth_addr(addr);

	  eos_evm::tb_account _account(_contract->get_self(), _contract->get_self().value);
	  auto by_eth_account_index = _account.get_index<eosio::name("byeth")>();

	  auto itr_eth_addr = by_eth_account_index.find(_addr);
	  if (itr_eth_addr == by_eth_account_index.end()) {
	  	return {};
	  }
	  auto balance_eosio = itr_eth_addr->balance;

	  eos_evm::tb_token_contract _token_contract(_contract->get_self(), _contract->get_self().value);
	  eosio::check(_token_contract.begin() != _token_contract.end(), "must link token contract first");
	  auto itr_token_contract = _token_contract.begin();
	  auto sym_precision = itr_token_contract->contract.get_symbol().precision();

	  return checksum256_to_evmc_uint256(balance_eosio);
  }

  /// Get the account's code size (EVMC host method).
  size_t get_code_size(const address &addr) const noexcept override {
	  print(" \n get code size");
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
	  print(" \n get code hash");
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
  	print(" \n copy code");
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
      /// 3. remove account state record
      eos_evm::tb_account_state _account_state(_contract->get_self(), itr_eth_addr->id);
      auto by_eth_account_state_index = _account_state.get_index<eosio::name("bystatekey")>();
      auto itr_eth_addr_state = by_eth_account_state_index.begin();
      while(itr_eth_addr_state != by_eth_account_state_index.end()) {
          /// TODO: if have large amount of data need to batch delete
          by_eth_account_state_index.erase(itr_eth_addr_state);
      }
  }

  /// Call/create other contract (EVMC host method).
  result call(const evmc_message &msg) noexcept override {
  	print(" \n  call code..");
	eosio::check(msg.depth > 0, "call depth should > 0");
	auto eos_evm_ptr = std::static_pointer_cast<eos_evm>(_contract);
	evmc_result _result;
	_result.output_data = nullptr;
	_result.output_size = 0;
	_result.create_address = {0};
	_result.release = nullptr;
	if (msg.kind == EVMC_CREATE) {
		/// get nonce
		auto nonce = std::static_pointer_cast<eos_evm>(_contract)->get_nonce(msg);
		/// create contract address
		auto eth_contract_addr = contract_destination(msg.sender, nonce);
		/// set nonce
		std::static_pointer_cast<eos_evm>(_contract)->set_nonce(msg);
		/// set contract
		_result = create_contract(eth_contract_addr, msg);
	} else {
		auto code = eos_evm_ptr->get_eth_code(evmc_address_to_checksum256(msg.destination));
		_result = vm_execute(code, msg);
		if (_result.status_code == EVMC_SUCCESS) {
			/// transfer value
			auto transfer_val = intx::be::unsafe::load<intx::uint256>(&msg.value.bytes[0]);
			/// transfer asset
			if (transfer_val > 0) {
				transfer_fund(msg, _result);
			}
		} else {
			_result.status_code = EVMC_FAILURE;
		}
	}

	return result(_result);
  }

  /// Get transaction context (EVMC host method).
  evmc_tx_context get_tx_context() const noexcept override {
	  print(" \n get tx context");
	evmc_tx_context result = {};
//	result.tx_gas_price = 100000;
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
  	eos_evm::eth_log emit_log;
  	emit_log.address = addr;
  	for (size_t i = 0; i < topics_count; i++) {
  		emit_log.topics.push_back(evmc_bytes32(topics[i]));
  	}
  	std::copy(data, data + data_size, std::back_inserter(emit_log.data));
  	eth_emit_logs.push_back(emit_log);
  	/// print eth emit logs
  	auto print_emit_logs = [&](eos_evm::eth_log &emit_log){
  		print(" \n address    : "); printhex(&emit_log.address.bytes[0], sizeof(evmc_address));
  		print(" \n topic      : ", emit_log.topics_to_string());
  		print(" \n data       : "); printhex(emit_log.data.data(), emit_log.data.size());
  	};
	print(" \nemit log    : ");     std::for_each(eth_emit_logs.begin(), eth_emit_logs.end(), print_emit_logs);
  }
};
}  // namespace evmc


