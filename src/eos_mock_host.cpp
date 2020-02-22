//
// Created by Yu Yang Zhang on 2/21/20.
//

#pragma once

#include <eosio/eosio.hpp>
#include <eosio/asset.hpp>
#include <eosio/crypto.hpp>
#include <eosio/privileged.hpp>
#include "eos_mock_host.hpp"
#include <eosio.token.hpp>

using namespace evmc;

typedef eosio::checksum160 eosio_addr;
/// @copydoc evmc_host_interface::account_exists
bool account_exists(const address &addr) {
  /// TODO uint8_t bytes[20]; copy to eosio::checksum160
  eth_addr _addr;
  tb_account _account(_self, _self.value);
  auto itr_account = _account.find(_addr);
  return itr_account == _account.end();
};

/// @copydoc evmc_host_interface::get_storage
bytes32 get_storage(const address &addr, const bytes32 &key) {
  // get EOS addr from evm addr
  /// TODO uint8_t bytes[20]; copy to eosio::checksum160
  eth_addr _addr;
  tb_account _account(_self, _self.value);
  auto itr_account = _account.find(_addr);
  name eos_account = itr_account->eosio_account;

  int64_t ram; int64_t cpu; int_64_t net;
  get_resource_limits(eos_account, ram, cpu, net);
  /// TODO ram copy back to uint8_t bytes[32];
  evmc::bytes32 ram_left;
  return ram_left;
};

/// @copydoc evmc_host_interface::set_storage
evmc_storage_status set_storage(const address &addr,
								const bytes32 &key,
								const bytes32 &value) {
  // buy ram?
  eth_addr _addr;
  tb_account _account(_self, _self.value);
  auto itr_account = _account.find(_addr);
  name eos_account = itr_account->eosio_account;

  require_auth(eos_account);
  action(
	  permission_level(_self, N(active)),
	  N(eosio),
	  N(buyram),
	  std::make_tuple(eos_account, eos_account, asset{1, S(4, EOS)})
  ).send();
};

/// @copydoc evmc_host_interface::get_balance
uint256be get_balance(const address &addr) {
  eth_addr _addr;
  tb_account _account(_self, _self.value);
  auto itr_account = _account.find(_addr);
  name eos_account = itr_account->eosio_account;

  // EOS balance
  eosio::token t(N(eosio.token));
  const auto sym_name = eosio::symbol_type(S(4,EOS)).name();
  const auto my_balance = t.get_balance(N(eos_account), sym_name );

  // contract balance
  asset contract_balance = itr_account->eosio_balance;

  // EOS balance + contract balance
  asset total_balance = my_balance + contract_balance;
  uint256be balance;

  /// convert total_balance to bytes32
  return balance;
};

/// @copydoc evmc_host_interface::get_code_size
size_t get_code_size(const address &addr) {
  /// TODO convert address to eosio::checksum160
  eth_addr _addr;
  tb_account_code _account_code(_self, _self.value);
  auto itr_account_code = _account_code.find(_addr);
  if (itr_account_code == _account_code.end()) return 0;
  auto bytecode = itr_account_code->bytecode;
  return bytecode.size();
};

/// @copydoc evmc_host_interface::get_code_hash
bytes32 get_code_hash(const address &addr) {
  eth_addr _addr;
  tb_account_code _account_code(_self, _self.value);
  auto itr_account_code = _account_code.find(_addr);
  if (itr_account_code == _account_code.end()) return 0;
  auto code = itr_account_code->bytecode;
  eosio::checksum256 hash_val = sha256(code.data(), code.size());

  /// convert eosio::checksum256 to evmc::byte32
  evmc::bytes32 hash;
  return hash;
};

/// @copydoc evmc_host_interface::copy_code
size_t copy_code(const address &addr,
				 size_t code_offset,
				 uint8_t *buffer_data,
				 size_t buffer_size) {

};

/// @copydoc evmc_host_interface::selfdestruct
void selfdestruct(const address &addr, const address &beneficiary) {
  // remove code
  eth_addr _addr;
  tb_account_code _account_code(_self, _self.value);
  auto itr_account_code = _account_code.find(_addr);
  if (itr_account_code == _account_code.end()) return;
  _account_code.erase(itr_account_code);
  // release ram

};

/// @copydoc evmc_host_interface::call
result call(const evmc_message &msg) {

};

/// @copydoc evmc_host_interface::get_tx_context
//evmc_tx_context get_tx_context() {
//  struct evmc_tx_context
//  {
//	evmc_uint256be tx_gas_price;     /**< The transaction gas price. */
//	evmc_address tx_origin;          /**< The transaction origin account. */
//	evmc_address block_coinbase;     /**< The miner of the block. */
//	int64_t block_number;            /**< The block number. */
//	int64_t block_timestamp;         /**< The block timestamp. */
//	int64_t block_gas_limit;         /**< The block gas limit. */
//	evmc_uint256be block_difficulty; /**< The block difficulty. */
//	evmc_uint256be chain_id;         /**< The blockchain's ChainID. */
//  };

//   evmc_uint256be chain_id;
//   auto chain_id =
//};

/// @copydoc evmc_host_interface::get_block_hash
bytes32 get_block_hash(int64_t block_number) {
	return bytes32{{0}};
};

///// @copydoc evmc_host_interface::emit_log
//void emit_log(const address &addr,
//			  const uint8_t *data,
//			  size_t data_size,
//			  const bytes32 topics[],
//			  size_t num_topics) {
//
//};
