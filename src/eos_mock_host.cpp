//
// Created by Yu Yang Zhang on 2/21/20.
//

#include <eosio/eosio.hpp>
#include <eosio/privileged.hpp>
#include "eos_mock_host.hpp"
#include <eosio.token.hpp>

using namespace evmc;

typedef eosio::checksum256 eosio_addr;

EOSHostContext::EOSHostContext(std::shared_ptr<eosio::contract> contract_ptr): _contract(contract_ptr){
}

/// @copydoc evmc_host_interface::account_exists
bool EOSHostContext::account_exists(const evmc::address &addr) const noexcept {
  /// TODO uint8_t bytes[20]; copy to eosio::checksum160
  eth_addr _addr;
  test_contract::tb_account _account(_contract->get_self(), _contract->get_self().value);
  auto by_eth_account_index = _account.get_index<name("byeth")>();
  auto itr_eth_addr = by_eth_account_index.find(_addr);
  return itr_eth_addr != by_eth_account_index.end();
};

/// @copydoc evmc_host_interface::get_storage
bytes32 EOSHostContext::get_storage(const address &addr, const bytes32 &key) const noexcept{
  // get EOS addr from evm addr
  /// TODO uint8_t bytes[20]; copy to eosio::checksum160
  eth_addr _addr;
  test_contract::tb_account _account(_contract->get_self(), _contract->get_self().value);
  auto by_eth_account_index = _account.get_index<name("byeth")>();
  auto itr_eth_addr = by_eth_account_index.find(_addr);

  /// mock storage in EOS host
  /// TODO ram copy back to uint8_t bytes[32];
  evmc::bytes32 ram_left;
  return ram_left;
};

/// @copydoc evmc_host_interface::set_storage
evmc_storage_status EOSHostContext::set_storage(const address &addr,
								const bytes32 &key,
								const bytes32 &value) noexcept{
  // buy ram?
  eth_addr _addr;
  test_contract::tb_account _account(_contract->get_self(), _contract->get_self().value);
  auto by_eth_account_index = _account.get_index<name("byeth")>();
  auto itr_eth_addr = by_eth_account_index.find(_addr);
  /// mock storage in EOS host
  evmc_storage_status status;
  return status;
};

/// @copydoc evmc_host_interface::get_balance
uint256be EOSHostContext::get_balance(const address &addr) const noexcept{
  eth_addr _addr;
  test_contract::tb_account _account(_contract->get_self(), _contract->get_self().value);
  auto by_eth_account_index = _account.get_index<name("byeth")>();
  auto itr_eth_addr = by_eth_account_index.find(_addr);

  asset contract_balance = itr_eth_addr->eosio_balance;
  uint256be balance;
  /// convert contract_balance to bytes32
  return balance;
};

/// @copydoc evmc_host_interface::get_code_size
size_t EOSHostContext::get_code_size(const address &addr) const noexcept{
  /// TODO convert address to eosio::checksum160
  eth_addr _addr;
  test_contract::tb_account_code _account_code(_contract->get_self(), _contract->get_self().value);
  auto by_eth_account_code_index = _account_code.get_index<name("byeth")>();
  auto itr_eth_code = by_eth_account_code_index.find(_addr);
  assert_b(itr_eth_code != by_eth_account_code_index.end(), "no such address");
  auto bytecode = itr_eth_code->bytecode;
  return bytecode.size();
};

/// @copydoc evmc_host_interface::get_code_hash
bytes32 EOSHostContext::get_code_hash(const address &addr) const noexcept{
  eth_addr _addr;
  test_contract::tb_account_code _account_code(_contract->get_self(), _contract->get_self().value);
  auto by_eth_account_code_index = _account_code.get_index<name("byeth")>();
  auto itr_eth_code = by_eth_account_code_index.find(_addr);
  assert_b(itr_eth_code != by_eth_account_code_index.end(), "no such address");
  auto code = itr_eth_code->bytecode;
  /// code to hex string then sha256
//  eosio::checksum256 hash_val = eosio::sha256(salt.c_str(), 32);

  /// convert eosio::checksum256 to evmc::byte32
  evmc::bytes32 hash;
  return hash;
};

/// @copydoc evmc_host_interface::copy_code
size_t EOSHostContext::copy_code(const address &addr,
				 size_t code_offset,
				 uint8_t *buffer_data,
				 size_t buffer_size) const noexcept{
	return 0;
};

/// @copydoc evmc_host_interface::selfdestruct
void EOSHostContext::selfdestruct(const address &addr, const address &beneficiary) noexcept{
};

/// @copydoc evmc_host_interface::call
//result EOSHostContext::call(const evmc_message &msg) noexcept{
//  evmc_status_code status;
//  result res{status};
//  return null;
//};

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
bytes32 EOSHostContext::get_block_hash(int64_t block_number) const noexcept{
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

void EOSHostContext::assert_b(bool test, const char *msg) const{
  eosio::internal_use_do_not_use::eosio_assert(static_cast<uint32_t>(test), msg);
}
