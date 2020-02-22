//
// Created by Yu Yang Zhang on 2/21/20.
//

#ifndef TEST_CONTRACT_INCLUDE_EVMC_EOS_MOCK_HOST_HPP_
#define TEST_CONTRACT_INCLUDE_EVMC_EOS_MOCK_HOST_HPP_
#include <evmc/evmc.hpp>
#include <eosio/eosio.hpp>
#include <test_contract.hpp>


class EOSHostContext : public evmc::HostInterface {
 public:
  /// @copydoc evmc_host_interface::account_exists
  virtual bool account_exists(const evmc::address &addr) const noexcept;

  /// @copydoc evmc_host_interface::get_storage
  virtual evmc::bytes32 get_storage(const evmc::address &addr, const evmc::bytes32 &key) const noexcept;

  /// @copydoc evmc_host_interface::set_storage
  virtual evmc_storage_status set_storage(const evmc::address &addr,
										  const evmc::bytes32 &key,
										  const evmc::bytes32 &value) noexcept;

  /// @copydoc evmc_host_interface::get_balance
  virtual evmc::uint256be get_balance(const evmc::address &addr) const noexcept;

  /// @copydoc evmc_host_interface::get_code_size
  virtual size_t get_code_size(const evmc::address &addr) const noexcept;

  /// @copydoc evmc_host_interface::get_code_hash
  virtual evmc::bytes32 get_code_hash(const evmc::address &addr) const noexcept;

  /// @copydoc evmc_host_interface::copy_code
  virtual size_t copy_code(const evmc::address &addr,
						   size_t code_offset,
						   uint8_t *buffer_data,
						   size_t buffer_size) const noexcept;

  /// @copydoc evmc_host_interface::selfdestruct
  virtual void selfdestruct(const evmc::address &addr, const evmc::address &beneficiary) noexcept;

  /// @copydoc evmc_host_interface::call
  virtual evmc::result call(const evmc_message &msg) noexcept;

  /// @copydoc evmc_host_interface::get_tx_context
  virtual evmc_tx_context get_tx_context() const noexcept;

  /// @copydoc evmc_host_interface::get_block_hash
  virtual evmc::bytes32 get_block_hash(int64_t block_number) const noexcept;

  /// @copydoc evmc_host_interface::emit_log
//  virtual void emit_log(const evmc::address &addr,
//						const uint8_t *data,
//						size_t data_size,
//						const evmc::bytes32 topics[],
//						size_t num_topics) noexcept;
};

#endif //TEST_CONTRACT_INCLUDE_EVMC_EOS_MOCK_HOST_HPP_
