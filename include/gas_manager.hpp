//
// Created by Yu Yang Zhang on 3/20/20.
//

#ifndef EOS_EVM_GAS_MANAGER_HPP
#define EOS_EVM_GAS_MANAGER_HPP

#include <eos_evm.hpp>
#include <eos_evm_host.hpp>

class GasManager {

public:
	GasManager(std::shared_ptr <eosio::contract> contract_ptr, eos_evm::rlp_decoded_trx &trx, evmc_message &message)
			: _contract(contract_ptr), _trx(trx), _msg(message), _gas(0), _initial_gas(0) {
		vm_execute_result = {};
	}

	/// buy gas
	void buy_gas() {
		auto gas = uint256_from_vector(_trx.gas_v.data(), _trx.gas_v.size());
		auto gas_price = uint256_from_vector(_trx.gasPrice_v.data(), _trx.gasPrice_v.size());
		if (gas > 0 && gas_price > 0) {
			intx::uint256 msg_gas_value = gas * gas_price;

			/// check balance
			eos_evm::tb_account _account(_contract->get_self(), _contract->get_self().value);
			auto by_eth_account_index = _account.get_index<name("byeth")>();
			eth_addr_256 eth_address_256 = evmc_address_to_eth_addr_256(this->_msg.sender);
			auto itr_eth_addr = by_eth_account_index.find(eth_address_256);
			eosio::check(itr_eth_addr != by_eth_account_index.end(), "no such eth address");
			intx::uint256 sender_balance = intx::be::unsafe::load<intx::uint256>(
					itr_eth_addr->balance.extract_as_byte_array().data());
			eosio::check(sender_balance >= msg_gas_value, "insufficient balance for gas");

			/// sub balance
			sub_balance(this->_msg.sender, msg_gas_value);

			/// add gas
			this->_gas += intx::narrow_cast<uint64_t>(gas);
			this->_initial_gas = intx::narrow_cast<uint64_t>(gas);
		}
	}

	void use_gas(const uint64_t amount) {
		eosio::check(this->_gas >= amount, "out of gas");
		this->_gas -= amount;
	}


	void refund_gas() {
		uint64_t refund = this->gas_used() / 2;
		/// get vm gas left
		auto vm_exe_status = this->vm_execute_result.status_code;
		if (vm_exe_status == EVMC_SUCCESS || vm_exe_status == EVMC_REVERT) {
			auto gas_limit = uint_from_vector(this->_trx.gas_v, "gas");
			if (refund > gas_limit - this->vm_execute_result.gas_left) {
				refund = gas_limit - this->vm_execute_result.gas_left;
			};
			this->_gas += refund;
			auto gas_price = uint256_from_vector(_trx.gasPrice_v.data(), _trx.gasPrice_v.size());
			auto remaining = this->_gas * gas_price;

			if (this->_gas > 0 && gas_price > 0) {
				add_balance(this->_msg.sender, remaining);
			}
		}
	}

	void set_vm_execute_result(const evmc_result &result) {
		this->vm_execute_result = result;
	}

	uint64_t gas_used() {
		return this->_initial_gas - this->_gas;
	}

	void add_balance(const evmc::address &address, const intx::uint256 &balance) {
		eos_evm::tb_account _account(_contract->get_self(), _contract->get_self().value);
		eth_addr_256 eth_address_256 = evmc_address_to_eth_addr_256(this->_msg.sender);
		auto by_eth_account_index = _account.get_index<name("byeth")>();
		auto itr_eth_addr = by_eth_account_index.find(eth_address_256);

		/// update account table token balance
		_account.modify(*itr_eth_addr, _contract->get_self(), [&](auto &the_account) {
			intx::uint256 old_balance = intx::be::unsafe::load<intx::uint256>(
					the_account.balance.extract_as_byte_array().data());
			intx::uint256 new_balance = old_balance + balance;
			the_account.balance = intx_uint256_to_uint256_t(new_balance);
		});
	}

	void sub_balance(const evmc::address &address, const intx::uint256 &balance) {
		eos_evm::tb_account _account(_contract->get_self(), _contract->get_self().value);
		eth_addr_256 eth_address_256 = evmc_address_to_eth_addr_256(this->_msg.sender);
		auto by_eth_account_index = _account.get_index<name("byeth")>();
		auto itr_eth_addr = by_eth_account_index.find(eth_address_256);
		/// check enough balance
		eosio::check(intx::be::unsafe::load<intx::uint256>(itr_eth_addr->balance.extract_as_byte_array().data()) >=
		             balance, "overdrawn balance");

		/// update account table token balance
		_account.modify(*itr_eth_addr, _contract->get_self(), [&](auto &the_account) {
			intx::uint256 old_balance = intx::be::unsafe::load<intx::uint256>(
					the_account.balance.extract_as_byte_array().data());
			intx::uint256 new_balance = old_balance - balance;
			the_account.balance = intx_uint256_to_uint256_t(new_balance);
		});
	}

private:
	eos_evm::rlp_decoded_trx _trx;
	evmc_message _msg;
	std::shared_ptr <eosio::contract> _contract;
	uint64_t _gas;
	uint64_t _initial_gas;
	evmc_result vm_execute_result;
};

#endif //EOS_EVM_GAS_MANAGER_HPP
