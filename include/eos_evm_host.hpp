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
	/// EOS EVM Host implementation.
	class EOSHostContext : public Host {
	public:
		/// contract
		EOSHostContext(eos_evm &contract, address origin) : _contract(contract) {
			tx_context.tx_gas_price = GAS_PRICE_FORCED;
			tx_context.tx_origin = origin;
			tx_context.block_coinbase = evmc_address({1});
			tx_context.block_number = eosio::tapos_block_num();
			tx_context.block_timestamp = eosio::current_time_point().sec_since_epoch();
			tx_context.block_gas_limit = BLOCK_GAS_LIMIT;
			tx_context.block_difficulty = evmc_uint256be({1});
			tx_context.chain_id = evmc_uint256be({1});
		};
		eos_evm &_contract;
		address tx_origin;

		evmc_tx_context tx_context{};
		/// The block header hash value to be returned by get_block_hash().
		bytes32 block_hash = {};

		/// eth emit logs
		std::vector <eos_evm::eth_log> eth_emit_logs = {};

		storage_records storage_history_records;

		evmc_result create_contract(const address &eth_contract_addr, const evmc_message &message) {
			eosio::check(message.kind == EVMC_CREATE || message.kind == EVMC_CREATE2, "message kind must be create or create2");
			eosio::check(message.input_size > 0, "message input size must be > 0");

			eth_addr_160 eth_contract_160 = evmc_address_to_eth_addr_160(eth_contract_addr);
			eth_addr_256 eth_contract_256 = evmc_address_to_eth_addr_256(eth_contract_addr);
			evmc_message msg = message;
			std::vector <uint8_t> code;
			evmc_result result;
			if (!get_code_size(eth_contract_addr)) {
				std::vector <uint8_t> create_code = std::vector<uint8_t>(msg.input_data,
				                                                         msg.input_data + msg.input_size);
				msg.destination = eth_contract_addr;

				/// add account to table
				eos_evm::tb_account _account(_contract.get_self(), _contract.get_self().value);
				auto by_eth_account_index = _account.get_index<eosio::name("byeth")>();
				auto itr_eth_addr = by_eth_account_index.find(eth_contract_256);
				if (itr_eth_addr == by_eth_account_index.end()) {
					eos_evm::tb_token_contract _token_contract(_contract.get_self(), _contract.get_self().value);
					_account.emplace(_contract.get_self(), [&](auto &the_account) {
						the_account.id = _account.available_primary_key();
						the_account.eth_address = eth_contract_160;
						the_account.nonce = INIT_NONCE_PLUS_ONE;
						the_account.balance = INIT_BALANCE;
						the_account.eosio_account = name();
					});
				}

				/// execute create code
				result = vm_execute(create_code, msg);
				eosio::check(result.output_size, "contract can not be empty");
				/// get raw evm code from result output
				std::vector <uint8_t> raw_evm_code;
				std::copy_n(result.output_data, result.output_size, std::back_inserter(raw_evm_code));

				if (result.status_code == EVMC_SUCCESS) {
					/// add code to table
					eos_evm::tb_account_code _account_code(_contract.get_self(), _contract.get_self().value);
					auto by_eth_account_code_index = _account_code.get_index<eosio::name("byeth")>();
					auto itr_eth_code = by_eth_account_code_index.find(eth_contract_256);
					if (itr_eth_code != by_eth_account_code_index.end()) {
						result.status_code = EVMC_FAILURE;
					} else {
						_account_code.emplace(_contract.get_self(), [&](auto &the_account_code) {
							the_account_code.id = _account_code.available_primary_key();
							the_account_code.eth_address = eth_contract_160;
							the_account_code.bytecode = raw_evm_code;
						});
					}
					result.create_address = eth_contract_addr;
				}
				if (result.status_code != EVMC_SUCCESS){
					/// when result is not success, failed evm trx still needs to be recorded in eos trx,
					/// which must success with no dirty data. Delete dirty address created before.
					itr_eth_addr = by_eth_account_index.find(eth_contract_256);
					eos_evm::tb_account_state _account_state(_contract.get_self(), itr_eth_addr->id);
					auto itr_eth_addr_state = _account_state.begin();
					while (itr_eth_addr_state != _account_state.end()) {
						itr_eth_addr_state = _account_state.erase(itr_eth_addr_state);
					}

					if (itr_eth_addr != by_eth_account_index.end()){
						by_eth_account_index.erase(itr_eth_addr);
					}
				}
			}
			return result;
		}

		/// create contract address
		address create_address(const address &sender, const intx::uint256 &nonce) {
			RLPBuilder rlp_builder;
			rlp_builder.start_list();
			rlp_builder.add(nonce);
			rlp_builder.add(&sender.bytes[0], sizeof(address));
			std::vector <uint8_t> eth_rlp = rlp_builder.build();

			auto eth = ethash::keccak256(eth_rlp.data(), eth_rlp.size());

			address contract_address;
			std::copy_n(&eth.bytes[0] + PADDING, 20, &contract_address.bytes[0]);

			return contract_address;
		}

		/// create contract address2
		address create_address2(const evmc_message &msg) {
			///keccak256( 0xff ++ address ++ salt ++ keccak256(init_code))[12:]
			std::vector<uint8_t> contract_address2_seed;
			std::vector<uint8_t> ff{0xff};
			std::vector<uint8_t> sender_v(sizeof(evmc::address));
			std::copy_n(&msg.sender.bytes[0], sizeof(evmc::address), sender_v.data());
			std::vector<uint8_t> create2_salt_v(sizeof(evmc::address));
			auto int256_salt = intx::be::load<intx::uint256>(msg.create2_salt);
			toBigEndian(int256_salt, create2_salt_v);

			std::vector<uint8_t> init_code_hash_v;
			std::vector<uint8_t> init_code(msg.input_data, msg.input_data + msg.input_size);
			auto init_code_hash = ethash::keccak256(init_code.data(), init_code.size());
			std::copy_n(&init_code_hash.bytes[0], sizeof(init_code_hash), init_code_hash_v.data());

			contract_address2_seed.insert(contract_address2_seed.end(), ff.begin(), ff.end());
			contract_address2_seed.insert(contract_address2_seed.end(), sender_v.begin(), sender_v.end());
			contract_address2_seed.insert(contract_address2_seed.end(), create2_salt_v.begin(), create2_salt_v.end());
			contract_address2_seed.insert(contract_address2_seed.end(), init_code_hash_v.begin(), init_code_hash_v.end());

			auto eth = ethash::keccak256(contract_address2_seed.data(), contract_address2_seed.size());

			address contract_address;
			std::copy_n(&eth.bytes[0] + PADDING, sizeof(evmc::address), &contract_address.bytes[0]);

			return contract_address;
		}

		void transfer(const evmc_message &message, evmc_result &result) {
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
				eos_evm::tb_account _account(_contract.get_self(), _contract.get_self().value);
				auto by_eth_account_index = _account.get_index<eosio::name("byeth")>();
				auto itr_sender = by_eth_account_index.find(evmc_address_to_eth_addr_256(message.sender));
				/// sub sender balance
				auto transfer_amount_256 = intx::be::unsafe::load<intx::uint256>(&transfer_value.bytes[0]);
				_account.modify(*itr_sender, eosio::same_payer, [&](auto &the_account) {
					intx::uint256 old_balance = intx::be::unsafe::load<intx::uint256>(
							the_account.balance.extract_as_byte_array().data());
					intx::uint256 new_balance = old_balance - transfer_amount_256;
					the_account.balance = intx_uint256_to_uint256_t(new_balance);
				});
				auto itr_dest = by_eth_account_index.find(evmc_address_to_eth_addr_256(message.destination));
				/// add destination balance
				if (itr_dest == by_eth_account_index.end()) {
					_account.emplace(_contract.get_self(), [&](auto &the_account) {
						the_account.id = _account.available_primary_key();
						the_account.eth_address = evmc_address_to_eth_addr_160(message.destination);
						the_account.nonce = INIT_NONCE;
						/// add balance
						intx::uint256 balance = transfer_amount_256;
						the_account.balance = intx_uint256_to_uint256_t(balance);
						the_account.eosio_account = name();
					});
				} else {
					_account.modify(*itr_dest, eosio::same_payer, [&](auto &the_account) {
						intx::uint256 old_balance = intx::be::unsafe::load<intx::uint256>(
								the_account.balance.extract_as_byte_array().data());
						intx::uint256 new_balance = old_balance + transfer_amount_256;
						the_account.balance = intx_uint256_to_uint256_t(new_balance);
					});
				}
				result.status_code = EVMC_SUCCESS;
			}
		}

		evmc_result vm_execute(std::vector <uint8_t> &code, const evmc_message &msg) {
			evmc_revision rev = EVMC_ISTANBUL;
			auto vm = evmc_create_evmone();
			evmc_result result = vm->execute(vm, &get_interface(), this->to_context(), rev, &msg, code.data(),
			                                 code.size());
			return result;
		}

	protected:

		/// Returns true if an account exists (EVMC Host method).
		bool account_exists(const address &addr) const noexcept override {
			eth_addr_256 _addr = evmc_address_to_eth_addr_256(addr);
			eos_evm::tb_account _account(_contract.get_self(), _contract.get_self().value);
			auto by_eth_account_index = _account.get_index<eosio::name("byeth")>();
			auto itr_eth_addr = by_eth_account_index.find(_addr);
			return itr_eth_addr != by_eth_account_index.end();
		}

		/// Get the account's storage value at the given key (EVMC Host method).
		bytes32 get_storage(const address &addr, const bytes32 &key) const noexcept override {
			eth_addr_256 _addr = evmc_address_to_eth_addr_256(addr);
			eos_evm::tb_account _account(_contract.get_self(), _contract.get_self().value);
			auto by_eth_account_index = _account.get_index<eosio::name("byeth")>();
			auto itr_eth_addr = by_eth_account_index.find(_addr);
			if (itr_eth_addr == by_eth_account_index.end()) return {};

			eos_evm::tb_account_state _account_state(_contract.get_self(), itr_eth_addr->id);
			auto by_eth_account_state_index = _account_state.get_index<eosio::name("bystatekey")>();
			/// key to checksum256
			std::array<uint8_t, 32> key_array;
			std::copy_n(&key.bytes[0], sizeof(bytes32), key_array.begin());
			uint256_t key_eosio = eosio::fixed_bytes<32>(key_array);
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

		void record_set_storage_history (const address &addr,
				const bytes32 &key,
				const bytes32 &value,
				const evmc_storage_status &status,
				const bool &dirty = false) {
			if (storage_history_records.find(addr) == storage_history_records.end()) {
				std::map<bytes32, std::tuple<bytes32, evmc_storage_status, bool>> storage_history_entry;
				storage_history_entry[key] = std::make_tuple(value, status, dirty);
				storage_history_records[addr] = storage_history_entry;
			} else {
				storage_history_records[addr][key] = std::make_tuple(value, status, dirty);
			}
		}
		/// Set the account's storage value (EVMC Host method).
		evmc_storage_status set_storage(const address &addr,
		                                const bytes32 &key,
		                                const bytes32 &value) noexcept override {
			evmc_storage_status status{};
			/// record storage_history for revert and dirty flag
			record_set_storage_history(addr, key, value, status, false);

			/// copy address to _addr(eth_addr_256)
			eth_addr_256 _addr = evmc_address_to_eth_addr_256(addr);
			eos_evm::tb_account _account(_contract.get_self(), _contract.get_self().value);
			auto by_eth_account_index = _account.get_index<eosio::name("byeth")>();

			auto itr_eth_addr = by_eth_account_index.find(_addr);
			if (itr_eth_addr == by_eth_account_index.end())
				return EVMC_STORAGE_UNCHANGED;

			eos_evm::tb_account_state _account_state(_contract.get_self(), itr_eth_addr->id);
			auto by_eth_account_state_index = _account_state.get_index<eosio::name("bystatekey")>();
			/// key to checksum256
			std::array<uint8_t, 32> key_array;
			std::copy(&key.bytes[0], &key.bytes[0] + sizeof(bytes32), key_array.begin());
			uint256_t key_eosio = eosio::fixed_bytes<32>(key_array);
			auto itr_old = by_eth_account_state_index.find(key_eosio);
			/// value to checksum256
			std::array<uint8_t, 32> new_value_array;
			std::copy(&value.bytes[0], &value.bytes[0] + sizeof(bytes32), new_value_array.begin());
			uint256_t new_value = eosio::fixed_bytes<32>(new_value_array);

			auto dirty = std::get<2>(storage_history_records[addr][key]);
			if (!dirty) {
				/// set dirty = true;
				std::get<2>(storage_history_records[addr][key]) = true;
				if (itr_old == by_eth_account_state_index.end() && new_value_array != ZERO_IN_BYTES) {
					_account_state.emplace(_contract.get_self(), [&](auto &the_state) {
						the_state.id = _account_state.available_primary_key();
						the_state.key = key_eosio;
						the_state.value = new_value;
					});
					status = EVMC_STORAGE_ADDED;
				} else {
					auto old_value = itr_old->value;
					if (old_value == new_value) {
						status = EVMC_STORAGE_UNCHANGED;
					} else if (new_value_array != ZERO_IN_BYTES) {
						_account_state.modify(*itr_old, eosio::same_payer, [&](auto &the_state) {
							the_state.value = new_value;
						});
						status = EVMC_STORAGE_MODIFIED;
					} else {
						by_eth_account_state_index.erase(itr_old);
						status = EVMC_STORAGE_DELETED;
					}
				}
			} else {
				if (new_value_array != ZERO_IN_BYTES) {
					_account_state.modify(*itr_old, eosio::same_payer, [&](auto &the_state) {
						the_state.value = new_value;
					});
					status = EVMC_STORAGE_MODIFIED_AGAIN;
				}
			}
			std::get<1>(storage_history_records[addr][key]) = status;
			return status;
		}

		/// Get the account's balance (EVMC Host method).
		uint256be get_balance(const address &addr) const noexcept override {
			eth_addr_256 _addr = evmc_address_to_eth_addr_256(addr);

			eos_evm::tb_account _account(_contract.get_self(), _contract.get_self().value);
			auto by_eth_account_index = _account.get_index<eosio::name("byeth")>();

			auto itr_eth_addr = by_eth_account_index.find(_addr);
			if (itr_eth_addr == by_eth_account_index.end()) {
				return {};
			}
			auto balance_eosio = itr_eth_addr->balance;

			eos_evm::tb_token_contract _token_contract(_contract.get_self(), _contract.get_self().value);
			eosio::check(_token_contract.begin() != _token_contract.end(), "must link token contract first");
			auto itr_token_contract = _token_contract.begin();
			auto sym_precision = itr_token_contract->contract.get_symbol().precision();

			return eth_addr_256_to_evmc_uint256(balance_eosio);
		}

		/// Get the account's code size (EVMC host method).
		size_t get_code_size(const address &addr) const noexcept override {
			eth_addr_256 _addr = evmc_address_to_eth_addr_256(addr);
			eos_evm::tb_account_code _account_code(_contract.get_self(), _contract.get_self().value);
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
			eth_addr_256 _addr = evmc_address_to_eth_addr_256(addr);
			eos_evm::tb_account_code _account_code(_contract.get_self(), _contract.get_self().value);
			auto by_eth_account_code_index = _account_code.get_index<eosio::name("byeth")>();
			auto itr_eth_code = by_eth_account_code_index.find(_addr);
			if (itr_eth_code == by_eth_account_code_index.end()) {
				return {};
			} else {
				auto code = itr_eth_code->bytecode;
				eosio::checksum256 code_hash = eosio::sha256((const char *) code.data(), (uint32_t) code.size());
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
			eth_addr_256 _addr = evmc_address_to_eth_addr_256(addr);
			eos_evm::tb_account_code _account_code(_contract.get_self(), _contract.get_self().value);
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
			eth_addr_256 _addr = evmc_address_to_eth_addr_256(addr);
			eos_evm::tb_account _account(_contract.get_self(), _contract.get_self().value);
			auto by_eth_account_index = _account.get_index<eosio::name("byeth")>();
			auto itr_eth_suicide = by_eth_account_index.find(_addr);
			/// 1. remove account state record
			eos_evm::tb_account_state _account_state(_contract.get_self(), itr_eth_suicide->id);
			auto itr_eth_suicide_state = _account_state.begin();
			while (itr_eth_suicide_state != _account_state.end()) {
				itr_eth_suicide_state = _account_state.erase(itr_eth_suicide_state);
			}
			/// 2. transfer balance to beneficiary
			auto remain_balance = intx::be::unsafe::load<intx::uint256>(itr_eth_suicide->balance.extract_as_byte_array().data());
			eth_addr_256 eth_address_beneficiary = evmc_address_to_eth_addr_256(beneficiary);
			auto itr_eth_beneficiary = by_eth_account_index.find(eth_address_beneficiary);

			if (itr_eth_beneficiary != by_eth_account_index.end()) {
				/// update account table token balance
				_account.modify(*itr_eth_beneficiary, _contract.get_self(), [&](auto &the_account) {
					intx::uint256 old_balance = intx::be::unsafe::load<intx::uint256>(
							the_account.balance.extract_as_byte_array().data());
					intx::uint256 new_balance = old_balance + remain_balance;
					the_account.balance = intx_uint256_to_uint256_t(new_balance);
				});
			} else {
				/// create beneficiary
				_account.emplace(_contract.get_self(), [&](auto &the_account) {
					the_account.id = _account.available_primary_key();
					the_account.eth_address = evmc_address_to_eth_addr_160(beneficiary);
					the_account.nonce = INIT_NONCE;
					the_account.balance = intx_uint256_to_uint256_t(remain_balance);
					the_account.eosio_account = name();
				});
			}

			/// 3. remove account table record
			if (itr_eth_suicide != by_eth_account_index.end()) {
				by_eth_account_index.erase(itr_eth_suicide);
			}
			/// 4. remove account code table record
			eos_evm::tb_account_code _account_code(_contract.get_self(), _contract.get_self().value);
			auto by_eth_account_code_index = _account_code.get_index<eosio::name("byeth")>();
			auto itr_eth_code = by_eth_account_code_index.find(_addr);
			if (itr_eth_code != by_eth_account_code_index.end()) {
				by_eth_account_code_index.erase(itr_eth_code);
			}
		}

		/// Call/create other contract (EVMC host method).
		result call(const evmc_message &msg) noexcept override {
			eosio::check(msg.depth > 0, "call depth should > 0");
			evmc_result _result;
			_result.output_data = nullptr;
			_result.output_size = 0;
			_result.create_address = {0};
			_result.release = nullptr;
			if (msg.kind == EVMC_CREATE || msg.kind == EVMC_CREATE2) {
				/// get nonce
				auto nonce = _contract.get_nonce(msg);
				/// create contract address
				auto eth_contract_addr = msg.kind == EVMC_CREATE ? create_address(msg.sender, nonce) : create_address2(msg);
				/// set contract
				_result = create_contract(eth_contract_addr, msg);
			} else {
				auto code = _contract.get_eth_code(evmc_address_to_eth_addr_256(msg.destination));
				_result = vm_execute(code, msg);
				if (_result.status_code == EVMC_SUCCESS) {
					/// transfer value
					auto transfer_val = intx::be::load<intx::uint256>(msg.value);
					/// transfer asset
					if (transfer_val > 0) {
						transfer(msg, _result);
					}
				} else {
					_result.status_code = EVMC_FAILURE;
				}
			}
			_contract.increase_nonce(msg);

			return result(_result);
		}

		/// Get transaction context (EVMC host method).
		evmc_tx_context get_tx_context() const noexcept override {
			return tx_context;
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
		}
	};
}  // namespace evmc


