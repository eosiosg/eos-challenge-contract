#pragma once
#include <eosio/eosio.hpp>
#include <eosio/asset.hpp>
#include <eosio/crypto.hpp>
#include <eosio/singleton.hpp>
#include <eosio/binary_extension.hpp>

#include <evmone/execution.hpp>
#include <evmone/evmone.h>
#include <evmc_status_code.hpp>
#include <evmc/evmc.h>
#include <evmc/evmc.hpp>

#include <rlp.hpp>
#include <ecc/uECC.h>
#include <utils.hpp>

using namespace eosio;

class [[eosio::contract("eos_evm")]] eos_evm : public contract {
	public:
		using contract::contract;

		explicit eos_evm(eosio::name receiver, eosio::name code,  datastream<const char*> ds);

		[[eosio::action]]
		void raw(const hex_code &trx_code, const binary_extension<eth_addr_160> &sender);
		[[eosio::action]]
		void create(name eos_account, const binary_extension<std::string> eth_address);
		[[eosio::on_notify("*::transfer")]]
		void transfers(const name &from, const name &to, const asset &quantity, const std::string memo);
		[[eosio::action]]
		void withdraw(name eos_account, asset amount);
		[[eosio::action]]
		void linktoken(const extended_symbol &contract);

	public:

		enum account_type {
			CREATE_ETH_PURE_ADDRESS,
			CREATE_EOS_ASSOCIATE_ADDRESS
		};

		enum raw_verify_sig_type {
			ETH_SIG_VERIFY,
			EOS_SIG_VERIFY
		};

		struct rlp_decode_trx {
			std::vector<uint8_t> nonce_v;
			std::vector<uint8_t> gasPrice_v;
			std::vector<uint8_t> gas_v;
			std::vector<uint8_t> to;
			std::vector<uint8_t> value;
			std::vector<uint8_t> data;
			std::vector<uint8_t> v;
			std::vector<uint8_t> r_v;
			std::vector<uint8_t> s_v;

			uint64_t get_chain_id() {
				uint64_t chain_id = uint_from_vector(v, "chain ID");
				return chain_id;
			}

			uint8_t get_actual_v() {
				uint8_t actual_v;
				auto chain_id = get_chain_id();
				eosio::check(chain_id >= 37, "Non-EIP-155 signature V value");

				if (chain_id % 2) {
					actual_v = 0;
					chain_id = (chain_id - 35) / 2;
				} else {
					actual_v = 1;
					chain_id = (chain_id - 36) / 2;
				}
				return actual_v;
			}

			bool is_r_or_s_zero() {return r_v.empty() || s_v.empty();};

			bool is_create_contract() { return to.empty(); };
		};

		struct eth_log {
			evmc_address address;
			std::vector<evmc_uint256be> topics;
			std::vector<uint8_t> data;

			std::string topics_to_string() {
				std::string topics_str;
				for (int i = 0; i < topics.size(); ++i) {
					topics_str += "\"";
					topics_str += BytesToHex(std::vector<uint8_t>(&topics[i].bytes[0], &topics[i].bytes[0] + sizeof(evmc_uint256be)));
					topics_str += "\"";
					if (i != topics.size() - 1) {
						topics_str += ",";
					}
				}
				return topics_str;
			}
		};

		struct [[eosio::table("eos_evm")]] st_account {
			uint64_t           id;
			eth_addr_160       eth_address;
			eosio_uint256      nonce;
			asset              balance;
			name               eosio_account; /// TODO need to change as optional

			uint64_t primary_key() const { return id; };
			eth_addr_256 by_eth() const { return eth_addr_160_to_eth_addr_256(eth_address); };
			uint64_t by_eos() const {
			    if (bool(eosio_account)) {
                    return eosio_account.value;
			    }
			    return 0;
			};
		};

		typedef eosio::multi_index<"account"_n, st_account,
			indexed_by<"byeth"_n, const_mem_fun<st_account, eth_addr_256, &st_account::by_eth>>,
			indexed_by<"byeos"_n, const_mem_fun<st_account, uint64_t, &st_account::by_eos>>
			> tb_account;

		struct [[eosio::table("eos_evm")]] st_account_state {
		    uint64_t           id;
			eosio_uint256      key;
			eosio_uint256      value;

			uint64_t primary_key() const { return id; };
			eosio_uint256 by_state_key() const { return key; };
		};

		typedef eosio::multi_index<"accountstate"_n, st_account_state,
			indexed_by<"bystatekey"_n, const_mem_fun<st_account_state, eosio_uint256, &st_account_state::by_state_key>>
		> tb_account_state;

		struct [[eosio::table("eos_evm")]] st_account_code {
		  	uint64_t             id;
			eth_addr_160         eth_address;
			std::vector<uint8_t> bytecode;

			uint64_t primary_key() const { return id; };
		  	eth_addr_256 by_eth() const { return eth_addr_160_to_eth_addr_256(eth_address); };
		};

		typedef eosio::multi_index<"accountcode"_n, st_account_code,
			indexed_by<"byeth"_n, const_mem_fun<st_account_code, eth_addr_256 , &st_account_code::by_eth>>
			> tb_account_code;

		struct [[eosio::table("eos_evm")]] st_token_contract {
			uint64_t            id;
			extended_symbol     contract;

			uint64_t primary_key() const { return 0; }
		} ;

		typedef eosio::multi_index<"contract"_n, st_token_contract> tb_token_contract;

	public:
		intx::uint256 get_nonce(const evmc_message &msg);
		eosio_uint256 get_init_nonce();
		void set_nonce(const evmc_message &msg);
		/// get code
		std::vector<uint8_t> get_eth_code(eth_addr_256 eth_address);
		/// transfer eosio SYS token
		void transfer_fund(const evmc_message &message, evmc_result &result);
	private:
		/// address recover
		evmc_address ecrecover(const evmc_uint256be &hash, const uint8_t version, const evmc_uint256be r, const evmc_uint256be s);
		/// RLP
		std::vector<uint8_t> next_part(RLPParser &parser, const char *label);
		rlp_decode_trx RLPDecodeTrx(const hex_code &trx_code);
		std::vector<uint8_t> RLPEncodeTrx(const rlp_decode_trx &trx);
		/// keccak hash
		evmc_uint256be gen_unsigned_trx_hash(std::vector<uint8_t> unsigned_trx);

		/// print receipt
		void print_vm_receipt(evmc_result result, eos_evm::rlp_decode_trx &trx, evmc_address &sender);
		/// message construct
		void message_construct(eos_evm::rlp_decode_trx &trx, evmc_message &msg);
	};


