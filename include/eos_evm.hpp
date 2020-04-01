#pragma once
#include <eosio/eosio.hpp>
#include <eosio/asset.hpp>
#include <eosio/crypto.hpp>
#include <eosio/singleton.hpp>
#include <eosio/binary_extension.hpp>
#include <eosio/transaction.hpp>

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
		void simulate(const hex_code &trx_code, const binary_extension<eth_addr_160> &sender);
		[[eosio::action]]
		void create(const name &eos_account, const binary_extension<std::string> &eth_address);
		[[eosio::on_notify("*::transfer")]]
		void ontransfer(const name &from, const name &to, const asset &quantity, const std::string memo);
		[[eosio::action]]
		void withdraw(const name &eos_account, const asset &amount);
		[[eosio::action]]
		void linktoken(const extended_symbol &contract);
		[[eosio::action]]
		void log(const std::string &status_code,
				 const std::string &output,
				 const std::string &from,
				 const std::string &to,
				 const std::string &nonce,
				 const std::string &gas_price,
				 const std::string &gas_left,
				 const std::string &gas_usage,
				 const std::string &value,
				 const std::string &data,
				 const std::string &v,
				 const std::string &r,
				 const std::string &s,
				 const std::string &contract,
				 const std::string &eth_emit_logs
				);
		[[eosio::action]]
		void getblocknum() {
			print(" \n", eosio::tapos_block_num());
			print(" \n", eosio::tapos_block_prefix());
		}

		[[eosio::action]]
		void rawtest(std::string address, std::string &caller, hex_code &code, std::string &data, std::string &gas, std::string &gasPrice, std::string &origin, std::string &value);

	public:

		enum account_type {
			CREATE_ETH_PURE_ADDRESS,
			CREATE_EOS_ASSOCIATE_ADDRESS
		};

		enum raw_verify_sig_type {
			ETH_SIG_VERIFY_TYPE,
			EOS_SIG_VERIFY_TYPE
		};

		struct rlp_decoded_trx {
			std::vector<uint8_t> nonce_v;
			std::vector<uint8_t> gasPrice_v;
			std::vector<uint8_t> gas_v;
			std::vector<uint8_t> to;
			std::vector<uint8_t> value;
			std::vector<uint8_t> data;
			std::vector<uint8_t> v;
			std::vector<uint8_t> r;
			std::vector<uint8_t> s;

			const std::tuple<uint8_t, uint64_t> get_v_chain_id_EIP155() const {
				uint8_t actual_v;
				uint64_t chain_id;
				auto signature_v = uint_from_vector(v, "signature v");
				eosio::check(signature_v >= 37, "Non-EIP-155 signature V value");

				if (signature_v % 2) {
					actual_v = 0;
					chain_id = (signature_v - 35) / 2;
				} else {
					actual_v = 1;
					chain_id = (signature_v - 36) / 2;
				}
				return std::make_tuple(actual_v, chain_id);
			}

			bool is_r_or_s_zero() {return r.empty() || s.empty();};

			bool is_create_contract() { return to.empty(); };
		};

		struct eth_log {
			evmc_address address;
			std::vector<evmc_uint256be> topics;
			std::vector<uint8_t> data;

			std::string topics_to_string() const;
		};

		struct [[eosio::table("eos_evm")]] st_account {
			uint64_t           id;
			eth_addr_160       eth_address;
			uint256_t          nonce;
			uint256_t          balance;
			name               eosio_account;

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
			uint256_t          key;
			uint256_t          value;

			uint64_t primary_key() const { return id; };
			uint256_t by_state_key() const { return key; };
		};

		typedef eosio::multi_index<"accountstate"_n, st_account_state,
			indexed_by<"bystatekey"_n, const_mem_fun<st_account_state, uint256_t, &st_account_state::by_state_key>>
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

		/// used as singleton, validate in impl
		struct [[eosio::table("eos_evm")]] st_token_contract {
			uint64_t            id;
			extended_symbol     contract;

			uint64_t primary_key() const { return 0; }
		} ;

		typedef eosio::multi_index<"contract"_n, st_token_contract> tb_token_contract;

	public:
		eth_addr_160 create_eth_address(const name &eos_account, std::string &eth_address);
		intx::uint256 get_nonce(const evmc_message &msg);
		void increase_nonce(const evmc_message &msg);
		/// get code
		std::vector<uint8_t> get_eth_code(const eth_addr_256 &eth_address);
		void add_balance(const name& eos_account, const asset& quantity);
		void sub_balance(const name& eos_account, const asset& quantity);
		void add_balance(const evmc::address &address, const intx::uint256 &balance);
		void sub_balance(const evmc::address &address, const intx::uint256 &balance);
	private:
		/// address recover
		evmc_address ecrecover(const evmc_uint256be &hash, const uint8_t version, const evmc_uint256be r, const evmc_uint256be s);
		/// RLP
		std::vector<uint8_t> next_part(RLPParser &parser, const char *label);
		rlp_decoded_trx RLPDecodeTrx(const hex_code &trx_code);
		std::vector<uint8_t> RLPEncodeTrx(const rlp_decoded_trx &trx);
		/// keccak hash
		evmc_uint256be gen_unsigned_trx_hash(const std::vector<uint8_t> &unsigned_trx);

		/// print receipt
		void print_vm_receipt_json(const evmc_result &result,
				const eos_evm::rlp_decoded_trx &trx,
				const evmc_address &sender,
				const uint64_t &gas_used,
				const std::vector<eth_log> &eth_emit_logs);
		/// message construct
		void message_construct(const eos_evm::rlp_decoded_trx &trx, evmc_message &msg);
	};


