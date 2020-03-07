#pragma once
#include <eosio/eosio.hpp>
#include <eosio/asset.hpp>
#include <eosio/crypto.hpp>
#include <evmc/evmc.h>
#include <evmc/evmc.hpp>
#include <rlp.hpp>
#include <ecc/uECC.h>
#include <evmc/mocked_host.hpp>
#include <utils.hpp>
#include <evmc_status_code.hpp>
#include <eosio/binary_extension.hpp>

using namespace eosio;

class [[eosio::contract("eos_evm")]] eos_evm : public contract {
	public:
		using contract::contract;

		explicit eos_evm(eosio::name receiver, eosio::name code,  datastream<const char*> ds);

		[[eosio::action]]
		void rawtest(hex_code hexcode);
		[[eosio::action]]
		void verifysig(hex_code trx_code);
		[[eosio::action]]
		void rawtrxexe(hex_code trx_param, eth_addr_160 eth_address, eth_addr_160 sender);
		[[eosio::action]]
		void raw(const hex_code &trx_code, const binary_extension<eth_addr_160> &sender);
		[[eosio::action]]
		void create(name eos_account, std::string salt);
		[[eosio::action]]
		void updateeth(eth_addr_160 eth_address, name eos_account);
		[[eosio::action]]
		void transfers(name from, asset amount);
		[[eosio::action]]
		void withdraw(name eos_account, asset amount);
		[[eosio::action]]
		void setcode(eth_addr_160 eth_address, hex_code evm_code);

	public:
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

			bool is_r_s_zero() {return r_v.empty() || s_v.empty();};
		};

		struct [[eosio::table("eos_evm")]] st_account {
			uint64_t           id;
			eth_addr_160       eth_address;
			uint64_t           nonce;
			asset              eosio_balance;
			name               eosio_account;

			uint64_t primary_key() const { return id; };
			eth_addr_256 by_eth() const { return eth_addr_160_to_eth_addr_256(eth_address); };
			uint64_t by_eos() const { return eosio_account.value; };
		};

		typedef eosio::multi_index<"account"_n, st_account,
			indexed_by<"byeth"_n, const_mem_fun<st_account, eth_addr_256, &st_account::by_eth>>,
			indexed_by<"byeos"_n, const_mem_fun<st_account, uint64_t, &st_account::by_eos>>
			> tb_account;

		struct [[eosio::table("eos_evm")]] st_account_state {
		    uint64_t           id;
			eosio::checksum256 key;
			eosio::checksum256 value;

			uint64_t primary_key() const { return id; };
		};

		typedef eosio::multi_index<"accountstate"_n, st_account_state> tb_account_state;

		struct [[eosio::table("eos_evm")]] st_account_storage {
			uint64_t             id;
			eosio::checksum256   storage_key;
			eosio::checksum256   storage_val;

			uint64_t primary_key() const { return id; };
			eosio::checksum256 by_storage_key() const { return storage_key; };
		};

		typedef eosio::multi_index<"accountstore"_n, st_account_storage,
			indexed_by<"bystorekey"_n, const_mem_fun<st_account_storage, eosio::checksum256, &st_account_storage::by_storage_key>>
		> tb_account_storage;

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

		struct [[eosio::table("eos_evm")]] st_global_nonce {
			uint64_t nonce;

			uint64_t primary_key() const { return 0; };
		};

		typedef eosio::multi_index<"globalnonce"_n, st_global_nonce> tb_global_nonce;

		tb_account _account;
		tb_account_code _account_code;
		tb_global_nonce _nonce;
 	private:
		void assert_b(bool test, const char *msg);
		uint64_t get_nonce();
		/// address recover
		evmc_address ecrecover(const evmc_uint256be &hash, const uint8_t version, const evmc_uint256be r, const evmc_uint256be s);
		/// RLP
		std::vector<uint8_t> next_part(RLPParser &parser, const char *label);
		rlp_decode_trx RLPDecodeTrx(const hex_code &trx_code);
		std::vector<uint8_t> RLPEncodeTrx(const rlp_decode_trx &trx);
		/// keccak hash
		evmc_uint256be gen_unsigned_trx_hash(std::vector<uint8_t> unsigned_trx);
		/// get code
		std::vector<uint8_t> get_eth_code(eth_addr_256 eth_address);
		/// vm execute
		evmc_result vm_execute(std::vector<uint8_t> &code, eos_evm::rlp_decode_trx &trx, evmc_address &sender);
		/// print receipt
		void print_vm_receipt(evmc_result result, eos_evm::rlp_decode_trx &trx, evmc_address &sender);
	};


