#pragma once
#include <eosio/eosio.hpp>
#include <eosio/asset.hpp>
#include <eosio/crypto.hpp>
#include <evmc/evmc.h>
#include <bytecode.hpp>
#include <rlp.hpp>
using namespace eosio;

typedef eosio::checksum256  eth_addr;
typedef std::vector<uint8_t> binary_code;
typedef std::string          hex_code;

class [[eosio::contract("test_contract")]] test_contract : public contract {
	public:
		using contract::contract;

		explicit test_contract(eosio::name receiver, eosio::name code,  datastream<const char*> ds);

		[[eosio::action]]
		void check();
		[[eosio::action]]
		void hexcodegen();
		[[eosio::action]]
		void rawtest(hex_code hexcode);
		[[eosio::action]]
		void verifysig(hex_code trx_code);
		[[eosio::action]]
		void rawtrxexe(hex_code trx_param, eth_addr eth_address);
		[[eosio::action]]
		void raw(hex_code trx_code);
		[[eosio::action]]
		void create(name eos_account, std::string salt);
		[[eosio::action]]
		void transfers(name from, asset amount);
		[[eosio::action]]
		void withdraw(name eos_account, asset amount);
		[[eosio::action]]
		void setcode(eth_addr eth_address, hex_code evm_code);

		using check_action = action_wrapper<"check"_n, &test_contract::check>;

	public:
		struct [[eosio::table("test_contract")]] st_account {
			uint64_t           id;
			eth_addr           eth_address;
			eosio::checksum256 nonce;
			asset              eosio_balance;
			name               eosio_account;

			uint64_t primary_key() const { return id; };
			eth_addr by_eth() const { return eth_address; };
			uint64_t by_eos() const { return eosio_account.value; };
		};

		typedef eosio::multi_index<"account"_n, st_account,
			indexed_by<"byeth"_n, const_mem_fun<st_account, eosio::checksum256, &st_account::by_eth>>,
			indexed_by<"byeos"_n, const_mem_fun<st_account, uint64_t, &st_account::by_eos>>
			> tb_account;

		struct [[eosio::table("test_contract")]] st_account_state {
		    uint64_t           id;
			eosio::checksum256 key;
			eosio::checksum256 value;

			uint64_t primary_key() const { return id; };
		};

		typedef eosio::multi_index<"accountstate"_n, st_account_state> tb_account_state;

		struct [[eosio::table("test_contract")]] st_account_storage {
			uint64_t             id;
			eosio::checksum256   storage_key;
			eosio::checksum256   storage_val;

			uint64_t primary_key() const { return id; };
			eosio::checksum256 by_storage_key() const { return storage_key; };
		};

		typedef eosio::multi_index<"accountstore"_n, st_account_storage,
			indexed_by<"bystorekey"_n, const_mem_fun<st_account_storage, eosio::checksum256, &st_account_storage::by_storage_key>>
		> tb_account_storage;

		struct [[eosio::table("test_contract")]] st_account_code {
		  	uint64_t id;
			eth_addr eth_address;
			std::vector<uint8_t> bytecode;

			uint64_t primary_key() const { return id; };
		  	eth_addr by_eth() const { return eth_address; };
		};

		typedef eosio::multi_index<"accountcode"_n, st_account_code,
			indexed_by<"byeth"_n, const_mem_fun<st_account_code, eosio::checksum256, &st_account_code::by_eth>>
			> tb_account_code;
 	private:
		void assert_b(bool test, const char *msg);
		// RLP encoding related
		std::string encodeBinary(uint64_t n);
		std::string encodeLength(size_t n, unsigned char offset);
		std::string rplEncode(std::string val);
		// address recover
		evmc_address ecrecover(const evmc_uint256be &hash, std::vector<uint8_t> &signature);
		evmc_address ecrecover2(const evmc_uint256be &hash, const uint8_t version, const evmc_uint256be r, const evmc_uint256be s);
		std::vector<uint8_t> next_part(RLPParser &parser, const char *label);
		uint64_t uint_from_vector(std::vector<uint8_t> v, const char *label);
};


