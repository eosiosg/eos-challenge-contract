#pragma once
#include <eosio/eosio.hpp>
#include <eosio/asset.hpp>
#include <eosio/crypto.hpp>
#include <evmc/evmc.h>
#include <eos_mock_host.hpp>
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
		void rawtest();
		[[eosio::action]]
		void raw(binary_code trx_code, eosio::checksum160 sender);
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

};

