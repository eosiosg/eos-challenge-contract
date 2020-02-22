#pragma once
#include <eosio/eosio.hpp>
#include <eosio/asset.hpp>
#include <evmc/evmc.h>
#include <eos_mock_host.hpp>
using namespace eosio;

typedef eosio::checksum160  eth_addr;
CONTRACT test_contract : public contract {
   public:
      using contract::contract;
      typedef std::vector<uint8_t> binary_code;

      ACTION check( );
      evmc_address ecrecover(const evmc_uint256be &hash, std::vector<uint8_t> &signature);
      [[eosio::action]]
      void raw();
      [[eosio::action]]
      void create(name eos_account, std::string salt);
      [[eosio::action]]
      void transfers(name from, asset amount);
      [[eosio::action]]
      void withdraw(name eos_account, asset amount);

      using check_action = action_wrapper<"check"_n, &test_contract::check>;

      EOSHostContext eos_mock_context;
   public:
      struct [[eosio::table("test_contract")]] st_account {
		eth_addr           account_id;
        eosio::checksum256 nonce;
        asset              eosio_balance;
        name               eosio_account;

		eth_addr primary_key() const { return account_id; };
		name by_eos() const { return eosio_account; };
      };

      typedef eosio::multi_index<"account"_n, st_account,
		  		indexed_by<name("eosio_account"), const_mem_fun<st_account, uint64_t, &st_account::by_eos>>
	  > tb_account;

      struct [[eosio::table("test_contract")]] st_account_state {
        eosio::checksum256 key;
        eosio::checksum256 value;

        eosio::checksum256 primary_key() const { return key; };
      };

      typedef eosio::multi_index<"accountstate"_n, st_account_state> tb_account_state;

      struct [[eosio::table("test_contract")]] st_account_code {
		eth_addr account_id;
        std::vector<uint8_t> bytecode;

		eth_addr primary_key() const { return account_id; };
      };

      typedef eosio::multi_index<"accountcode"_n, st_account_code> tb_account_code;

      void assert_b(bool test, const char *msg);

};
