#include <eosio/eosio.hpp>
#include <eosio/asset.hpp>
#include <evmc/evmc.h>
using namespace eosio;

CONTRACT test_contract : public contract {
   public:
      using contract::contract;
      typedef std::vector<uint8_t> binary_code;
      typedef eosio::checksum160  eth_addr;

      ACTION check( );
      evmc_address ecrecover(const evmc_uint256be &hash, std::vector<uint8_t> &signature);
      [[eosio::action]]
      void raw(binary_code trx_code, eth_addr sender);
      [[eosio::action]]
      void create(name eos_account, std::string salt);
      [[eosio::action]]
      void transfers(name from);
      [[eosio::action]]
      void withdraw(name eos_account, asset amount);

      using check_action = action_wrapper<"check"_n, &test_contract::check>;
   private:
      struct [[eosio::table("test_contract")]] st_account {
		eth_addr           account_id;
        eosio::checksum256 nonce;
        asset              eosio_balance;
        name               eosio_account;

		eth_addr primary_key() const { return account_id; };
      };

      typedef eosio::multi_index<"account"_n, st_account> tb_account;

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
