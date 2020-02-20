#include <eosio/eosio.hpp>
#include <evmc.h>
using namespace eosio;

CONTRACT test_contract : public contract {
   public:
      using contract::contract;

      ACTION hi( name nm );
      ACTION check(eosio::checksum256 &hash, const uint8_t version, const eosio::checksum256 r, const eosio::checksum256 s);
      evmc_address ecrecover2(const evmc_uint256be hash, const uint8_t version, const evmc_uint256be r, const evmc_uint256be s);
      void assert_b(bool test, const char *msg);

      using hi_action = action_wrapper<"hi"_n, &test_contract::hi>;
};
