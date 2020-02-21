#include <eosio/eosio.hpp>
#include <evmc.h>
using namespace eosio;

CONTRACT test_contract : public contract {
   public:
      using contract::contract;

      ACTION check( );
      evmc_address ecrecover(const evmc_uint256be &hash, std::vector<uint8_t> &signature);
      void assert_b(bool test, const char *msg);

      using hi_action = action_wrapper<"hi"_n, &test_contract::hi>;
};
