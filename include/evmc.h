

#include <stdbool.h> /* Definition of bool, true and false. */
#include <stddef.h>  /* Definition of size_t. */
#include <stdint.h>  /* Definition of int64_t, uint64_t. */

#if __cplusplus
extern "C" {
#endif


struct evmc_bytes32
{
    /** The 32 bytes. */
    uint8_t bytes[32];
};

typedef evmc_bytes32 evmc_uint256be;

struct evmc_address
{
    /** The 20 bytes of the hash. */
    uint8_t bytes[20];
};

#if __cplusplus
}
#endif
