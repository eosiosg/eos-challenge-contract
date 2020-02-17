#include <test_contract.hpp>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <ethash/keccak.hpp>

const evmc_address zero_address{{0}};

ACTION test_contract::hi( name nm ) {
   /* fill in action body */
   print_f("Name : %\n",nm);
}

ACTION test_contract::check(eosio::checksum256 &hash, const uint8_t version, const eosio::checksum256 r, const eosio::checksum256 s) {
  hash.print();
  //evmc_address res = ecrecover(hash, version, r, s);
}

evmc_address test_contract::ecrecover2(const evmc_uint256be hash, const uint8_t version, const evmc_uint256be r, const evmc_uint256be s){
  if (version > 1) {
	return zero_address;
  }

  std::vector<uint8_t> signature;
  std::copy(r.bytes, r.bytes + sizeof(evmc_uint256be),
			std::back_inserter(signature));
  std::copy(s.bytes, s.bytes + sizeof(evmc_uint256be),
			std::back_inserter(signature));

  static secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
  secp256k1_ecdsa_recoverable_signature ecsig;
  if (!secp256k1_ecdsa_recoverable_signature_parse_compact(
	  ctx, &ecsig, (unsigned char *) &signature[0], version)) {
	return zero_address;
  }

  secp256k1_pubkey ecpubkey;
  if (!secp256k1_ecdsa_recover(ctx, &ecpubkey, &ecsig, hash.bytes)) {
	return zero_address;
  }
  size_t pubkeysize = 65;
  unsigned char pubkey[65];
  secp256k1_ec_pubkey_serialize(ctx, pubkey, &pubkeysize, &ecpubkey,
								SECP256K1_EC_UNCOMPRESSED);

  assert(pubkey[0] == 4);
  assert(pubkeysize == 65);
  assert(pubkeysize > 1);
  // skip the version byte at [0]
  auto pubkeyhash =
	  ethash::keccak256((uint8_t * )(pubkey + 1), pubkeysize - 1);

  evmc_address address;
  std::copy(pubkeyhash.bytes + (sizeof(evmc_uint256be) - sizeof(evmc_address)),
			pubkeyhash.bytes + sizeof(evmc_uint256be), address.bytes);

  return address;
}
