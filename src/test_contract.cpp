#include <test_contract.hpp>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <ethash/keccak.hpp>
#include <calculate/add.hpp>

const evmc_address zero_address{{0}};

ACTION test_contract::hi( name nm ) {
   /* fill in action body */
   print_f("Name : %\n",nm);
   eosio::print(add(10, 20));
   secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
   print_f("Name : %\n",nm);
}

ACTION test_contract::check(eosio::checksum256 &hash, const uint8_t version, const eosio::checksum256 r, const eosio::checksum256 s) {
  //hash.print();
  evmc_uint256be hash_evmc;
  std::copy(hash.get_array().begin(), hash.get_array().end(), hash_evmc.bytes);
  evmc_uint256be r_evmc;
  std::copy(r.get_array().begin(), r.get_array().end(), r_evmc.bytes);
  evmc_uint256be s_evmc;
  std::copy(s.get_array().begin(), s.get_array().end(), s_evmc.bytes);

  eosio::checksum160 addr;
  evmc_address addr_evmc = ecrecover2(hash_evmc, version, r_evmc, s_evmc);
  std::copy(addr_evmc.bytes, addr_evmc.bytes + sizeof(evmc_address), addr.data());
  addr.print();
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
