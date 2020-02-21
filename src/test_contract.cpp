#include <test_contract.hpp>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <ethash/keccak.hpp>
#include <calculate/add.hpp>

const evmc_address zero_address{{0}};

std::vector<uint8_t> HexToBytes(const std::string &hex) {
  std::vector<uint8_t> bytes;

  for (unsigned int i = 0; i < hex.length(); i += 2) {
	std::string byteString = hex.substr(i, 2);

	uint8_t bin = (uint8_t) strtol(byteString.c_str(), NULL, 16);
	bytes.push_back(bin);
  }
  return bytes;
}

ACTION test_contract::check( ) {
  /* fill in action body */
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
  // hash
  evmc_uint256be hash{{0}};
  std::string hash_str = "92aef1b955b9de564fc50e31a55b470b0c8cdb931f186485d620729fb03d6f2c";
  auto msg_hash = HexToBytes(hash_str);
  for (int i = 0; i < msg_hash.size(); ++i) {
	hash.bytes[i] = msg_hash[i];
  }

  uint8_t version = 0;
  std::string sig("b826808a8c41e00b7c5d71f211f005a84a7b97949d5e765831e1da4e34c9b8295d2a622eee50f25af78241c1cb7cfff11bcf2a13fe65dee1e3b86fd79a4e3ed000");
  std::vector<uint8_t> signature;
  signature = HexToBytes(sig);
  secp256k1_ecdsa_recoverable_signature ecsig;
  if (!secp256k1_ecdsa_recoverable_signature_parse_compact(
	  ctx, &ecsig, (unsigned char *) &signature[0], version)) {
	print("zero address");
  }

  secp256k1_pubkey ecpubkey;
  if (!secp256k1_ecdsa_recover(ctx, &ecpubkey, &ecsig, &msg_hash[0])) {
	print("zero address");
  }
  print(" \necpubkey is : ");
  for (int kI = 0; kI < 64; ++kI) {
	print(ecpubkey.data[kI]);
  }

  size_t pubkeysize = 65;
  unsigned char pubkey[65];
  secp256k1_ec_pubkey_serialize(ctx, pubkey, &pubkeysize, &ecpubkey,
								SECP256K1_EC_UNCOMPRESSED);
  print(" \npubkey is : ");
  for (int kI = 0; kI < 64; ++kI) {
	print(pubkey[kI]);
  }

  assert(pubkey[0] == 4);
  assert(pubkeysize == 65);
  assert(pubkeysize > 1);

  auto pubkeyhash =
	  ethash::keccak256((uint8_t * )(pubkey + 1), pubkeysize - 1);

  evmc_address address;
  std::copy(pubkeyhash.bytes + (sizeof(evmc_uint256be) - sizeof(evmc_address)),
			pubkeyhash.bytes + sizeof(evmc_uint256be), address.bytes);
  print(" \naddress is : ");
  for (int kJ = 0; kJ < 20; ++kJ) {
	print(address.bytes[kJ]);
  }
}

void test_contract::assert_b(bool test, const char *msg) {
  eosio::internal_use_do_not_use::eosio_assert(static_cast<uint32_t>(test), msg);
}

evmc_address test_contract::ecrecover(const evmc_uint256be &hash, std::vector<uint8_t> &signature) {
  uint8_t version = 0;
  if (version > 1) {
	return zero_address;
  }

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
	  ethash::keccak256((uint8_t *) (pubkey + 1), pubkeysize - 1);

  evmc_address address;
  std::copy(pubkeyhash.bytes + (sizeof(evmc_uint256be) - sizeof(evmc_address)),
			pubkeyhash.bytes + sizeof(evmc_uint256be), address.bytes);

  return address;
}

void test_contract::raw(binary_code trx_code, eth_addr sender) {

}

void test_contract::create(name eos_account, std::string salt) {

}

void test_contract::transfer(name from) {

}

void test_contract::withdraw(name eos_account, asset amount) {

}