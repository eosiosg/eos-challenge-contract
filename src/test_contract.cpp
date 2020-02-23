#include <test_contract.hpp>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <ethash/keccak.hpp>

#include <evmone/execution.hpp>
#include <evmc/evmc.hpp>
#include <evmc/mocked_host.hpp>
#include <evmone/evmone.h>

const evmc_address zero_address{{0}};

test_contract::test_contract(eosio::name receiver, eosio::name code,  datastream<const char*> ds): contract(receiver, code, ds){
}

std::vector<uint8_t> HexToBytes(const std::string &hex) {
	std::vector<uint8_t> bytes;

	for (unsigned int i = 0; i < hex.length(); i += 2) {
		std::string byteString = hex.substr(i, 2);

		uint8_t bin = (uint8_t) strtol(byteString.c_str(), NULL, 16);
		bytes.push_back(bin);
	}
	return bytes;
}

void test_contract::check( ) {
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

void test_contract::rawtest() {
//	EOSHostContext *host = new EOSHostContext(std::make_shared<eosio::contract>(*this));
  	evmc::MockedHost host;
	evmc_revision rev = EVMC_BYZANTIUM;
	evmc_message msg{};

	msg.gas = 2000;
	auto vm = evmc::VM{evmc_create_evmone()};
	std::vector<uint8_t> code = HexToBytes("6007600d0160005260206000f3");
	evmc::result result = vm.execute(host, rev, msg, code.data(), code.size());
	evmc::bytes output;
	output = {result.output_data, result.output_size};

	//print("res size: ", output.size());
	printhex(output.data(), output.size());
}

void test_contract::raw(binary_code trx_code, eosio::checksum160 sender) {
  	//TODO what in the trx_code??
  	// 1. which contract?
  	// 2. transaction signature?
  	// 3. trx_code may be set code... and need to update table
}


void test_contract::create(name eos_account, std::string salt) {
  	require_auth(eos_account);
  	/// TODO just use eosio_account string + salt and rlp
	std::string eos_str = eos_account.to_string();
	std::string combine = eos_str + salt;
	std::string eth_str = rplEncode(combine);

  	auto eth = eosio::ripemd160((const char *)eth_str.c_str(), 20);
	// copy to eosio::sha160 to eosio::sha256
	auto eth_array = eth.extract_as_byte_array();
	eth_addr eth_address = eosio::fixed_bytes<32>(eth_array);

  	tb_account _account(_self, _self.value);
  	auto by_eth_account_index = _account.get_index<name("byeth")>();
  	auto itr_eth_addr = by_eth_account_index.find(eth_address);
  	assert_b(itr_eth_addr == by_eth_account_index.end(), "already have eth address");
	_account.emplace(_self, [&](auto &the_account) {
	  the_account.eth_address = eth_address;
	  the_account.nonce = eosio::sha256(salt.c_str(), 32);
	  the_account.eosio_balance = asset(0, symbol(symbol_code("EOS"), 4));
	  the_account.eosio_account = eos_account;
	});
}

void test_contract::transfers(name from, asset amount) {
	require_auth(from);
	tb_account _account(_self, _self.value);
	auto by_eos_account_index = _account.get_index<name("byeos")>();
	auto itr_eos_from = by_eos_account_index.find(from.value);
	assert_b(itr_eos_from != by_eos_account_index.end(), "no such eosio account");

	action(
			permission_level{from, "active"_n},
			"eosio.token"_n,
			"transfer"_n,
			std::make_tuple(from, _self, amount, std::string(""))
	      ).send();
	// update account table token balance
	_account.modify(*itr_eos_from, _self, [&](auto &the_account) {
	  the_account.eosio_balance += amount;
	});
}

void test_contract::withdraw(name eos_account, asset amount) {
	require_auth(eos_account);
	tb_account _account(_self, _self.value);
	auto by_eos_account_index = _account.get_index<name("byeos")>();
	auto itr_eos_from = by_eos_account_index.find(eos_account.value);
	assert_b(itr_eos_from != by_eos_account_index.end(), "no such eosio account");

	action(
			permission_level{eos_account, "active"_n},
			"eosio.token"_n,
			"transfer"_n,
			std::make_tuple(_self, eos_account, amount, std::string(""))
	      ).send();
	// update account table token balance
	_account.modify(*itr_eos_from, _self, [&](auto &the_account) {
	  the_account.eosio_balance -= amount;
	});
}

void test_contract::setcode(eth_addr eth_address, hex_code evm_code) {
  	// find eos account to check auth
  	tb_account _account(_self, _self.value);
  	auto by_eth_account_index = _account.get_index<name("byeth")>();
  	auto itr_eth_addr = by_eth_account_index.find(eth_address);
  	assert_b(itr_eth_addr != by_eth_account_index.end(), "no such eth account");

  	name eos_account = itr_eth_addr->eosio_account;
  	require_auth(eos_account);

  	// set code and use eos_account ram
    tb_account_code _account_code(_self, _self.value);
    auto by_eth_account_code_index = _account_code.get_index<name("byeth")>();
    auto itr_eth_code = by_eth_account_code_index.find(eth_address);
    if (itr_eth_code == by_eth_account_code_index.end()) {
	  _account_code.emplace(eos_account, [&](auto &the_account_code){
		the_account_code.eth_address = eth_address;
		the_account_code.bytecode = HexToBytes(evm_code);
	  });
	} else {
      _account_code.modify(*itr_eth_code, eos_account, [&](auto &the_account_code){
        the_account_code.bytecode = HexToBytes(evm_code);
      });
    }
}


std::string test_contract::encodeBinary(uint64_t n) {
  std::string rs;

  if (n == 0) {
	// do nothing; return empty string
	return "";
  } else {
	rs.assign(encodeBinary(n / 256));

	unsigned char ch = n % 256;
	rs.append((const char *) &ch, 1);
  }

  return rs;
}

std::string test_contract::encodeLength(size_t n, unsigned char offset){
  std::string rs;
  ///TODO check
//  assert_b(n < 256 ** 8, "n too big");

  if (n < 56) {
	unsigned char ch = n + offset;
	rs.assign((const char *) &ch, 1);
  } else {
	std::string binlen = encodeBinary(n);

	unsigned char ch = binlen.size() + offset + 55;
	rs.assign((const char *) &ch, 1);
	rs.append(binlen);
  }

  return rs;
}

std::string test_contract::rplEncode(std::string val) {
  std::string s;
  const char *p = val.size() ? val.c_str() : nullptr;
  size_t sz = val.size();

  if ((sz == 1) && (p[0] < 0x80))
	s.append((const char *) p, 1);
  else
	s += encodeLength(sz, 0x80) + val;

  return s;
}