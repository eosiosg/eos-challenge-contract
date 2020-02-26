#include <test_contract.hpp>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <ethash/keccak.hpp>

#include <evmone/execution.hpp>
#include <evmc/evmc.hpp>
#include <eos_mock_host.hpp>
#include <evmone/evmone.h>

const evmc_address zero_address{{0}};

test_contract::test_contract(eosio::name receiver, eosio::name code,  datastream<const char*> ds): contract(receiver, code, ds){
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

evmc_address test_contract::ecrecover2(const evmc_uint256be &hash, const uint8_t version, const evmc_uint256be r, const evmc_uint256be s) {
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
	  ethash::keccak256((uint8_t *) (pubkey + 1), pubkeysize - 1);

  evmc_address address;
  std::copy(pubkeyhash.bytes + (sizeof(evmc_uint256be) - sizeof(evmc_address)),
			pubkeyhash.bytes + sizeof(evmc_uint256be), address.bytes);

  return address;
}

void test_contract::hexcodegen() {
    	auto const code = bytecode{} + OP_TIMESTAMP + OP_COINBASE + OP_OR + OP_GASPRICE + OP_OR +
                      OP_NUMBER + OP_OR + OP_DIFFICULTY + OP_OR + OP_GASLIMIT + OP_OR + OP_ORIGIN +
                      OP_OR + OP_CHAINID + OP_OR + ret_top();
	printhex(code.data(), code.size());
}

/// pass hex code to execute in evm
/// auto code = bytecode{} + OP_ADDRESS + OP_BALANCE + mstore(0) + ret(32 - 6, 6); == 30316000526006601af3
/// "30316000526006601af3"  get balance
/// "6007600d0160005260206000f3" execute compute return 0x14
void test_contract::rawtest(hex_code hexcode) {
	evmc::EOSHostContext host = evmc::EOSHostContext(std::make_shared<eosio::contract>(*this));
	evmc_revision rev = EVMC_BYZANTIUM;
	evmc_message msg{};

	msg.gas = 2000;
	auto vm = evmc::VM{evmc_create_evmone()};
	std::vector<uint8_t> code = HexToBytes(hexcode);
	evmc::result result = vm.execute(host, rev, msg, code.data(), code.size());
	evmc::bytes output;
	output = {result.output_data, result.output_size};

	print(" \nres is : ");
	printhex(output.data(), output.size());
}

std::vector<uint8_t> test_contract::next_part(RLPParser &parser, const char *label) {
  assert_b(!parser.at_end(), "Transaction too short");
  return parser.next();
}

uint64_t test_contract::uint_from_vector(std::vector<uint8_t> v, const char *label) {
  assert_b(v.size() <= 8, "uint from vector size too large");

  uint64_t u = 0;
  for (size_t i = 0; i < v.size(); i++) {
	u = u << 8;
	u += v[i];
  }

  return u;
}

void test_contract::verifysig(hex_code trx_code) {
  	std::vector<uint8_t> tx = HexToBytes(trx_code);
  	RLPParser tx_envelope_p = RLPParser(tx);
	std::vector<uint8_t> tx_envelope = tx_envelope_p.next();
	assert_b(!tx_envelope_p.at_end(), "There are more bytes here than one transaction");

	RLPParser tx_parts_p = RLPParser(tx_envelope);

	std::vector<uint8_t> nonce_v = next_part(tx_parts_p, "nonce");
	std::vector<uint8_t> gasPrice_v = next_part(tx_parts_p, "gas price");
	std::vector<uint8_t> gas_v = next_part(tx_parts_p, "start gas");
	std::vector<uint8_t> to = next_part(tx_parts_p, "to address");
	std::vector<uint8_t> value_v = next_part(tx_parts_p, "value");
	std::vector<uint8_t> data = next_part(tx_parts_p, "data");
	std::vector<uint8_t> v = next_part(tx_parts_p, "signature V");
	std::vector<uint8_t> r_v = next_part(tx_parts_p, "signature R");
	std::vector<uint8_t> s_v = next_part(tx_parts_p, "signature S");

	uint64_t nonce = uint_from_vector(nonce_v, "nonce");
	uint64_t gasPrice = uint_from_vector(gasPrice_v, "gas price");
	uint64_t gas = uint_from_vector(gas_v, "start gas");
	uint64_t value = uint_from_vector(value_v, "value");

	assert_b(r_v.size() == sizeof(evmc_uint256be), "signature R invalid length");
	evmc_uint256be r;
	std::copy(r_v.begin(), r_v.end(), r.bytes);

	assert_b(s_v.size() == sizeof(evmc_uint256be), "signature R invalid length");
	evmc_uint256be s;
	std::copy(s_v.begin(), s_v.end(), s.bytes);

	// Figure out non-signed V

	if (v.size() < 1) {
	  return;
	}

	uint64_t chainID = uint_from_vector(v, "chain ID");

	uint8_t actualV;
	assert_b(chainID >= 37, "Non-EIP-155 signature V value");

	if (chainID % 2) {
	  actualV = 0;
	  chainID = (chainID - 35) / 2;
	} else {
	  actualV = 1;
	  chainID = (chainID - 36) / 2;
	}

	// Re-encode RLP

	RLPBuilder unsignedTX_b;
	unsignedTX_b.start_list();

	std::vector<uint8_t> empty;
	unsignedTX_b.add(empty);    // S
	unsignedTX_b.add(empty);    // R
	unsignedTX_b.add(chainID);  // V
	unsignedTX_b.add(data);
	if (value == 0) {
	  // signing hash expects 0x80 here, not 0x00
	  unsignedTX_b.add(empty);
	} else {
	  unsignedTX_b.add(value);
	}
	unsignedTX_b.add(to);
	if (gas == 0) {
	  unsignedTX_b.add(empty);
	} else {
	  unsignedTX_b.add(gas);
	}
	if (gasPrice == 0) {
	  unsignedTX_b.add(empty);
	} else {
	  unsignedTX_b.add(gasPrice);
	}
	if (nonce == 0) {
	  unsignedTX_b.add(empty);
	} else {
	  unsignedTX_b.add(nonce);
	}

	std::vector<uint8_t> unsignedTX = unsignedTX_b.build();

	// Recover Address

	auto unsignedTX_h = ethash::keccak256(unsignedTX.data(), unsignedTX.size());
	evmc_uint256be evmc_usignedTX_h;
	std::copy(&unsignedTX_h.bytes[0], unsignedTX_h.bytes + sizeof(evmc_uint256be),
			  &evmc_usignedTX_h.bytes[0]);
	evmc_address from = ecrecover2(evmc_usignedTX_h, actualV, r, s);
	/// TODO check from address in account table
	std::array<uint8_t, 32> eth_array;
	std::copy_n(&from.bytes[0] + 12, 20, eth_array.begin());
	eth_addr eth_address = eosio::fixed_bytes<32>(eth_array);
	tb_account _account(_self, _self.value);
	auto by_eth_account_index = _account.get_index<name("byeth")>();
	auto itr_eth_addr = by_eth_account_index.find(eth_address);
	assert_b(itr_eth_addr != by_eth_account_index.end(), "invalid signed transaction");
}

/// eg: trx: e42a722b00000000000000000000000000000000000000000000000000000000000000070000000000000000000000000000000000000000000000000000000000000008
///     eth_address: contract address
///     smart contract code: 6080604052600436106049576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063e42a722b14604e578063ef5fb05b1460a2575b600080fd5b348015605957600080fd5b506086600480360381019080803560030b9060200190929190803560030b906020019092919050505060d0565b604051808260030b60030b815260200191505060405180910390f35b34801560ad57600080fd5b5060b460dd565b604051808260030b60030b815260200191505060405180910390f35b6000818301905092915050565b600060149050905600a165627a7a72305820556e7725ce14e3dfb830dceeb656d8cfafb2e1391d84f4a9daaaa057435c69cd0029
void test_contract::rawtrxexe(hex_code trx_param, eth_addr eth_address) {
	evmc::EOSHostContext host = evmc::EOSHostContext(std::make_shared<eosio::contract>(*this));
	evmc_revision rev = EVMC_BYZANTIUM;
	evmc_message msg{};
	msg.kind = EVMC_CALL;
	auto data = HexToBytes(trx_param);
	msg.input_data = data.data();
	msg.input_size = data.size();
	msg.gas = 20000;

	tb_account_code _account_code(_self, _self.value);
	auto by_eth_account_code_index = _account_code.get_index<name("byeth")>();
	auto itr_eth_code = by_eth_account_code_index.find(eth_address);
	assert_b(itr_eth_code != by_eth_account_code_index.end(), "no contract on this account");

	auto vm = evmc::VM{evmc_create_evmone()};
	std::vector<uint8_t> code = itr_eth_code->bytecode;

	evmc::result result = vm.execute(host, rev, msg, code.data(), code.size());
	print(" \ngas left is : ", result.gas_left);
	assert_b(result.status_code == EVMC_SUCCESS, "execute failed");
	evmc::bytes output;
	output = {result.output_data, result.output_size};
	print(" \nres is : ");
	printhex(output.data(), output.size());
}

void test_contract::raw(hex_code trx_code) {
  	//TODO what in the trx_code??
  	// 1. which contract?
  	// 2. transaction signature?
  	// 3. trx_code may be set code... and need to update table
  	std::vector<uint8_t> tx = HexToBytes(trx_code);
	RLPParser tx_envelope_p = RLPParser(tx);
	std::vector<uint8_t> tx_envelope = tx_envelope_p.next();
	assert_b(!tx_envelope_p.at_end(), "There are more bytes here than one transaction");

	RLPParser tx_parts_p = RLPParser(tx_envelope);

	std::vector<uint8_t> nonce_v = next_part(tx_parts_p, "nonce");
	std::vector<uint8_t> gasPrice_v = next_part(tx_parts_p, "gas price");
	std::vector<uint8_t> gas_v = next_part(tx_parts_p, "start gas");
	std::vector<uint8_t> to = next_part(tx_parts_p, "to address");
	std::vector<uint8_t> value_v = next_part(tx_parts_p, "value");
	std::vector<uint8_t> data = next_part(tx_parts_p, "data");
	std::vector<uint8_t> v = next_part(tx_parts_p, "signature V");
	std::vector<uint8_t> r_v = next_part(tx_parts_p, "signature R");
	std::vector<uint8_t> s_v = next_part(tx_parts_p, "signature S");

	uint64_t nonce = uint_from_vector(nonce_v, "nonce");
	uint64_t gasPrice = uint_from_vector(gasPrice_v, "gas price");
	uint64_t gas = uint_from_vector(gas_v, "start gas");
	uint64_t value = uint_from_vector(value_v, "value");

	assert_b(r_v.size() == sizeof(evmc_uint256be), "signature R invalid length");
	evmc_uint256be r;
	std::copy(r_v.begin(), r_v.end(), r.bytes);

	assert_b(s_v.size() == sizeof(evmc_uint256be), "signature R invalid length");
	evmc_uint256be s;
	std::copy(s_v.begin(), s_v.end(), s.bytes);

	// Figure out non-signed V

	if (v.size() < 1) {
	  return;
	}

	uint64_t chainID = uint_from_vector(v, "chain ID");

	uint8_t actualV;
	assert_b(chainID >= 37, "Non-EIP-155 signature V value");

	if (chainID % 2) {
	  actualV = 0;
	  chainID = (chainID - 35) / 2;
	} else {
	  actualV = 1;
	  chainID = (chainID - 36) / 2;
	}

	// Re-encode RLP

	RLPBuilder unsignedTX_b;
	unsignedTX_b.start_list();

	std::vector<uint8_t> empty;
	unsignedTX_b.add(empty);    // S
	unsignedTX_b.add(empty);    // R
	unsignedTX_b.add(chainID);  // V
	unsignedTX_b.add(data);
	if (value == 0) {
	  // signing hash expects 0x80 here, not 0x00
	  unsignedTX_b.add(empty);
	} else {
	  unsignedTX_b.add(value);
	}
	unsignedTX_b.add(to);
	if (gas == 0) {
	  unsignedTX_b.add(empty);
	} else {
	  unsignedTX_b.add(gas);
	}
	if (gasPrice == 0) {
	  unsignedTX_b.add(empty);
	} else {
	  unsignedTX_b.add(gasPrice);
	}
	if (nonce == 0) {
	  unsignedTX_b.add(empty);
	} else {
	  unsignedTX_b.add(nonce);
	}

	std::vector<uint8_t> unsignedTX = unsignedTX_b.build();

	// Recover Address
	auto unsignedTX_h = ethash::keccak256(unsignedTX.data(), unsignedTX.size());
	evmc_uint256be evmc_usignedTX_h;
	std::copy(&unsignedTX_h.bytes[0], unsignedTX_h.bytes + sizeof(evmc_uint256be),
			  &evmc_usignedTX_h.bytes[0]);
	evmc_address from = ecrecover2(evmc_usignedTX_h, actualV, r, s);
	std::array<uint8_t, 32> eth_array;
	std::copy_n(&from.bytes[0] + 12, 20, eth_array.begin());
	eth_addr eth_address = eosio::fixed_bytes<32>(eth_array);
	tb_account _account(_self, _self.value);
	auto by_eth_account_index = _account.get_index<name("byeth")>();
	auto itr_eth_addr = by_eth_account_index.find(eth_address);
	assert_b(itr_eth_addr != by_eth_account_index.end(), "invalid signed transaction");

  	evmc::EOSHostContext host = evmc::EOSHostContext(std::make_shared<eosio::contract>(*this));
  	evmc_revision rev = EVMC_BYZANTIUM;
  	evmc_message msg{};
	std::copy(to.begin(), to.end(), &msg.destination.bytes[0]);;
  	msg.sender = from;
  	msg.input_data = data.data();
  	msg.input_size = data.size();
  	to_evmc_uint256be(value, &msg.value);
  	/// TODO if value > 0 need to transfer ETH

	/// get code from table
	tb_account_code _account_code(_self, _self.value);
	auto by_eth_account_code_index = _account_code.get_index<name("byeth")>();
	auto itr_eth_code = by_eth_account_code_index.find(eth_address);
	assert_b(itr_eth_code != by_eth_account_code_index.end(), "no contract on this account");

  	auto vm = evmc::VM{evmc_create_evmone()};
  	std::vector<uint8_t> code = itr_eth_code->bytecode;
  	evmc::result result = vm.execute(host, rev, msg, code.data(), code.size());
  	evmc::bytes output;
  	output = {result.output_data, result.output_size};
	print(" \nres is : ");
	printhex(output.data(), output.size());
}


void test_contract::create(name eos_account, std::string salt) {
  	require_auth(eos_account);
  	// check eosio account exist
  	tb_account _account(_self, _self.value);
  	auto by_eos_account_index = _account.get_index<name("byeos")>();
  	auto itr_eos_addr = by_eos_account_index.find(eos_account.value);
  	assert_b(itr_eos_addr == by_eos_account_index.end(), "eos account already linked eth address");
  	/// TODO just use eosio_account string + eos_account.size() + salt and rlp
	std::string eos_str = eos_account.to_string();
	std::string combine = eos_str + std::to_string(eos_str.size()) + salt;
	std::string eth_str = rplEncode(combine);

  	auto eth = ethash::keccak256((uint8_t *) eth_str.c_str(), eth_str.size());
  	auto eth_bytes = eth.bytes;
	// transfer uint8_t [32] to std::array
  	std::array<uint8_t, 32> eth_array;
  	std::copy_n(&eth_bytes[0] + 12, 20, eth_array.begin());
	eth_addr eth_address = eosio::fixed_bytes<32>(eth_array);

  	auto by_eth_account_index = _account.get_index<name("byeth")>();
  	auto itr_eth_addr = by_eth_account_index.find(eth_address);
  	assert_b(itr_eth_addr == by_eth_account_index.end(), "already have eth address");

	_account.emplace(_self, [&](auto &the_account) {
	  the_account.id = _account.available_primary_key();
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
	    the_account_code.id = _account_code.available_primary_key();
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
