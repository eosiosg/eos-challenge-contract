#include <test_contract.hpp>
//#include <secp256k1.h>
//#include <secp256k1_recovery.h>
#include <ethash/keccak.hpp>

#include <evmone/execution.hpp>
#include <evmc/evmc.hpp>
#include <eos_mock_host.hpp>
#include <evmone/evmone.h>
#include <evmc/mocked_host.hpp>

const evmc_address zero_address{{0}};

test_contract::test_contract(eosio::name receiver, eosio::name code,  datastream<const char*> ds): contract(receiver, code, ds) ,
_account(_self, _self.value), _account_code(_self, _self.value), _nonce(_self, _self.value){
}

evmc_address test_contract::ecrecover(const evmc_uint256be &hash, const uint8_t version, const evmc_uint256be r, const evmc_uint256be s) {
	if (version > 1) {
		return zero_address;
	}

	std::array<uint8_t, 65> signature;
	signature.fill({});
	signature[0] = 0x1f;
	std::copy(r.bytes, r.bytes + sizeof(evmc_uint256be), signature.data()+1);
	std::copy(s.bytes, s.bytes + sizeof(evmc_uint256be), signature.data()+33);

	std::array<char, 65> ecc_sig;
	std::copy_n(signature.data(), 65, ecc_sig.data());
	print(" \n ecc signature is : ");
	printhex(ecc_sig.data(), ecc_sig.size());
	eosio::signature eosio_signature = eosio::signature{std::in_place_index<0>, ecc_sig};

	std::array<uint8_t, 32> message_hash_arr;
	std::copy(&hash.bytes[0], &hash.bytes[0] + 32, message_hash_arr.begin());
	eosio::checksum256 message_hash = eosio::fixed_bytes<32>(message_hash_arr);;

	eosio::public_key pubkey_compress = eosio::recover_key(message_hash, eosio_signature);
	auto k1_pubkey = std::get<0>(pubkey_compress);

	std::vector<uint8_t> _compressed_key( std::begin(k1_pubkey), std::end(k1_pubkey) );

	size_t pubkeysize = 65;
	unsigned char pubkey[65];
	pubkey[0] = 4;
	uECC_decompress(_compressed_key.data(), pubkey + 1, uECC_secp256k1());

	auto pubkeyhash =
			ethash::keccak256((uint8_t *) (pubkey + 1), pubkeysize - 1);

	evmc_address address;
	std::copy(pubkeyhash.bytes + (sizeof(evmc_uint256be) - sizeof(evmc_address)),
	          pubkeyhash.bytes + sizeof(evmc_uint256be), address.bytes);
	print(" \naddress is: ");
	printhex(&address.bytes[0], sizeof(address.bytes));
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
	//assert_b(!tx_envelope_p.at_end(), "There are more bytes here than one transaction");

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

	print("\n actual V", actualV);
	evmc_address from = ecrecover(evmc_usignedTX_h, actualV, r, s);
	/// TODO check from address in account table
	std::array<uint8_t, 32> eth_array;
	eth_array.fill({});
	std::copy_n(&from.bytes[0], 20, eth_array.begin()+12);
	eth_addr eth_address = eosio::fixed_bytes<32>(eth_array);
//	tb_account _account(_self, _self.value);
	auto by_eth_account_index = _account.get_index<name("byeth")>();
	auto itr_eth_addr = by_eth_account_index.find(eth_address);
	assert_b(itr_eth_addr != by_eth_account_index.end(), "invalid signed transaction");
}

/// eg: trx: e42a722b00000000000000000000000000000000000000000000000000000000000000070000000000000000000000000000000000000000000000000000000000000008
///     eth_address: contract address
///     smart contract code: 6080604052600436106049576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063e42a722b14604e578063ef5fb05b1460a2575b600080fd5b348015605957600080fd5b506086600480360381019080803560030b9060200190929190803560030b906020019092919050505060d0565b604051808260030b60030b815260200191505060405180910390f35b34801560ad57600080fd5b5060b460dd565b604051808260030b60030b815260200191505060405180910390f35b6000818301905092915050565b600060149050905600a165627a7a72305820556e7725ce14e3dfb830dceeb656d8cfafb2e1391d84f4a9daaaa057435c69cd0029
void test_contract::rawtrxexe(hex_code trx_param, eth_addr eth_address, eth_addr sender) {
	evmc::EOSHostContext host = evmc::EOSHostContext(std::make_shared<eosio::contract>(*this));
	evmc_revision rev = EVMC_BYZANTIUM;
	evmc_message msg{};
	msg.kind = EVMC_CALL;
	auto data = HexToBytes(trx_param);
	msg.input_data = data.data();
	msg.input_size = data.size();
	/// copy sender to msg.sender
	auto eth_sender_array = sender.extract_as_byte_array();
	std::copy_n(eth_sender_array.begin()+12, 20, &msg.sender.bytes[0]);
	/// copy eosio::checksum256 to bytes[20]
	auto eth_array = eth_address.extract_as_byte_array();
	std::copy_n(eth_array.begin()+12, 20, &msg.destination.bytes[0]);
	msg.gas = 2000000;

	auto by_eth_account_code_index = _account_code.get_index<name("byeth")>();
	auto itr_eth_code = by_eth_account_code_index.find(eth_address);
	assert_b(itr_eth_code != by_eth_account_code_index.end(), "no contract on this account");

	std::vector<uint8_t> code = itr_eth_code->bytecode;

	auto vm = evmc_create_evmone();
    	evmc_result result = vm->execute(vm, &evmc::EOSHostContext::get_interface(), host.to_context(), rev, &msg, code.data(), code.size());

	print(" \ngas left is : ", result.gas_left);
	assert_b(result.status_code == EVMC_SUCCESS, "execute failed");
	evmc::bytes output;
	output = {result.output_data, result.output_size};
	print(" \nres is : ");
	printhex(output.data(), output.size());
}

void test_contract::raw(hex_code trx_code) {
  	std::vector<uint8_t> tx = HexToBytes(trx_code);
	RLPParser tx_envelope_p = RLPParser(tx);
	std::vector<uint8_t> tx_envelope = tx_envelope_p.next();
	assert_b(tx_envelope_p.at_end(), "There are more bytes here than one transaction");

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
	evmc_address from = ecrecover(evmc_usignedTX_h, actualV, r, s);
	std::array<uint8_t, 32> eth_array;
	eth_array.fill({});
	std::copy_n(&from.bytes[0], 20, eth_array.begin()+12);
	eth_addr eth_address = eosio::fixed_bytes<32>(eth_array);
	auto by_eth_account_index = _account.get_index<name("byeth")>();
	auto itr_eth_addr = by_eth_account_index.find(eth_address);
	assert_b(itr_eth_addr != by_eth_account_index.end(), "invalid signed transaction");

	/// execute evm
	evmc::EOSHostContext host = evmc::EOSHostContext(std::make_shared<eosio::contract>(*this));
	evmc_revision rev = EVMC_BYZANTIUM;
	evmc_message msg{};
	msg.kind = EVMC_CALL;
	std::copy(to.begin(), to.end(), &msg.destination.bytes[0]);;
	std::copy_n(&from.bytes[0], 20, &msg.sender.bytes[0]);
	print(" \ninput param: ");
	printhex(data.data(), data.size());
	msg.input_data = data.data();
	msg.input_size = data.size();
//	to_evmc_uint256be(value, &msg.value);
	msg.gas = gas;
	/// TODO if value > 0 need to transfer ETH

	/// get code from table
	std::array<uint8_t, 32> eth_contract_arr;
	eth_contract_arr.fill({});
	std::copy_n(to.begin(), 20, eth_contract_arr.begin()+12);
	eth_addr eth_dest = eosio::fixed_bytes<32>(eth_contract_arr);
	auto by_eth_account_code_index = _account_code.get_index<name("byeth")>();
	auto itr_eth_code = by_eth_account_code_index.find(eth_dest);
	assert_b(itr_eth_code != by_eth_account_code_index.end(), "no contract on this account");

	std::vector<uint8_t> code = itr_eth_code->bytecode;
	auto vm = evmc_create_evmone();
	evmc_result result = vm->execute(vm, &evmc::EOSHostContext::get_interface(), host.to_context(), rev, &msg, code.data(), code.size());
	print(" \ngas left is : ", result.gas_left);
	assert_b(result.status_code == EVMC_SUCCESS, "execute failed");
	evmc::bytes output;
	output = {result.output_data, result.output_size};
	print(" \nres is : ");
	printhex(output.data(), output.size());
}


void test_contract::create(name eos_account, std::string salt) {
  	require_auth(eos_account);
  	// check eosio account exist
  	auto by_eos_account_index = _account.get_index<name("byeos")>();
  	auto itr_eos_addr = by_eos_account_index.find(eos_account.value);
  	assert_b(itr_eos_addr == by_eos_account_index.end(), "eos account already linked eth address");
  	/// TODO just use eosio_account string + eos_account.size() + salt and rlp
	std::string eos_str = eos_account.to_string();
	std::string combine = eos_str + std::to_string(eos_str.size()) + salt;

	RLPBuilder eth_str;
	eth_str.start_list();
	eth_str.add(eos_str);
	eth_str.add(salt);
	std::vector<uint8_t> eth_rlp = eth_str.build();

  	auto eth = ethash::keccak256(eth_rlp.data(), eth_rlp.size());
  	auto eth_bytes = eth.bytes;
	// transfer uint8_t [32] to std::array
  	std::array<uint8_t, 32> eth_array;
	eth_array.fill({});
	std::copy_n(&eth_bytes[0], 20, eth_array.begin() + 12);
	eth_addr eth_address = eosio::fixed_bytes<32>(eth_array);

  	auto by_eth_account_index = _account.get_index<name("byeth")>();
  	auto itr_eth_addr = by_eth_account_index.find(eth_address);
  	assert_b(itr_eth_addr == by_eth_account_index.end(), "already have eth address");

	_account.emplace(_self, [&](auto &the_account) {
	  the_account.id = _account.available_primary_key();
	  the_account.eth_address = eth_address;
	  the_account.nonce = 1;
	  the_account.eosio_balance = asset(0, symbol(symbol_code("EOS"), 4));
	  the_account.eosio_account = eos_account;
	});
}
///ETH private key
///
///(0) 0xD81F4358cB8cab53D005e7f47c7ba3F5116000A6 (100 ETH)
///(1) 0x39944247C2eDF660D86D57764B58d83B8EEE9014 (100 ETH)
///(2) 0xE327e755438fBDf9e60891d9B752DA10a38514D1 (100 ETH)
///(3) 0x8aAFae259C494870AC4E34e9E6019788787dDd77 (100 ETH)
///(4) 0x37840eE7603305F5F3d8fd26d41A4C3a5d7375da (100 ETH)
///(5) 0xeAD1a186688C5A9c967B427B632EaEFE8043B12c (100 ETH)
///(6) 0x713D1Ff9A73a7aC655F6F638316CBfdCf6da4B48 (100 ETH)
///(7) 0xCbf129e6Dd638cbc5b88C328087a6A963A73CeDd (100 ETH)
///(8) 0x5E9eb0EEd9B9afd8712e8611Bf5a6D593f7705Fd (100 ETH)
///(9) 0xa64428bee004C975FFcA398673c4D6E21a057FB6 (100 ETH)
///
///Private Keys
///==================
///(0) 0xcbb1981be330b0d97e620a61b913f678fc9c12c059a70badf92d0db317ff804f
///(1) 0x3f04415249414ff900b464f8d588517146c4ec39a3ae9855282030fa3de3862f
///(2) 0x9089c365c66ca5d1ea63f1a42a569326d887e680b2256fe79897a2da5aa708ea
///(3) 0x23c29d7d2eb5078c33ec80d5c0d86bcc0a0f5b58a24ee0d5904c7dd965956efb
///(4) 0x9587828e1281a552977f6619e3cf540ad3344fd31d90dce44daaaed2f70683dd
///(5) 0x7b697d4cccd589c1d065a18f315b5a5582e97984313fc9bb013dfd458769a829
///(6) 0x62c0788dd9f80919ed4f44392321892228a99deb31c0ba22060060f9ccc338a9
///(7) 0xcdc2fa8a012050cf0b3d1c2dc56fd8bb27ee74f3832627f48919977233d5fd64
///(8) 0x8fa52da70a645fe2daab8bcc24b523680dc6c4350985ea270cbe5d29d92fc8b0
///(9) 0x70458e863ddd01cbc5cb6891d399836a17f8d78a06ec6b4c12fae71352848344

void test_contract::updateeth(eth_addr eth_address, name eos_account) {
    auto by_eos_account_index = _account.get_index<name("byeos")>();
    auto itr_eos_addr = by_eos_account_index.find(eos_account.value);

	_account.modify(*itr_eos_addr, _self, [&](auto &the_account) {
	  the_account.eth_address = eth_address;
	});
}

void test_contract::transfers(name from, asset amount) {
	require_auth(from);
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
  	auto by_eth_account_index = _account.get_index<name("byeth")>();
  	auto itr_eth_addr = by_eth_account_index.find(eth_address);
  	assert_b(itr_eth_addr != by_eth_account_index.end(), "no such eth account");

  	name eos_account = itr_eth_addr->eosio_account;
  	require_auth(eos_account);

  	// set code and use eos_account ram
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


void test_contract::assert_b(bool test, const char *msg) {
	eosio::internal_use_do_not_use::eosio_assert(static_cast<uint32_t>(test), msg);
}

uint64_t test_contract::get_nonce() {
	/// modify + 1
	_nonce.modify(_nonce.begin(), _self, [&](auto &the_nonce) {
		the_nonce.nonce += 1;
	});
	/// return new nonce
	return _nonce.begin()->nonce;
}
