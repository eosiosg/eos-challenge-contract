#include <eos_evm.hpp>
#include <ethash/keccak.hpp>

#include <evmone/execution.hpp>
#include <eos_mock_host.hpp>
#include <evmone/evmone.h>

const evmc_address zero_address{{0}};

eos_evm::eos_evm(eosio::name receiver, eosio::name code,  datastream<const char*> ds): contract(receiver, code, ds) ,
_account(_self, _self.value), _account_code(_self, _self.value), _nonce(_self, _self.value), _token_contract(_self, _self.value){
}

void eos_evm::create(name eos_account,  const binary_extension<std::string> salt) {
	require_auth(eos_account);
	// check eosio account exist
	auto by_eos_account_index = _account.get_index<name("byeos")>();
	auto itr_eos_addr = by_eos_account_index.find(eos_account.value);
	assert_b(itr_eos_addr == by_eos_account_index.end(), "eos account already linked eth address");

	auto salt_value = salt.has_value() ? salt.value() : "";

    /// must associate EOSIO account
    std::string eos_str = eos_account.to_string();

    RLPBuilder eth_str;
    eth_str.start_list();
    eth_str.add(eos_str);
    eth_str.add(salt_value);
    std::vector<uint8_t> eth_rlp = eth_str.build();

    auto eth = ethash::keccak256(eth_rlp.data(), eth_rlp.size());
    auto eth_bytes = eth.bytes;
    // transfer uint8_t [32] to std::array
    std::array<uint8_t, 20> eth_array;
    eth_array.fill({});
    std::copy_n(&eth_bytes[0] + PADDING, 20, eth_array.begin());
    eth_addr_160 eth_address_160 = eosio::fixed_bytes<20>(eth_array);
    eth_addr_256 eth_address_256 = eth_addr_160_to_eth_addr_256(eth_address_160);

    auto by_eth_account_index = _account.get_index<name("byeth")>();
    auto itr_eth_addr = by_eth_account_index.find(eth_address_256);
    assert_b(itr_eth_addr == by_eth_account_index.end(), "already have eth address");

	eosio::check(_token_contract.begin() != _token_contract.end(), "must set token contract first");
	auto itr_token_contract = _token_contract.begin();

	_account.emplace(_self, [&](auto &the_account) {
        the_account.id = _account.available_primary_key();
        the_account.eth_address = eth_address_160;
        the_account.nonce = 1;
        the_account.eosio_balance = asset(0, itr_token_contract->contract.get_symbol());
        the_account.eosio_account = eos_account;
    });
}

void eos_evm::raw(const hex_code &trx_code, const binary_extension<eth_addr_160> &sender) {
	/// decode trx_code
	eos_evm::rlp_decode_trx trx = RLPDecodeTrx(trx_code);

	/// assert nonce
//	eosio::check(get_nonce() == uint_from_vector(trx.nonce_v, "nonce"), "nonce mismatch");

	/// encode raw trx_code
	std::vector<uint8_t> unsigned_trx = RLPEncodeTrx(trx);

	/// generate unsigned trx hash
	auto evmc_unsigned_trx_hash = gen_unsigned_trx_hash(unsigned_trx);

	evmc_uint256be r;
	std::copy(trx.r_v.begin(), trx.r_v.end(), r.bytes);
	evmc_uint256be s;
	std::copy(trx.s_v.begin(), trx.s_v.end(), s.bytes);

	/// get eth code
	auto eth_dest = vector_to_checksum256(trx.to);
	auto code = get_eth_code(eth_dest);

    auto by_eth_account_index = _account.get_index<name("byeth")>();
	evmc_address evmc_sender;
	if (!trx.is_r_s_zero()) {
        /// use eth signature
        /// Recover Address
        evmc_address from = ecrecover(evmc_unsigned_trx_hash, trx.get_actual_v(), r, s);
		evmc_sender = from;
        eosio::checksum256 sender_checksum_256 = evmc_address_to_checksum256(evmc_sender);
        auto itr_eth_addr = by_eth_account_index.find(sender_checksum_256);
        /// sender must exist
        assert_b(itr_eth_addr != by_eth_account_index.end(), "sender not exist in account table");
	} else {
	    /// use eos signature
		assert_b(sender.has_value(), "sender param can not be none"); /// sender exist;
		eosio::checksum256 sender_checksum_256 = evmc_address_to_checksum256(evmc_sender);
		auto itr_eth_addr = by_eth_account_index.find(sender_checksum_256);
		/// sender must exist
		assert_b(itr_eth_addr != by_eth_account_index.end(), "sender not exist in account table");
		evmc_sender = checksum160_to_evmc_address(sender.value());
		/// assert EOS associate account exist
		assert_b(itr_eth_addr->eosio_account != name(), "eosio associate account must exist");
		/// assert EOS associate account signature
		require_auth(itr_eth_addr->eosio_account);
	}
	/// execute code
	auto evm_result = vm_execute(code, trx, evmc_sender);

	/// if result == EVMC_SUCCESS, global nonce + 1;
//	if (evm_result.status_code == EVMC_SUCCESS) {
//		set_nonce();
//	}

	/// print result
	print_vm_receipt(evm_result, trx, evmc_sender);
}

void eos_evm::createeth(name eos_account,  const std::string &eth_address) {
    require_auth(eos_account);
    /// 0. to lower
	/// 1. TODO assert eth_address valid

	assert_b(eth_address.size() == 40, "invalid length eth address");
	auto eth_address_arr = HexToBytes(eth_address);
	eth_addr_256 eth_address_256 = vector_to_checksum256(eth_address_arr);
	auto by_eth_account_index = _account.get_index<name("byeth")>();
	auto itr_eth_addr = by_eth_account_index.find(eth_address_256);
	assert_b(itr_eth_addr == by_eth_account_index.end(), "already have eth address");

	eosio::check(_token_contract.begin() != _token_contract.end(), "must set token contract first");
	auto itr_token_contract = _token_contract.begin();

	/// 2. eth_address == 160 bits eth account  set directly eth_address
	_account.emplace(_self, [&](auto &the_account) {
		the_account.id = _account.available_primary_key();
		the_account.eth_address = eth_addr_256_to_eth_addr_160(eth_address_256);
		the_account.nonce = 1;
		the_account.eosio_balance = asset(0, itr_token_contract->contract.get_symbol());
		the_account.eosio_account = name();
	});
}

void eos_evm::settoken(const extended_symbol &contract) {
	auto itr_token_contract = _token_contract.begin();
	if (itr_token_contract == _token_contract.end()) {
		_token_contract.emplace(_self, [&](auto &the_contract) {
			the_contract.id = 0;
			the_contract.contract = contract;
		});
	} else {
		_token_contract.modify(itr_token_contract, eosio::same_payer, [&](auto &the_contract) {
			the_contract.contract = contract;
		});
	}
}

void eos_evm::transfers(const name &from, const name &to, const asset &quantity, const std::string memo) {
	require_auth(from);
	if (from == _self || to != _self) {
		return;
	}

	if (from == "eosio.bpay"_n || from == "eosio.names"_n || from == "eosio.ram"_n || from == "eosio.ramfee"_n ||
	    from == "eosio.saving"_n || from == "eosio.stake"_n || from == "eosio.vpay"_n) {
		return;
	}
	eosio::check(_token_contract.begin() != _token_contract.end(), "must set token contract first");
	auto itr_token_contract = _token_contract.begin();
	eosio::check(get_first_receiver() == itr_token_contract->contract.get_contract(), "not support this token contract");
	eosio::check(quantity.symbol == itr_token_contract->contract.get_symbol(), "not support this token symbol");
	eosio::check(quantity.amount > 0, "cannot transfer negative balance");

	auto by_eos_account_index = _account.get_index<name("byeos")>();
	auto itr_eos_from = by_eos_account_index.find(from.value);
	assert_b(itr_eos_from != by_eos_account_index.end(), "no such eosio account");
    assert_b(itr_eos_from->eosio_account != name(), "no associate eosio account");

    /// update account table token balance
	_account.modify(*itr_eos_from, _self, [&](auto &the_account) {
		the_account.eosio_balance += quantity;
	});
}

void eos_evm::withdraw(name eos_account, asset quantity) {
	require_auth(eos_account);
	auto by_eos_account_index = _account.get_index<name("byeos")>();
	auto itr_eos_from = by_eos_account_index.find(eos_account.value);
	assert_b(itr_eos_from != by_eos_account_index.end(), "no such associate eosio account");

	auto itr_token_contract = _token_contract.begin();
	eosio::check(itr_token_contract != _token_contract.end(), "must set token contract first");
	eosio::check(quantity.symbol == itr_token_contract->contract.get_symbol(), "not support this token symbol");
	/// check balance enough
	assert_b(itr_eos_from->eosio_balance >= quantity, "overdrawn balance");

	action(
			permission_level{_self, "active"_n},
			itr_token_contract->contract.get_contract(),
			"transfer"_n,
			std::make_tuple(_self, eos_account, quantity, std::string(""))
	).send();
	/// update account table token balance
	_account.modify(*itr_eos_from, _self, [&](auto &the_account) {
		the_account.eosio_balance -= quantity;
	});
}

void eos_evm::setcontract(const name &eos_creator, const hex_code &evm_code, const eth_addr_160 &sender, const uint64_t nonce) {
	require_auth(eos_creator);
	/// 1. assert nonce
	eosio::check(get_nonce() == nonce, "nonce mismatch");

	/// 2. construct evmc msg
	evmc::EOSHostContext host = evmc::EOSHostContext(std::make_shared<eosio::contract>(*this));
	evmc_revision rev = EVMC_BYZANTIUM;
	evmc_message msg{};
	msg.kind = EVMC_CREATE;
	msg.gas = 2000000;

	/// 3. execute evmone
	auto code = HexToBytes(evm_code);
	auto vm = evmc_create_evmone();
	auto result = vm->execute(vm, &evmc::EOSHostContext::get_interface(), host.to_context(), rev, &msg, code.data(), code.size());

	/// 4. get evmc_result output raw evm code
	std::vector<uint8_t> raw_evm_code;
	std::copy_n(result.output_data, result.output_size, std::back_inserter(raw_evm_code));

	/// 5. create a new eth address contract
	eth_addr_160 eth_contract_160 = contract_destination(sender, nonce);
	eth_addr_256 eth_contract_256 = eth_addr_160_to_eth_addr_256(eth_contract_160);

	auto by_eth_account_index = _account.get_index<name("byeth")>();
	auto itr_eth_addr = by_eth_account_index.find(eth_contract_256);
	assert_b(itr_eth_addr == by_eth_account_index.end(), "already exist eth contract");

	eosio::check(_token_contract.begin() != _token_contract.end(), "must set token contract first");
	auto itr_token_contract = _token_contract.begin();

	/// 6. add contract address to table no associate eos account
	_account.emplace(_self, [&](auto &the_account) {
		the_account.id = _account.available_primary_key();
		the_account.eth_address = eth_contract_160;
		the_account.nonce = 1;
		the_account.eosio_balance = asset(0, itr_token_contract->contract.get_symbol());
		the_account.eosio_account = name();
	});

	/// 7. add code to table
	auto by_eth_account_code_index = _account_code.get_index<name("byeth")>();
	auto itr_eth_code = by_eth_account_code_index.find(eth_contract_256);
	eosio::check(itr_eth_code == by_eth_account_code_index.end(), "address already exist code");
	_account_code.emplace(_self, [&](auto &the_account_code){
		the_account_code.id = _account_code.available_primary_key();
		the_account_code.eth_address = eth_contract_160;
		the_account_code.bytecode = raw_evm_code;
	});

	/// 8. if evmc success set nonce ++
	if (result.status_code == EVMC_SUCCESS) {
		set_nonce();
	}

	/// 9. print generated eth address
	print(" \nstatus_code   : ",      evmc::get_evmc_status_code_map().at(static_cast<int>(result.status_code)));
	print(" \noutput        : ");     printhex(result.output_data, result.output_size);
	print(" \ncontract addr : ");     printhex(eth_contract_160.extract_as_byte_array().data(), eth_contract_160.extract_as_byte_array().size());
}

void eos_evm::setcode(eth_addr_160 eth_address, hex_code evm_code) {
	// find eos account to check auth
	eth_addr_256 eth_address_256 = eth_addr_160_to_eth_addr_256(eth_address);
	auto by_eth_account_index = _account.get_index<name("byeth")>();
	auto itr_eth_addr = by_eth_account_index.find(eth_address_256);
	assert_b(itr_eth_addr != by_eth_account_index.end(), "no such eth account");

	name eos_account = itr_eth_addr->eosio_account;
//	require_auth(eos_account);

	auto by_eth_account_code_index = _account_code.get_index<name("byeth")>();
	auto itr_eth_code = by_eth_account_code_index.find(eth_address_256);
	if (itr_eth_code == by_eth_account_code_index.end()) {
		_account_code.emplace(_self, [&](auto &the_account_code){
			the_account_code.id = _account_code.available_primary_key();
			the_account_code.eth_address = eth_address;
			the_account_code.bytecode = HexToBytes(evm_code);
		});
	} else {
		_account_code.modify(*itr_eth_code, eosio::same_payer, [&](auto &the_account_code){
			the_account_code.bytecode = HexToBytes(evm_code);
		});
	}
}

evmc_address eos_evm::ecrecover(const evmc_uint256be &hash, const uint8_t version, const evmc_uint256be r, const evmc_uint256be s) {
	if (version > 1) {
		return zero_address;
	}

	std::array<uint8_t, 65> signature;
	signature.fill({});
	signature[0] = version + 31;
	std::copy(r.bytes, r.bytes + sizeof(evmc_uint256be), signature.data()+1);
	std::copy(s.bytes, s.bytes + sizeof(evmc_uint256be), signature.data()+33);

	std::array<char, 65> ecc_sig;
	std::copy_n(signature.data(), 65, ecc_sig.data());
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
	return address;
}


evmc_uint256be eos_evm::gen_unsigned_trx_hash(std::vector<uint8_t> unsigned_trx) {
	auto unsigned_trx_hash = ethash::keccak256(unsigned_trx.data(), unsigned_trx.size());
	evmc_uint256be evmc_unsigned_trx_hash;
	std::copy(&unsigned_trx_hash.bytes[0], unsigned_trx_hash.bytes + sizeof(evmc_uint256be),
	          &evmc_unsigned_trx_hash.bytes[0]);
	return evmc_unsigned_trx_hash;
}

std::vector<uint8_t> eos_evm::get_eth_code(eth_addr_256 eth_address) {
	auto by_eth_account_code_index = _account_code.get_index<name("byeth")>();
	auto itr_eth_code = by_eth_account_code_index.find(eth_address);
	assert_b(itr_eth_code != by_eth_account_code_index.end(), "no contract on this account");

	std::vector<uint8_t> eth_code = itr_eth_code->bytecode;
	return eth_code;
}

evmc_result eos_evm::vm_execute(std::vector<uint8_t> &code, eos_evm::rlp_decode_trx &trx, evmc_address &sender) {
	evmc::EOSHostContext host = evmc::EOSHostContext(std::make_shared<eosio::contract>(*this));
	evmc_revision rev = EVMC_BYZANTIUM;
	evmc_message msg{};
	msg.kind = EVMC_CALL;
	std::copy(trx.to.begin(), trx.to.end(), &msg.destination.bytes[0]);;
	std::copy_n(&sender.bytes[0], ADDRSIZE, &msg.sender.bytes[0]);
	msg.input_data = trx.data.data();
	msg.input_size = trx.data.size();
	std::copy(trx.value.begin(), trx.value.end(), &msg.value.bytes[0]);
	uint64_t gas = uint_from_vector(trx.gas_v, "gas");
	msg.gas = gas;

	auto vm = evmc_create_evmone();
	evmc_result result = vm->execute(vm, &evmc::EOSHostContext::get_interface(), host.to_context(), rev, &msg, code.data(), code.size());
	return result;
}


void eos_evm::assert_b(bool test, const char *msg) {
	eosio::internal_use_do_not_use::eosio_assert(static_cast<uint32_t>(test), msg);
}

uint64_t eos_evm::get_nonce() {
	if (_nonce.begin() == _nonce.end()) {
		_nonce.emplace(_self, [&](auto &the_nonce) {
			the_nonce.nonce = 0;
		});
	}
	/// return new nonce
	return _nonce.begin()->nonce + 1;
}

void eos_evm::set_nonce() {
	if (_nonce.begin() == _nonce.end()) {
		_nonce.emplace(_self, [&](auto &the_nonce) {
			the_nonce.nonce = 1;
		});
	}
	/// modify + 1
	_nonce.modify(_nonce.begin(), _self, [&](auto &the_nonce) {
		the_nonce.nonce += 1;
	});
}

std::vector<uint8_t> eos_evm::next_part(RLPParser &parser, const char *label) {
	assert_b(!parser.at_end(), "Transaction too short");
	return parser.next();
}

eos_evm::rlp_decode_trx eos_evm::RLPDecodeTrx(const hex_code &trx_code) {
	std::vector<uint8_t> tx = HexToBytes(trx_code);
	RLPParser tx_envelope_p = RLPParser(tx);
	std::vector<uint8_t> tx_envelope = tx_envelope_p.next();
	assert_b(tx_envelope_p.at_end(), "There are more bytes here than one transaction");

	RLPParser tx_parts_p = RLPParser(tx_envelope);
	rlp_decode_trx transaction;
	transaction.nonce_v = next_part(tx_parts_p, "nonce");
	transaction.gasPrice_v = next_part(tx_parts_p, "gas price");
	transaction.gas_v = next_part(tx_parts_p, "start gas");
	transaction.to = next_part(tx_parts_p, "to address");
	transaction.value = next_part(tx_parts_p, "value");
	transaction.data = next_part(tx_parts_p, "data");
	transaction.v = next_part(tx_parts_p, "signature V");
	transaction.r_v = next_part(tx_parts_p, "signature R");
	transaction.s_v = next_part(tx_parts_p, "signature S");

	return transaction;
}

std::vector<uint8_t> eos_evm::RLPEncodeTrx(const rlp_decode_trx &trx) {
	uint64_t nonce = uint_from_vector(trx.nonce_v, "nonce");
	uint64_t gasPrice = uint_from_vector(trx.gasPrice_v, "gas price");
	uint64_t gas = uint_from_vector(trx.gas_v, "start gas");
	uint64_t value = uint_from_vector(trx.value, "value");

//	assert_b(trx.r_v.size() == sizeof(evmc_uint256be), "signature R invalid length");
	evmc_uint256be r;
	std::copy(trx.r_v.begin(), trx.r_v.end(), r.bytes);

//	assert_b(trx.s_v.size() == sizeof(evmc_uint256be), "signature R invalid length");
	evmc_uint256be s;
	std::copy(trx.s_v.begin(), trx.s_v.end(), s.bytes);

	// Figure out non-signed V

	if (trx.v.size() < 1) {
		return {};
	}

	uint64_t chainID = uint_from_vector(trx.v, "chain ID");

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
	RLPBuilder unsigned_trx_builder;
	unsigned_trx_builder.start_list();

	std::vector<uint8_t> empty;
	unsigned_trx_builder.add(empty);    // S
	unsigned_trx_builder.add(empty);    // R
	unsigned_trx_builder.add(chainID);  // V
	unsigned_trx_builder.add(trx.data);
	if (value == 0) {
		// signing hash expects 0x80 here, not 0x00
		unsigned_trx_builder.add(empty);
	} else {
		unsigned_trx_builder.add(value);
	}
	unsigned_trx_builder.add(trx.to);
	if (gas == 0) {
		unsigned_trx_builder.add(empty);
	} else {
		unsigned_trx_builder.add(gas);
	}
	if (gasPrice == 0) {
		unsigned_trx_builder.add(empty);
	} else {
		unsigned_trx_builder.add(gasPrice);
	}
	if (nonce == 0) {
		unsigned_trx_builder.add(empty);
	} else {
		unsigned_trx_builder.add(nonce);
	}

	std::vector<uint8_t> unsigned_trx = unsigned_trx_builder.build();
	return unsigned_trx;
}

void eos_evm::print_vm_receipt(evmc_result result, eos_evm::rlp_decode_trx &trx, evmc_address &sender) {
	print(" \nstatus_code : ",      evmc::get_evmc_status_code_map().at(static_cast<int>(result.status_code)));
	print(" \noutput      : ");     printhex(result.output_data, result.output_size);
	print(" \nfrom        : ");     printhex(&sender.bytes[0], sizeof(evmc_address));
	print(" \nto          : ");     printhex(trx.to.data(), trx.to.size());
	print(" \nnonce       : ",      uint_from_vector(trx.nonce_v, "nonce"));
	print(" \ngas_price   : ",      uint_from_vector(trx.gasPrice_v, "gasPrice_v"));
	print(" \ngas         : ",      uint_from_vector(trx.gas_v, "gas"));
	print(" \nvalue       : ",      uint_from_vector(trx.value, "value"));
	print(" \ndata        : ");     printhex(trx.data.data(), trx.data.size());
	print(" \nv           : ",      uint_from_vector(trx.v,     "v"));
	print(" \nr           : ");     printhex(trx.r_v.data(), trx.r_v.size());
	print(" \ns           : ");     printhex(trx.s_v.data(), trx.s_v.size());
}

eth_addr_160 eos_evm::contract_destination(const eth_addr_160 &sender, const uint64_t nonce) {
	RLPBuilder eth_str;
	eth_str.start_list();
	eth_str.add(sender.extract_as_byte_array().data(), sender.extract_as_byte_array().size());
	eth_str.add(nonce);
	std::vector<uint8_t> eth_rlp = eth_str.build();

	auto eth = ethash::keccak256(eth_rlp.data(), eth_rlp.size());
	auto eth_bytes = eth.bytes;
	// transfer uint8_t [32] to std::array
	std::array<uint8_t, 20> eth_array;
	eth_array.fill({});
	std::copy_n(&eth_bytes[0] + PADDING, 20, eth_array.begin());
	eth_addr_160 eth_contract_160 = eosio::fixed_bytes<20>(eth_array);
	return eth_contract_160;
}

/// pass hex code to execute in evm
/// auto code = bytecode{} + OP_ADDRESS + OP_BALANCE + mstore(0) + ret(32 - 6, 6); == 30316000526006601af3
/// "30316000526006601af3"  get balance
/// "6007600d0160005260206000f3" execute compute return 0x14
void eos_evm::rawtest(hex_code hexcode) {
	evmc::EOSHostContext host = evmc::EOSHostContext(std::make_shared<eosio::contract>(*this));
	evmc_revision rev = EVMC_BYZANTIUM;
	evmc_message msg{};

	msg.gas = 2000000;
	std::vector<uint8_t> code = HexToBytes(hexcode);
	auto vm = evmc_create_evmone();
	evmc_result result = vm->execute(vm, &evmc::EOSHostContext::get_interface(), host.to_context(), rev, &msg, code.data(), code.size());
	evmc::bytes output;
	output = {result.output_data, result.output_size};

	print(" \nres is : ");
	printhex(output.data(), output.size());
}

void eos_evm::verifysig(hex_code trx_code) {
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

	RLPBuilder unsigned_trx_builder;
	unsigned_trx_builder.start_list();

	std::vector<uint8_t> empty;
	unsigned_trx_builder.add(empty);    // S
	unsigned_trx_builder.add(empty);    // R
	unsigned_trx_builder.add(chainID);  // V
	unsigned_trx_builder.add(data);
	if (value == 0) {
		// signing hash expects 0x80 here, not 0x00
		unsigned_trx_builder.add(empty);
	} else {
		unsigned_trx_builder.add(value);
	}
	unsigned_trx_builder.add(to);
	if (gas == 0) {
		unsigned_trx_builder.add(empty);
	} else {
		unsigned_trx_builder.add(gas);
	}
	if (gasPrice == 0) {
		unsigned_trx_builder.add(empty);
	} else {
		unsigned_trx_builder.add(gasPrice);
	}
	if (nonce == 0) {
		unsigned_trx_builder.add(empty);
	} else {
		unsigned_trx_builder.add(nonce);
	}

	std::vector<uint8_t> unsigned_trx = unsigned_trx_builder.build();

	// Recover Address
	auto unsigned_trx_hash = ethash::keccak256(unsigned_trx.data(), unsigned_trx.size());
	evmc_uint256be evmc_unsigned_trx_hash;
	std::copy(&unsigned_trx_hash.bytes[0], unsigned_trx_hash.bytes + sizeof(evmc_uint256be),
	          &evmc_unsigned_trx_hash.bytes[0]);

	print("\n actual V", actualV);
	evmc_address from = ecrecover(evmc_unsigned_trx_hash, actualV, r, s);
	/// TODO check from address in account table
	std::array<uint8_t, 32> eth_array;
	eth_array.fill({});
	std::copy_n(&from.bytes[0], 20, eth_array.begin()+12);
	eth_addr_256 eth_address_256 = eosio::fixed_bytes<32>(eth_array);
//	tb_account _account(_self, _self.value);
	auto by_eth_account_index = _account.get_index<name("byeth")>();
	auto itr_eth_addr = by_eth_account_index.find(eth_address_256);
	assert_b(itr_eth_addr != by_eth_account_index.end(), "invalid signed transaction");
}

/// eg: trx: e42a722b00000000000000000000000000000000000000000000000000000000000000070000000000000000000000000000000000000000000000000000000000000008
///     eth_address: contract address
///     smart contract code: 6080604052600436106049576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063e42a722b14604e578063ef5fb05b1460a2575b600080fd5b348015605957600080fd5b506086600480360381019080803560030b9060200190929190803560030b906020019092919050505060d0565b604051808260030b60030b815260200191505060405180910390f35b34801560ad57600080fd5b5060b460dd565b604051808260030b60030b815260200191505060405180910390f35b6000818301905092915050565b600060149050905600a165627a7a72305820556e7725ce14e3dfb830dceeb656d8cfafb2e1391d84f4a9daaaa057435c69cd0029
void eos_evm::rawtrxexe(hex_code trx_param, eth_addr_160 eth_address, eth_addr_160 sender) {
	eth_addr_256 eth_address_256 = eth_addr_160_to_eth_addr_256(eth_address);
	evmc::EOSHostContext host = evmc::EOSHostContext(std::make_shared<eosio::contract>(*this));
	evmc_revision rev = EVMC_BYZANTIUM;
	evmc_message msg{};
	msg.kind = EVMC_CALL;
	auto data = HexToBytes(trx_param);
	msg.input_data = data.data();
	msg.input_size = data.size();
	/// copy sender to msg.sender
	auto eth_sender_array = sender.extract_as_byte_array();
	std::copy(eth_sender_array.begin(), eth_sender_array.end(), &msg.sender.bytes[0]);
	/// copy eosio::checksum256 to bytes[20]
	auto eth_array = eth_address.extract_as_byte_array();
	std::copy(eth_array.begin(), eth_array.end(), &msg.destination.bytes[0]);
	msg.gas = 2000000;

	auto by_eth_account_code_index = _account_code.get_index<name("byeth")>();
	auto itr_eth_code = by_eth_account_code_index.find(eth_address_256);
	assert_b(itr_eth_code != by_eth_account_code_index.end(), "no contract on this account");

	std::vector<uint8_t> code = itr_eth_code->bytecode;

	auto vm = evmc_create_evmone();
	evmc_result result = vm->execute(vm, &evmc::EOSHostContext::get_interface(), host.to_context(), rev, &msg, code.data(), code.size());

	print(" \ngas left is : ", result.gas_left);
	assert_b(result.status_code == EVMC_SUCCESS, "execute failed");
	print_f("\n res status: %", static_cast<uint64_t>(result.status_code));
	evmc::bytes output;
	output = {result.output_data, result.output_size};
	print(" \nres is : ");
	printhex(output.data(), output.size());
}
