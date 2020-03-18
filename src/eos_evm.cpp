#include <eos_evm.hpp>
#include <ethash/keccak.hpp>


#include <eos_mock_host.hpp>

const evmc_address zero_address{{0}};

eos_evm::eos_evm(eosio::name receiver, eosio::name code,  datastream<const char*> ds): contract(receiver, code, ds) { }

void eos_evm::create(name eos_account,  const binary_extension<std::string> eth_address) {
	require_auth(eos_account);
	// check eosio account exist
	tb_account _account(_self, _self.value);
	auto by_eos_account_index = _account.get_index<name("byeos")>();

	auto eth_address_value = eth_address.has_value() ? eth_address.value() : "";
	auto create_type = eth_address_value.size() == 40 ? account_type::CREATE_ETH_PURE_ADDRESS : account_type::CREATE_EOS_ASSOCIATE_ADDRESS;

	tb_token_contract _token_contract(_self, _self.value);
	eosio::check(_token_contract.begin() != _token_contract.end(), "must link token contract first");
	auto itr_token_contract = _token_contract.begin();

	/// 1. eth_address == 160 bits eth account  set directly eth_address
	if (create_type == account_type::CREATE_ETH_PURE_ADDRESS) {
	    auto eth_address_arr = HexToBytes(eth_address_value);
        eth_addr_256 eth_address_256 = vector_to_checksum256(eth_address_arr);
        auto by_eth_account_index = _account.get_index<name("byeth")>();
        auto itr_eth_addr = by_eth_account_index.find(eth_address_256);
        eosio::check(itr_eth_addr == by_eth_account_index.end(), "eth address already exist");

        _account.emplace(_self, [&](auto &the_account) {
            the_account.id = _account.available_primary_key();
            the_account.eth_address = eth_addr_256_to_eth_addr_160(eth_address_256);
	        the_account.nonce = get_init_nonce();
	        the_account.balance = asset(0, itr_token_contract->contract.get_symbol());
	        the_account.eosio_account = name();
        });
	} else {
		/// 2. eth_address ！= 160 bits eth account,  must associate EOSIO account
		auto itr_eos_addr = by_eos_account_index.find(eos_account.value);
		eosio::check(itr_eos_addr == by_eos_account_index.end(), "eos account already linked eth address");
		std::string eos_str = eos_account.to_string();

		RLPBuilder eth_str;
		eth_str.start_list();
		eth_str.add(eos_str);
		eth_str.add(eth_address_value);
		std::vector <uint8_t> eth_rlp = eth_str.build();

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
		eosio::check(itr_eth_addr == by_eth_account_index.end(), "eth address already exist");

		_account.emplace(_self, [&](auto &the_account) {
			the_account.id = _account.available_primary_key();
			the_account.eth_address = eth_address_160;
			the_account.nonce = get_init_nonce();
			the_account.balance = asset(0, itr_token_contract->contract.get_symbol());
			the_account.eosio_account = eos_account;
		});
	}
}

void eos_evm::raw(const hex_code &trx_code, const binary_extension<eth_addr_160> &sender) {
	/// decode trx_code
	eos_evm::rlp_decode_trx trx = RLPDecodeTrx(trx_code);

	/// construct evmc_message
	evmc_message msg{};
	message_construct(trx, msg);

	std::vector<uint8_t> code;
	/// is create contract
	if (!trx.is_create_contract()) {
		msg.kind = EVMC_CALL;
		/// get eth code
		auto eth_dest = vector_to_checksum256(trx.to);
		code = get_eth_code(eth_dest);
	} else {
		msg.kind = EVMC_CREATE;
	}

	/// encode raw trx_code
	std::vector<uint8_t> unsigned_trx = RLPEncodeTrx(trx);

	/// generate unsigned trx hash
	auto evmc_unsigned_trx_hash = gen_unsigned_trx_hash(unsigned_trx);

	evmc_uint256be r;
	std::copy(trx.r_v.begin(), trx.r_v.end(), r.bytes);
	evmc_uint256be s;
	std::copy(trx.s_v.begin(), trx.s_v.end(), s.bytes);

	tb_account _account(_self, _self.value);
	auto by_eth_account_index = _account.get_index<name("byeth")>();
	auto trx_type = trx.is_r_or_s_zero() ? raw_verify_sig_type::EOS_SIG_VERIFY : raw_verify_sig_type::ETH_SIG_VERIFY;
	if (trx_type == raw_verify_sig_type::ETH_SIG_VERIFY) {
        /// use eth signature
        /// Recover Address
        evmc_address from = ecrecover(evmc_unsigned_trx_hash, trx.get_actual_v(), r, s);
		msg.sender = from;
        eosio::checksum256 sender_checksum_256 = evmc_address_to_checksum256(msg.sender);
        auto itr_eth_addr = by_eth_account_index.find(sender_checksum_256);
		/// recover sender must exist
		eosio::check(itr_eth_addr != by_eth_account_index.end(), "recover sender not exist in account table");
	} else {
	    /// use eos signature
	    msg.sender = checksum160_to_evmc_address(sender.value());
		eosio::check(sender.has_value(), "sender param can not be none"); /// sender exist;
		eosio::checksum256 sender_checksum_256 = evmc_address_to_checksum256(msg.sender);
		auto itr_eth_addr = by_eth_account_index.find(sender_checksum_256);
		/// sender must exist
		eosio::check(itr_eth_addr != by_eth_account_index.end(), "sender not exist in account table");
		/// assert EOS associate account exist
		eosio::check(itr_eth_addr->eosio_account != name(), "eosio associate account must exist");
		/// assert EOS associate account signature
		require_auth(itr_eth_addr->eosio_account);
	}

	/// assert nonce
	auto nonce = get_nonce(msg);
	eosio::check(nonce == uint256_from_vector(trx.nonce_v.data(), trx.nonce_v.size()), "nonce mismatch");

	evmc_result result;
	evmc::EOSHostContext host = evmc::EOSHostContext(std::make_shared<eosio::contract>(*this));
	if (msg.kind == EVMC_CALL) {
		/// execute code
		result = host.vm_execute(code, msg);
	} else {
		/// create a new eth address contract
		auto eth_contract_address = host.contract_destination(msg.sender, nonce);
		result = host.create_contract(eth_contract_address, msg);
	}

	/// if result == EVMC_SUCCESS, nonce + 1;
	if (result.status_code == EVMC_SUCCESS) {
		/// transfer value
		uint64_t transfer_val = from_evmc_uint256be(&msg.value);
		/// transfer asset
		if (transfer_val > 0) {
			host.transfer_fund(msg, result);
		}
		set_nonce(msg);
	}

	/// print result
	print_vm_receipt(result, trx, msg.sender);
}

void eos_evm::linktoken(const extended_symbol &contract) {
	tb_token_contract _token_contract(_self, _self.value);
	auto itr_token_contract = _token_contract.begin();
	eosio::check(itr_token_contract == _token_contract.end(), "must link token once");
	_token_contract.emplace(_self, [&](auto &the_contract) {
		the_contract.id = 0;
		the_contract.contract = contract;
	});
}

void eos_evm::ontransfer(const name &from, const name &to, const asset &quantity, const std::string memo) {
	require_auth(from);
	if (from == _self || to != _self) {
		return;
	}

	if (from == "eosio.bpay"_n || from == "eosio.names"_n || from == "eosio.ram"_n || from == "eosio.ramfee"_n ||
	    from == "eosio.saving"_n || from == "eosio.stake"_n || from == "eosio.vpay"_n) {
		return;
	}
	tb_token_contract _token_contract(_self, _self.value);
	eosio::check(_token_contract.begin() != _token_contract.end(), "must link token contract first");
	auto itr_token_contract = _token_contract.begin();
	eosio::check(get_first_receiver() == itr_token_contract->contract.get_contract(), "not support token contract");
	eosio::check(quantity.symbol == itr_token_contract->contract.get_symbol(), "not support token symbol");
	eosio::check(quantity.amount > 0, "cannot transfer negative balance");

	tb_account _account(_self, _self.value);
	auto by_eos_account_index = _account.get_index<name("byeos")>();
	auto itr_eos_from = by_eos_account_index.find(from.value);
	eosio::check(itr_eos_from != by_eos_account_index.end(), "no such eosio account");
    eosio::check(itr_eos_from->eosio_account != name(), "no associate eosio account");

    /// update account table token balance
	_account.modify(*itr_eos_from, _self, [&](auto &the_account) {
		the_account.balance += quantity;
	});
}

void eos_evm::withdraw(name eos_account, asset quantity) {
	require_auth(eos_account);
	tb_account _account(_self, _self.value);
	auto by_eos_account_index = _account.get_index<name("byeos")>();
	auto itr_eos_from = by_eos_account_index.find(eos_account.value);
	eosio::check(itr_eos_from != by_eos_account_index.end(), "no such associate eosio account");

	tb_token_contract _token_contract(_self, _self.value);
	auto itr_token_contract = _token_contract.begin();
	eosio::check(itr_token_contract != _token_contract.end(), "must link token contract first");
	eosio::check(quantity.symbol == itr_token_contract->contract.get_symbol(), "not support token symbol");
	/// check balance enough
	eosio::check(itr_eos_from->balance >= quantity, "overdrawn balance");

	action(
			permission_level{_self, "active"_n},
			itr_token_contract->contract.get_contract(),
			"transfer"_n,
			std::make_tuple(_self, eos_account, quantity, std::string(""))
	).send();
	/// update account table token balance
	_account.modify(*itr_eos_from, _self, [&](auto &the_account) {
		the_account.balance -= quantity;
	});
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
	tb_account_code _account_code(_self, _self.value);
	auto by_eth_account_code_index = _account_code.get_index<name("byeth")>();
	auto itr_eth_code = by_eth_account_code_index.find(eth_address);
	eosio::check(itr_eth_code != by_eth_account_code_index.end(), "no contract on this account");

	std::vector<uint8_t> eth_code = itr_eth_code->bytecode;
	return eth_code;
}

void eos_evm::message_construct(eos_evm::rlp_decode_trx &trx, evmc_message &msg) {
	std::copy(trx.to.begin(), trx.to.end(), &msg.destination.bytes[0]);;
	msg.input_data = trx.data.data();
	msg.input_size = trx.data.size();
	std::copy(trx.value.begin(), trx.value.end(), &msg.value.bytes[0]);
	uint64_t gas = uint_from_vector(trx.gas_v, "start gas");
	msg.gas = gas;
}

intx::uint256 eos_evm::get_nonce(const evmc_message &msg) {
	tb_account _account(_self, _self.value);
	eth_addr_256 eth_address_256 = evmc_address_to_checksum256(msg.sender);
	auto by_eth_account_index = _account.get_index<name("byeth")>();
	auto itr_eth_addr = by_eth_account_index.find(eth_address_256);
	/// return nonce
	return intx::be::unsafe::load<intx::uint256>(itr_eth_addr->nonce.extract_as_byte_array().data());
}

eosio_uint256 eos_evm::get_init_nonce() {
	std::array<uint8_t, 32> init_nonce;
	init_nonce.fill({});
	init_nonce[init_nonce.size() - 1] = 0x01;
	return fixed_bytes<32>(init_nonce);
}

void eos_evm::set_nonce(const evmc_message &msg) {
	tb_account _account(_self, _self.value);
	eth_addr_256 eth_address_256 = evmc_address_to_checksum256(msg.sender);
	auto by_eth_account_index = _account.get_index<name("byeth")>();
	auto itr_eth_addr = by_eth_account_index.find(eth_address_256);
	/// modify + 1
	_account.modify(*itr_eth_addr, _self, [&](auto &the_account) {
		auto nonce_256 = intx::be::unsafe::load<intx::uint256>(the_account.nonce.extract_as_byte_array().data());
		auto next_nonce_256 = nonce_256 + 1;
		evmc_bytes32 evmc_nonce_256 = intx::be::store<evmc_bytes32>(next_nonce_256);
		std::array<uint8_t, 32> nonce_arr;
		nonce_arr.fill({});
		std::copy(&evmc_nonce_256.bytes[0], &evmc_nonce_256.bytes[0] + sizeof(evmc_bytes32), nonce_arr.data());
		the_account.nonce = fixed_bytes<32>(nonce_arr);
	});
}

std::vector<uint8_t> eos_evm::next_part(RLPParser &parser, const char *label) {
	eosio::check(!parser.at_end(), "Transaction too short");
	return parser.next();
}

eos_evm::rlp_decode_trx eos_evm::RLPDecodeTrx(const hex_code &trx_code) {
	std::vector<uint8_t> tx = HexToBytes(trx_code);
	RLPParser tx_envelope_p = RLPParser(tx);
	std::vector<uint8_t> tx_envelope = tx_envelope_p.next();
	eosio::check(tx_envelope_p.at_end(), "There are more bytes here than one transaction");

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
	auto nonce = uint256_from_vector(trx.nonce_v.data(), trx.nonce_v.size());
	auto gas_price = uint256_from_vector(trx.gasPrice_v.data(), trx.gasPrice_v.size());
	auto gas = uint256_from_vector(trx.gas_v.data(), trx.gas_v.size());
	auto value = uint256_from_vector(trx.value.data(), trx.value.size());

//	eosio::check(trx.r_v.size() == sizeof(evmc_uint256be), "signature R invalid length");
	evmc_uint256be r;
	std::copy(trx.r_v.begin(), trx.r_v.end(), r.bytes);

//	eosio::check(trx.s_v.size() == sizeof(evmc_uint256be), "signature R invalid length");
	evmc_uint256be s;
	std::copy(trx.s_v.begin(), trx.s_v.end(), s.bytes);

	// Figure out non-signed V

	if (trx.v.size() < 1) {
		return {};
	}

	uint64_t chainID = uint_from_vector(trx.v, "chain ID");

	uint8_t actualV;
	eosio::check(chainID >= 37, "Non-EIP-155 signature V value");

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
	if (trx.to.empty()) {
		unsigned_trx_builder.add(empty);
	} else {
		unsigned_trx_builder.add(trx.to);
	}
	if (gas == 0) {
		unsigned_trx_builder.add(empty);
	} else {
		unsigned_trx_builder.add(gas);
	}
	if (gas_price == 0) {
		unsigned_trx_builder.add(empty);
	} else {
		unsigned_trx_builder.add(gas_price);
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
	print(" \ngas_left    : ",      result.gas_left);
	print(" \ngas_usage   : ",      uint_from_vector(trx.gas_v, "gas") - result.gas_left);
	print(" \nvalue       : ",      uint_from_vector(trx.value, "value"));
	print(" \ndata        : ");     printhex(trx.data.data(), trx.data.size());
	print(" \nv           : ",      uint_from_vector(trx.v,     "v"));
	print(" \nr           : ");     printhex(trx.r_v.data(), trx.r_v.size());
	print(" \ns           : ");     printhex(trx.s_v.data(), trx.s_v.size());
	auto print_contract_address = [&](evmc_result &result) {
		print(" \ncontract    : ");  printhex(&result.create_address.bytes[0], sizeof(evmc::address));
	};
	if (trx.is_create_contract() && result.status_code == EVMC_SUCCESS) print_contract_address(result);
}
