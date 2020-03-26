#include <eos_evm.hpp>
#include <ethash/hash_types.hpp>
#include <ethash/keccak.hpp>


#include <eos_evm_host.hpp>

const evmc_address zero_address{{0}};

eos_evm::eos_evm(eosio::name receiver, eosio::name code, datastream<const char *> ds) : contract(receiver, code, ds) {}

void eos_evm::create(const name &eos_account, const binary_extension <std::string> &eth_address) {
	require_auth(eos_account);
	tb_account _account(_self, _self.value);
	auto by_eos_account_index = _account.get_index<name("byeos")>();

	auto eth_address_value = eth_address.has_value() ? eth_address.value() : "";
	auto create_type = eth_address_value.size() == 40 ? account_type::CREATE_ETH_PURE_ADDRESS
	                                                  : account_type::CREATE_EOS_ASSOCIATE_ADDRESS;

	tb_token_contract _token_contract(_self, _self.value);
	eosio::check(_token_contract.begin() != _token_contract.end(), "must link token contract first");
	auto itr_token_contract = _token_contract.begin();

	/// 1. eth_address == 160 bits eth account  set directly eth_address
	if (create_type == account_type::CREATE_ETH_PURE_ADDRESS) {
		auto eth_address_arr = HexToBytes(eth_address_value);
		eth_addr_256 eth_address_256 = vector_to_eth_addr_256(eth_address_arr);
		auto by_eth_account_index = _account.get_index<name("byeth")>();
		auto itr_eth_addr = by_eth_account_index.find(eth_address_256);
		eosio::check(itr_eth_addr == by_eth_account_index.end(), "eth address already exist");

		_account.emplace(_self, [&](auto &the_account) {
			the_account.id = _account.available_primary_key();
			the_account.eth_address = eth_addr_256_to_eth_addr_160(eth_address_256);
			the_account.nonce = INIT_NONCE;
			the_account.balance = INIT_BALANCE;
			the_account.eosio_account = name();
		});
	} else {
		/// 2. eth_address ！= 160 bits eth account,  must associate EOSIO account
		auto itr_eos_addr = by_eos_account_index.find(eos_account.value);
		eosio::check(itr_eos_addr == by_eos_account_index.end(), "eos account already linked eth address");

		eth_addr_160 eth_address_160 = create_eth_address(eos_account, eth_address_value);
		eth_addr_256 eth_address_256 = eth_addr_160_to_eth_addr_256(eth_address_160);

		auto by_eth_account_index = _account.get_index<name("byeth")>();
		auto itr_eth_addr = by_eth_account_index.find(eth_address_256);
		eosio::check(itr_eth_addr == by_eth_account_index.end(), "eth address already exist");

		_account.emplace(_self, [&](auto &the_account) {
			the_account.id = _account.available_primary_key();
			the_account.eth_address = eth_address_160;
			the_account.nonce = INIT_NONCE;
			the_account.balance = INIT_BALANCE;
			the_account.eosio_account = eos_account;
		});
	}
}

void eos_evm::raw(const hex_code &trx_code, const binary_extension <eth_addr_160> &sender) {
	/// decode trx_code
	eos_evm::rlp_decode_trx trx = RLPDecodeTrx(trx_code);

	/// construct evmc_message
	evmc_message msg{};
	message_construct(trx, msg);

	/// encode raw trx_code
	std::vector <uint8_t> unsigned_trx = RLPEncodeTrx(trx);

	/// generate unsigned trx hash
	auto evmc_unsigned_trx_hash = gen_unsigned_trx_hash(unsigned_trx);

	evmc_uint256be r;
	std::copy(trx.r.begin(), trx.r.end(), r.bytes);
	evmc_uint256be s;
	std::copy(trx.s.begin(), trx.s.end(), s.bytes);

	tb_account _account(_self, _self.value);
	auto by_eth_account_index = _account.get_index<name("byeth")>();
	/// validate signature by verify_sig_type
	auto trx_type = trx.is_r_or_s_zero() ? raw_verify_sig_type::EOS_SIG_VERIFY_TYPE : raw_verify_sig_type::ETH_SIG_VERIFY_TYPE;
	if (trx_type == raw_verify_sig_type::ETH_SIG_VERIFY_TYPE) {
		/// use eth signature
		/// Recover Address
		evmc_address from = ecrecover(evmc_unsigned_trx_hash, std::get<0>(trx.get_v_chain_id_EIP155()), r, s);
		msg.sender = from;
		eth_addr_256 sender_eth_addr_256 = evmc_address_to_eth_addr_256(msg.sender);
		auto itr_eth_addr = by_eth_account_index.find(sender_eth_addr_256);
		/// recover sender must exist
		eosio::check(itr_eth_addr != by_eth_account_index.end(), "recover sender not exist in account table");
	} else {
		/// use eos signature
		eosio::check(sender.has_value(), "sender param can not be none"); /// sender exist;
		msg.sender = eth_addr_160_to_evmc_address(sender.value());
		eth_addr_256 sender_eth_addr_256 = evmc_address_to_eth_addr_256(msg.sender);
		auto itr_eth_addr = by_eth_account_index.find(sender_eth_addr_256);
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
	std::vector <uint8_t> code;
	if (!trx.is_create_contract()) {
		/// message_call
		msg.kind = EVMC_CALL;
		/// get eth code
		auto eth_dest = vector_to_eth_addr_256(trx.to);
		code = get_eth_code(eth_dest);
		result = host.vm_execute(code, msg);
		increase_nonce(msg);
	} else {
		/// is create contract
		msg.kind = EVMC_CREATE;
		/// create a new eth address contract
		auto eth_contract_address = host.create_address(msg.sender, nonce);
		result = host.create_contract(eth_contract_address, msg);
	}

	/// if result == EVMC_SUCCESS, transfer value;
	if (result.status_code == EVMC_SUCCESS) {
		/// transfer value
		auto transfer_val = intx::be::unsafe::load<intx::uint256>(&msg.value.bytes[0]);
		/// transfer asset
		if (transfer_val > 0) {
			host.transfer(msg, result);
		}
	}

	/// print result
	print_vm_receipt_json(result, trx,msg.sender, host.eth_emit_logs);
}

/// execute only on API node and do not broadcast transaction to get EVM execution receipt
void eos_evm::simulate(const hex_code &trx_code, const binary_extension <eth_addr_160> &sender) {
	raw(trx_code, sender);
	eosio::check(false, "mock execution");
}

/// for client get receipt
void eos_evm::log(const std::string &status_code,
         const std::string &output,
         const std::string &from,
         const std::string &to,
         const std::string &nonce,
         const std::string &gas_price,
         const std::string &gas_left,
         const std::string &gas_usage,
         const std::string &value,
         const std::string &data,
         const std::string &v,
         const std::string &r,
         const std::string &s,
         const std::string &contract,
         const std::string &eth_emit_logs){
	require_auth(_self);
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
	add_balance(from, quantity);
}

/**
 * if asset precision is 4. ETH wei precision is 18.
 * the minimum withdraw amount is 0.0001 SYS = 10 ^ (18 - 4) wei
 * */
void eos_evm::withdraw(const name &eos_account, const asset &quantity) {
	require_auth(eos_account);

	tb_token_contract _token_contract(_self, _self.value);
	auto itr_token_contract = _token_contract.begin();

	sub_balance(eos_account, quantity);

	action(
			permission_level{_self, "active"_n},
			itr_token_contract->contract.get_contract(),
			"transfer"_n,
			std::make_tuple(_self, eos_account, quantity, std::string(""))
	).send();
}

eth_addr_160 eos_evm::create_eth_address(const name &eos_account, std::string &eth_address) {
	/// rlp encode
	std::string eos_str = eos_account.to_string();
	RLPBuilder eth_address_str;
	eth_address_str.start_list();
	/// reverse encode, rlp encode eos_str first then eth_address
	eth_address_str.add(eth_address);
	eth_address_str.add(eos_str);
	std::vector <uint8_t> eth_rlp = eth_address_str.build();

	auto eth = ethash::keccak256(eth_rlp.data(), eth_rlp.size());
	auto eth_bytes = eth.bytes;
	std::array<uint8_t, 20> eth_array;
	eth_array.fill({});
	std::copy_n(&eth_bytes[0] + PADDING, 20, eth_array.begin());
	eth_addr_160 eth_address_160 = eosio::fixed_bytes<20>(eth_array);
	return eth_address_160;
}

evmc_address
eos_evm::ecrecover(const evmc_uint256be &hash, const uint8_t version, const evmc_uint256be r, const evmc_uint256be s) {
	if (version > 1) {
		return zero_address;
	}

	std::array<uint8_t, 65> signature;
	signature.fill({});
	signature[0] = version + 31;
	std::copy(r.bytes, r.bytes + sizeof(evmc_uint256be), signature.data() + 1);
	std::copy(s.bytes, s.bytes + sizeof(evmc_uint256be), signature.data() + 33);

	std::array<char, 65> ecc_sig;
	std::copy_n(signature.data(), 65, ecc_sig.data());
	eosio::signature eosio_signature = eosio::signature{std::in_place_index < 0 > , ecc_sig};

	std::array<uint8_t, 32> message_hash_arr;
	std::copy(&hash.bytes[0], &hash.bytes[0] + 32, message_hash_arr.begin());
	eosio::checksum256 message_hash = eosio::fixed_bytes<32>(message_hash_arr);;

	eosio::public_key pubkey_compress = eosio::recover_key(message_hash, eosio_signature);
	auto k1_pubkey = std::get<0>(pubkey_compress);

	std::vector <uint8_t> _compressed_key(std::begin(k1_pubkey), std::end(k1_pubkey));

	size_t pubkeysize = 65;
	unsigned char pubkey[65];
	pubkey[0] = 4;
	uECC_decompress(_compressed_key.data(), pubkey + 1, uECC_secp256k1());

	auto pubkeyhash =
			ethash::keccak256((uint8_t * )(pubkey + 1), pubkeysize - 1);

	evmc_address address;
	std::copy(pubkeyhash.bytes + (sizeof(evmc_uint256be) - sizeof(evmc_address)),
	          pubkeyhash.bytes + sizeof(evmc_uint256be), address.bytes);
	return address;
}


evmc_uint256be eos_evm::gen_unsigned_trx_hash(const std::vector <uint8_t> &unsigned_trx) {
	auto unsigned_trx_hash = ethash::keccak256(unsigned_trx.data(), unsigned_trx.size());
	evmc_uint256be evmc_unsigned_trx_hash;
	std::copy(&unsigned_trx_hash.bytes[0], unsigned_trx_hash.bytes + sizeof(evmc_uint256be),
	          &evmc_unsigned_trx_hash.bytes[0]);
	return evmc_unsigned_trx_hash;
}

std::vector <uint8_t> eos_evm::get_eth_code(const eth_addr_256 &eth_address) {
	/// will return empty vector if no contract
	tb_account_code _account_code(_self, _self.value);
	auto by_eth_account_code_index = _account_code.get_index<name("byeth")>();
	auto itr_eth_code = by_eth_account_code_index.find(eth_address);

	std::vector <uint8_t> eth_code = itr_eth_code->bytecode;
	return eth_code;
}

void eos_evm::message_construct(const eos_evm::rlp_decode_trx &trx, evmc_message &msg) {
	std::copy(trx.to.begin(), trx.to.end(), &msg.destination.bytes[0]);;
	msg.input_data = trx.data.data();
	msg.input_size = trx.data.size();
	auto value_256 = uint256_from_vector(trx.value.data(), trx.value.size());
	msg.value = intx::be::store<evmc_uint256be>(value_256);
	uint64_t gas = uint_from_vector(trx.gas_v, "start gas");
	msg.gas = gas;
}

intx::uint256 eos_evm::get_nonce(const evmc_message &msg) {
	tb_account _account(_self, _self.value);
	eth_addr_256 eth_address_256 = evmc_address_to_eth_addr_256(msg.sender);
	auto by_eth_account_index = _account.get_index<name("byeth")>();
	auto itr_eth_addr = by_eth_account_index.find(eth_address_256);
	/// return nonce
	return intx::be::unsafe::load<intx::uint256>(itr_eth_addr->nonce.extract_as_byte_array().data());
}

void eos_evm::increase_nonce(const evmc_message &msg) {
	tb_account _account(_self, _self.value);
	eth_addr_256 eth_address_256 = evmc_address_to_eth_addr_256(msg.sender);
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

/// add balance
void eos_evm::add_balance(const name &eos_account, const asset &quantity) {
	tb_token_contract _token_contract(_self, _self.value);
	eosio::check(_token_contract.begin() != _token_contract.end(), "must link token contract first");
	auto itr_token_contract = _token_contract.begin();
	auto sym_precision = itr_token_contract->contract.get_symbol().precision();
	eosio::check(get_first_receiver() == itr_token_contract->contract.get_contract(), "not support token contract");
	eosio::check(quantity.symbol == itr_token_contract->contract.get_symbol(), "not support token symbol");
	eosio::check(quantity.amount > 0, "cannot transfer negative balance");

	tb_account _account(_self, _self.value);
	auto by_eos_account_index = _account.get_index<name("byeos")>();
	auto itr_eos_from = by_eos_account_index.find(eos_account.value);
	eosio::check(itr_eos_from != by_eos_account_index.end(), "no such eosio account");
	eosio::check(itr_eos_from->eosio_account != name(), "no associate eosio account");

	auto amount_256 = asset_to_uint256(quantity, sym_precision);
	/// update account table token balance
	_account.modify(*itr_eos_from, _self, [&](auto &the_account) {
		intx::uint256 old_balance = intx::be::unsafe::load<intx::uint256>(
				the_account.balance.extract_as_byte_array().data());
		intx::uint256 new_balance = old_balance + amount_256;
		the_account.balance = intx_uint256_to_uint256_t(new_balance);
	});
}

/// sub balance
void eos_evm::sub_balance(const name &eos_account, const asset &quantity) {
	tb_account _account(_self, _self.value);
	auto by_eos_account_index = _account.get_index<name("byeos")>();
	auto itr_eos_from = by_eos_account_index.find(eos_account.value);
	eosio::check(itr_eos_from != by_eos_account_index.end(), "no such associate eosio account");

	tb_token_contract _token_contract(_self, _self.value);
	auto itr_token_contract = _token_contract.begin();
	auto sym_precision = itr_token_contract->contract.get_symbol().precision();
	eosio::check(itr_token_contract != _token_contract.end(), "must link token contract first");
	eosio::check(quantity.symbol == itr_token_contract->contract.get_symbol(), "not support token symbol");

	/// check balance enough
	auto amount_256 = asset_to_uint256(quantity, sym_precision);
	eosio::check(
			intx::be::unsafe::load<intx::uint256>(itr_eos_from->balance.extract_as_byte_array().data()) >= amount_256,
			"overdrawn balance");
	/// update account table token balance
	_account.modify(*itr_eos_from, _self, [&](auto &the_account) {
		intx::uint256 old_balance = intx::be::unsafe::load<intx::uint256>(
				the_account.balance.extract_as_byte_array().data());
		intx::uint256 new_balance = old_balance - amount_256;
		/// intx::uint256 to uint256_t
		the_account.balance = intx_uint256_to_uint256_t(new_balance);
	});
}

std::vector <uint8_t> eos_evm::next_part(RLPParser &parser, const char *label) {
	eosio::check(!parser.at_end(), "Transaction too short");
	return parser.next();
}

eos_evm::rlp_decode_trx eos_evm::RLPDecodeTrx(const hex_code &trx_code) {
	std::vector <uint8_t> tx = HexToBytes(trx_code);
	RLPParser tx_envelope_p = RLPParser(tx);
	std::vector <uint8_t> tx_envelope = tx_envelope_p.next();
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
	transaction.r = next_part(tx_parts_p, "signature R");
	transaction.s = next_part(tx_parts_p, "signature S");

	return transaction;
}

std::vector <uint8_t> eos_evm::RLPEncodeTrx(const rlp_decode_trx &trx) {
	auto nonce = uint256_from_vector(trx.nonce_v.data(), trx.nonce_v.size());
	auto gas_price = uint256_from_vector(trx.gasPrice_v.data(), trx.gasPrice_v.size());
	auto gas = uint256_from_vector(trx.gas_v.data(), trx.gas_v.size());
	auto value = uint256_from_vector(trx.value.data(), trx.value.size());

	evmc_uint256be r;
	std::copy(trx.r.begin(), trx.r.end(), r.bytes);

	evmc_uint256be s;
	std::copy(trx.s.begin(), trx.s.end(), s.bytes);

	// Figure out non-signed V

	if (trx.v.size() < 1) {
		return {};
	}

	uint64_t chain_id = std::get<1>(trx.get_v_chain_id_EIP155());

	// Re-encode RLP
	RLPBuilder unsigned_trx_builder;
	unsigned_trx_builder.start_list();

	std::vector <uint8_t> empty;
	unsigned_trx_builder.add(empty);    // S
	unsigned_trx_builder.add(empty);    // R
	unsigned_trx_builder.add(chain_id);  // V
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

	std::vector <uint8_t> unsigned_trx = unsigned_trx_builder.build();
	return unsigned_trx;
}

void eos_evm::print_vm_receipt(const evmc_result &result, const eos_evm::rlp_decode_trx &trx, const evmc_address &sender, const std::vector<eos_evm::eth_log> &eth_emit_logs) {

	std::vector<uint8_t> create_address_v;
	create_address_v.reserve(sizeof(evmc_address));
	create_address_v.assign(&result.create_address.bytes[0], &result.create_address.bytes[0] + sizeof(evmc_address));

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
	print(" \nr           : ");     printhex(trx.r.data(), trx.r.size());
	print(" \ns           : ");     printhex(trx.s.data(), trx.s.size());
	print(" \ncontract    : ",      BytesToHex(create_address_v));
	/// print eth emit logs
	auto print_emit_logs = [&](const eos_evm::eth_log &emit_log) {
		print(" \n address    : ");
		printhex(&emit_log.address.bytes[0], sizeof(evmc_address));
		print(" \n topic      : ", emit_log.topics_to_string());
		print(" \n data       : ");
		printhex(emit_log.data.data(), emit_log.data.size());
	};
	print(" \nemit log    : ");
	std::for_each(eth_emit_logs.begin(), eth_emit_logs.end(), print_emit_logs);
}

void eos_evm::print_vm_receipt_json(const evmc_result &result, const eos_evm::rlp_decode_trx &trx, const evmc_address &sender, const std::vector<eos_evm::eth_log> &eth_emit_logs) {
	std::vector<uint8_t > output_data;
	output_data.reserve(result.output_size);
	output_data.assign(result.output_data, result.output_data + result.output_size);

	std::vector<uint8_t> sender_v;
	sender_v.reserve(sizeof(evmc_address));
	sender_v.assign(&sender.bytes[0], &sender.bytes[0] + sizeof(evmc_address));

	std::vector<uint8_t> create_address_v;
	create_address_v.reserve(sizeof(evmc_address));
	create_address_v.assign(&result.create_address.bytes[0], &result.create_address.bytes[0] + sizeof(evmc_address));

	/// eth_emit_logs to json string
	std::string eth_emit_logs_json;
	for (int i = 0; i < eth_emit_logs.size(); ++i) {
		eth_emit_logs_json += "\"emit logs\" : [";
		eth_emit_logs_json += "{\"address\" :";

		std::vector<uint8_t> emit_address_v;
		emit_address_v.reserve(sizeof(evmc_address));
		emit_address_v.assign(&eth_emit_logs[i].address.bytes[0], &eth_emit_logs[i].address.bytes[0] + sizeof(evmc_address));

		eth_emit_logs_json += "\"";
		eth_emit_logs_json += BytesToHex(emit_address_v);
		eth_emit_logs_json += "\", ";
		eth_emit_logs_json += eth_emit_logs[i].topics_to_string();
		eth_emit_logs_json += ", ";
		eth_emit_logs_json += "\"data\": ";
		eth_emit_logs_json += "\"";
		eth_emit_logs_json += BytesToHex(eth_emit_logs[i].data);
		eth_emit_logs_json += "\"";
		if (i != eth_emit_logs.size() - 1) {
			eth_emit_logs_json += ",";
		} else {
			eth_emit_logs_json += "}]";
		}
	}

	std::string vm_receipt = "{\"status_code\": ";  vm_receipt += "\"";  vm_receipt += evmc::get_evmc_status_code_map().at(static_cast<int>(result.status_code));  vm_receipt +=  "\"," ;
	vm_receipt += "\"output\": ";  vm_receipt += "\"";  vm_receipt += BytesToHex(output_data);  vm_receipt += "\",";
	vm_receipt += "\"from\": ";  vm_receipt += "\"";  vm_receipt += BytesToHex(sender_v);  vm_receipt += "\",";
	vm_receipt += "\"to\": ";  vm_receipt += "\"";  vm_receipt += BytesToHex(trx.to);  vm_receipt += "\",";
	vm_receipt += "\"nonce\": ";  vm_receipt += "\"";  vm_receipt += std::to_string(uint_from_vector(trx.nonce_v, "nonce"));  vm_receipt += "\",";
	vm_receipt += "\"gas_price\": ";  vm_receipt += "\"";  vm_receipt += std::to_string(uint_from_vector(trx.gasPrice_v, "gasPrice_v"));  vm_receipt += "\",";
	vm_receipt += "\"gas_left\": ";  vm_receipt += "\"";  vm_receipt += std::to_string(result.gas_left);  vm_receipt += "\",";
	vm_receipt += "\"gas_usage\": ";  vm_receipt += "\"";  vm_receipt += std::to_string(uint_from_vector(trx.gas_v, "gas") - result.gas_left);  vm_receipt += "\",";
	vm_receipt += "\"value\": ";  vm_receipt += "\"";  vm_receipt += BytesToHex(trx.value);  vm_receipt += "\",";
	vm_receipt += "\"data\": ";  vm_receipt += "\"";  vm_receipt += BytesToHex(trx.data);  vm_receipt += "\",";
	vm_receipt += "\"v\": ";  vm_receipt += "\"";  vm_receipt += std::to_string(uint_from_vector(trx.v, "v"));  vm_receipt += "\",";
	vm_receipt += "\"r\": ";  vm_receipt += "\"";  vm_receipt += BytesToHex(trx.r);  vm_receipt += "\",";
	vm_receipt += "\"s\": ";  vm_receipt += "\"";  vm_receipt += BytesToHex(trx.s);  vm_receipt += "\",";
	vm_receipt += "\"contract\": ";  vm_receipt += "\"";  vm_receipt += BytesToHex(create_address_v);
	vm_receipt += eth_emit_logs_json == "" ? "\"" : "\"," ;  vm_receipt += eth_emit_logs_json;  vm_receipt +=  "}";
	print(vm_receipt);

	action(
			permission_level{_self, "active"_n},
			_self,
			"log"_n,
			std::make_tuple(evmc::get_evmc_status_code_map().at(static_cast<int>(result.status_code)),
			                BytesToHex(output_data),
			                BytesToHex(sender_v),
			                BytesToHex(trx.to),
			                std::to_string(uint_from_vector(trx.nonce_v, "nonce")),
			                std::to_string(uint_from_vector(trx.gasPrice_v, "gasPrice_v")),
			                std::to_string(result.gas_left),
			                std::to_string(uint_from_vector(trx.gas_v, "gas") - result.gas_left),
			                BytesToHex(trx.value),
			                BytesToHex(trx.data),
			                std::to_string(uint_from_vector(trx.v, "v")),
			                BytesToHex(trx.r),
			                BytesToHex(trx.s),
			                BytesToHex(create_address_v),
			                eth_emit_logs_json)
	).send();
}

std::string eos_evm::eth_log::topics_to_string() const {
	std::string topics_str;
	topics_str += "\"topics\": [";
	for (int i = 0; i < topics.size(); ++i) {
		topics_str += "\"";
		topics_str += BytesToHex(std::vector<uint8_t>(&topics[i].bytes[0], &topics[i].bytes[0] + sizeof(evmc_uint256be)));
		topics_str += "\"";
		if (i != topics.size() - 1) {
			topics_str += ",";
		} else {
			topics_str += "]";
		}
	}
	return topics_str;
}