// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018-2019 The evmone Authors.
// Licensed under the Apache License, Version 2.0.
#pragma once

#include <cstdint>
#include <string>

using bytes = std::basic_string<uint8_t>;
using bytes_view = std::basic_string_view<uint8_t>;
typedef eosio::checksum160   eth_addr_160;
typedef eosio::checksum256   eth_addr_256;
typedef std::vector<uint8_t> binary_code;
typedef std::string          hex_code;

#define PADDING 12
#define ADDRSIZE 20

/// Encode a byte to a hex string.
inline std::string hex(uint8_t b) noexcept {
  static constexpr auto hex_chars = "0123456789abcdef";
  return {hex_chars[b >> 4], hex_chars[b & 0xf]};
}

/// Encodes bytes as hex string.
std::string hex(bytes_view bs) {
  std::string str;
  str.reserve(bs.size() * 2);
  for (auto b : bs)
	str += hex(b);
  return str;
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

std::string int2hex(uint64_t dec_num) {
  std::string hexdec_num = "";
  uint64_t r;
  char hex[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
  while (dec_num > 0) {
	r = dec_num % 16;
	hexdec_num = hex[r] + hexdec_num;
	dec_num = dec_num / 16;
  }
  return hexdec_num;
}

void to_evmc_uint256be(uint64_t val, evmc_uint256be *ret) {
  uint8_t mask = 0xff;
  for (size_t i = 0; i < sizeof(evmc_uint256be); i++) {
	uint8_t byte = val & mask;
	ret->bytes[sizeof(evmc_uint256be) - i - 1] = byte;  // big endian order
	val = val >> 8;
  }
}

eosio::checksum256 evmc_uint256_to_checksum256(evmc_uint256be value) {
	std::array<uint8_t, 32> eth_address_arr;
	eth_address_arr.fill({});
	std::copy_n(&value.bytes[0], sizeof(evmc_uint256be), eth_address_arr.begin());
	eth_addr_256 eth_address = eosio::fixed_bytes<32>(eth_address_arr);
	return eth_address;
}

eosio::checksum256 evmc_address_to_checksum256(evmc_address address) {
	std::array<uint8_t, 32> eth_address_arr;
	eth_address_arr.fill({});
	std::copy_n(&address.bytes[0], sizeof(evmc_address), eth_address_arr.begin()+PADDING);
	eth_addr_256 eth_address = eosio::fixed_bytes<32>(eth_address_arr);
	return eth_address;
}

eosio::checksum256 vector_to_checksum256(std::vector<uint8_t> &address) {
	eosio::check(address.size() == sizeof(evmc_address), "address must be 20bytes array");
	std::array<uint8_t, 32> eth_address_arr;
	eth_address_arr.fill({});
	std::copy(address.begin(), address.end(), eth_address_arr.begin()+PADDING);
	eth_addr_256 eth_address = eosio::fixed_bytes<32>(eth_address_arr);
	return eth_address;
}

eth_addr_256 eth_addr_160_to_eth_addr_256(const eth_addr_160 &eth_address_160) {
	auto eth_arr_160 = eth_address_160.extract_as_byte_array();
	std::array<uint8_t, 32> eth_arr_256;
	eth_arr_256.fill({});
	std::copy(eth_arr_160.begin(), eth_arr_160.end(), eth_arr_256.begin() + PADDING);
	auto eth_address_256 = eosio::fixed_bytes<32>(eth_arr_256);
	return eth_address_256;
}