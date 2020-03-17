// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018-2019 The evmone Authors.
// Licensed under the Apache License, Version 2.0.
#pragma once

#include <cstdint>
#include <string>
#include <intx.hpp>

using bytes = std::basic_string<uint8_t>;
using bytes_view = std::basic_string_view<uint8_t>;
typedef eosio::checksum160   eth_addr_160;
typedef eosio::checksum256   eth_addr_256;
typedef std::vector<uint8_t> binary_code;
typedef std::string          hex_code;
typedef eosio::checksum256   uint256_checksum;

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

std::string BytesToHex(const std::vector<uint8_t> &input)
{
	static const char characters[] = "0123456789ABCDEF";

	// Zeroes out the buffer unnecessarily, can't be avoided for std::string.
	std::string ret(input.size() * 2, 0);

	// Hack... Against the rules but avoids copying the whole buffer.
	char *buf = const_cast<char *>(ret.data());

	for (const auto &oneInputByte : input)
	{
		*buf++ = characters[oneInputByte >> 4];
		*buf++ = characters[oneInputByte & 0x0F];
	}
	return ret;
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

uint64_t uint_from_vector(std::vector<uint8_t> v, const char *label) {
	eosio::check(v.size() <= 8, "uint from vector size too large");

	uint64_t u = 0;
	for (size_t i = 0; i < v.size(); i++) {
		u = u << 8;
		u += v[i];
	}

	return u;
}

void to_evmc_uint256be(uint64_t val, evmc_uint256be *ret) {
  uint8_t mask = 0xff;
  for (size_t i = 0; i < sizeof(evmc_uint256be); i++) {
	uint8_t byte = val & mask;
	ret->bytes[sizeof(evmc_uint256be) - i - 1] = byte;  // big endian order
	val = val >> 8;
  }
}

/** Converts the given evmc_uint256be into a uint64_t, if the value of
    @val is more than 2^64 then return value will simply contain the
    lower 8 bytes of @val
*/
uint64_t from_evmc_uint256be(const evmc_uint256be *val) {
	const size_t offset = sizeof(evmc_uint256be) - sizeof(uint64_t);
	uint64_t ret = 0;
	for (size_t i = 0; i < sizeof(uint64_t); i++) {
		ret = ret << 8;
		ret |= val->bytes[i + offset];
	}
	return ret;
}

eosio::checksum256 evmc_uint256_to_checksum256(evmc_uint256be value) {
	std::array<uint8_t, 32> eth_address_arr;
	eth_address_arr.fill({});
	std::copy_n(&value.bytes[0], sizeof(evmc_uint256be), eth_address_arr.begin());
	eth_addr_256 eth_address = eosio::fixed_bytes<32>(eth_address_arr);
	return eth_address;
}

eosio::checksum256 evmc_address_to_checksum256(const evmc_address &address) {
	std::array<uint8_t, 32> eth_address_arr;
	eth_address_arr.fill({});
	std::copy_n(&address.bytes[0], sizeof(evmc_address), eth_address_arr.begin()+PADDING);
	eth_addr_256 eth_address_256 = eosio::fixed_bytes<32>(eth_address_arr);
	return eth_address_256;
}

eosio::checksum160 evmc_address_to_checksum160(const evmc_address &address) {
	std::array<uint8_t, 20> eth_address_arr;
	eth_address_arr.fill({});
	std::copy_n(&address.bytes[0], sizeof(evmc_address), eth_address_arr.begin());
	eth_addr_160 eth_address_160 = eosio::fixed_bytes<20>(eth_address_arr);
	return eth_address_160;
}

evmc_address checksum160_to_evmc_address(const eth_addr_160 &address) {
	evmc_address evmc_address;
	auto address_arr_160 = address.extract_as_byte_array();
	std::copy(address_arr_160.begin(), address_arr_160.end(), &evmc_address.bytes[0]);
	return evmc_address;
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

eth_addr_160 eth_addr_256_to_eth_addr_160(const eth_addr_256 &eth_address_256) {
    auto eth_arr_256 = eth_address_256.extract_as_byte_array();
    std::array<uint8_t, 20> eth_arr_160;
    eth_arr_160.fill({});
    std::copy(eth_arr_256.begin()+PADDING, eth_arr_256.end(), eth_arr_160.begin());
    auto eth_address_160 = eosio::fixed_bytes<20>(eth_arr_160);
    return eth_address_160;
}

intx::uint256 uint256_from_vector(const uint8_t* begin, size_t size = 32) {
	eosio::check(size <= 32, "size too large for put into uint256");

	if (size == 32) {
		return intx::be::unsafe::load<intx::uint256>(begin);
	}
	else {
		uint8_t arr[32] = {};
		const auto offset = 32 - size;
		memcpy(arr + offset, begin, size);

		return intx::be::load<intx::uint256>(arr);
	}
}