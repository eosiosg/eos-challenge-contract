// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018-2019 The evmone Authors.
// Licensed under the Apache License, Version 2.0.
#pragma once

#include <cstdint>
#include <string>

using bytes = std::basic_string<uint8_t>;
using bytes_view = std::basic_string_view<uint8_t>;

/// Encode a byte to a hex string.
inline std::string hex(uint8_t b) noexcept
{
    static constexpr auto hex_chars = "0123456789abcdef";
    return {hex_chars[b >> 4], hex_chars[b & 0xf]};
}

/// Decodes hex encoded string to bytes.
///
/// Exceptions:
/// - std::length_error when the input has invalid length (must be even).
/// - std::out_of_range when invalid hex digit encountered.
bytes from_hex(std::string_view hex){
  if (hex.length() % 2 == 1) {}
//	throw std::length_error{"the length of the input is odd"};

  bytes bs;
  bs.reserve(hex.length() / 2);
  int b = 0;
  for (size_t i = 0; i < hex.size(); ++i)
  {
	const auto h = hex[i];
	int v;
	if (h >= '0' && h <= '9')
	  v = h - '0';
	else if (h >= 'a' && h <= 'f')
	  v = h - 'a' + 10;
	else if (h >= 'A' && h <= 'F')
	  v = h - 'A' + 10;
//	else
//	  throw std::out_of_range{"not a hex digit"};

	if (i % 2 == 0)
	  b = v << 4;
	else
	  bs.push_back(static_cast<uint8_t>(b | v));
  }
  return bs;
}

/// Encodes bytes as hex string.
std::string hex(bytes_view bs) {
  std::string str;
  str.reserve(bs.size() * 2);
  for (auto b : bs)
	str += hex(b);
  return str;
}

/// Decodes the hexx encoded string.
///
/// The hexx encoding format is the hex format (base 16) with the extension
/// for run-length encoding. The parser replaces expressions like
///     `(` <num_repetitions> `x` <element> `)`
/// with `<element>` repeated `<num_repetitions>` times.
/// E.g. `(2x1d3)` is `1d31d3` in hex.
///
/// @param hexx  The hexx encoded string.
/// @return      The decoded bytes.
//bytes from_hexx(const std::string& hexx) {
//  const auto re = std::regex{R"(\((\d+)x([^)]+)\))"};
//
//  auto hex = hexx;
//  auto position_correction = size_t{0};
//  for (auto it = std::sregex_iterator{hexx.begin(), hexx.end(), re}; it != std::sregex_iterator{};
//	   ++it)
//  {
//	auto num_repetitions = std::stoi((*it)[1]);
//	auto replacement = std::string{};
//	while (num_repetitions-- > 0)
//	  replacement += (*it)[2];
//
//	const auto pos = static_cast<size_t>(it->position()) + position_correction;
//	const auto length = static_cast<size_t>(it->length());
//	hex.replace(pos, length, replacement);
//	position_correction += replacement.length() - length;
//  }
//  return from_hex(hex);
//}
