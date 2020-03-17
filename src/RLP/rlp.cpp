// RLP Encoding, as defined: https://github.com/ethereum/wiki/wiki/RLP

#include "rlp.hpp"

#include <assert.h>
#include <algorithm>
#include <memory>
#include <string>
#include <vector>

void RLPBuilder::add_size(size_t size, uint8_t type_byte_short,
                          uint8_t type_byte_long) {
  if (size < 56) {
    buffer.push_back(type_byte_short + size);
  } else {
    // Long lists require a byte indicating the length of the length
    uint8_t field_length_count = 0;
    do {
      ++field_length_count;
      buffer.push_back(size & 0xff);
      size >>= 8;
    } while (size > 0);
    buffer.push_back(type_byte_long + field_length_count);
  }
}

void RLPBuilder::add_string_size(size_t size) { add_size(size, 0x80, 0xb7); }

void RLPBuilder::add_list_size(size_t size) { add_size(size, 0xc0, 0xf7); }

void RLPBuilder::add(const std::vector<uint8_t> &vec) {
  assert(!finished);
  std::reverse_copy(vec.begin(), vec.end(), std::back_inserter(buffer));
  add_string_size(vec.size());
}

inline std::vector<uint8_t> uint256_to_byte(const intx::uint256 &n)
{
	std::vector<uint8_t> vec;
	if (n != 0) {
		uint8_t arr[32] = {};
		intx::be::store(arr, n);

		const auto n_bytes = intx::count_significant_words<uint8_t>(n);
		vec.resize(n_bytes);

		std::memcpy(vec.data(), arr + 32 - n_bytes, n_bytes);
	}
	return vec;
}

void RLPBuilder::add(const intx::uint256 &number) {
	assert(!finished);
	if (number <= 0x7f) {
		buffer.push_back((uint8_t)number);
	} else {
		std::vector<uint8_t> number_vec = uint256_to_byte(number);
		std::reverse_copy(number_vec.begin(), number_vec.end(), std::back_inserter(buffer));
		add_string_size(number_vec.size());
	}
}

void RLPBuilder::add(const uint8_t *data, size_t size) {
  assert(!finished);
  if (size == 1 && data[0] <= 0x7f) {
    buffer.push_back(data[0]);
  } else {
    std::reverse_copy(data, data + size, std::back_inserter(buffer));
    add_string_size(size);
  }
}

void RLPBuilder::add(const std::string &str) {
  assert(!finished);
  std::reverse_copy(str.begin(), str.end(), std::back_inserter(buffer));
  add_string_size(str.size());
}

void RLPBuilder::add(const evmc_address &address) {
  assert(!finished);
  add(address.bytes, sizeof(evmc_address));
}

void RLPBuilder::add(const evmc_uint256be &uibe) {
  assert(!finished);
  add(uibe.bytes, sizeof(evmc_uint256be));
}

void RLPBuilder::add(uint64_t number) {
  assert(!finished);
  if (number == 0) {
    // "0" is encoded as "empty string" here, not "integer zero"
    std::vector<uint8_t> empty_value;
    add(empty_value);
  } else {
    if (number <= 0x7f) {
      buffer.push_back((uint8_t)number);
    } else {
      uint8_t length = 0;
      do {
        ++length;
        buffer.push_back(number & 0xff);
        number >>= 8;
      } while (number > 0);
      add_string_size(length);
    }
  }
}

void RLPBuilder::start_list() {
  assert(!finished);
  assert(list_depth < MAX_LIST_DEPTH - 1);
  list_start[++list_depth] = buffer.size();
}

void RLPBuilder::end_list() {
  assert(!finished);
  assert(list_depth >= 0);
  add_list_size(buffer.size() - list_start[list_depth]);
  --list_depth;
}

// Closes any open lists, then reverses and returns the buffer.
std::vector<uint8_t> &&RLPBuilder::build() {
  assert(!finished);
  while (list_depth >= 0) {
    end_list();
  }
  std::reverse(buffer.begin(), buffer.end());
  finished = true;
  return std::move(buffer);
}

bool RLPParser::at_end() { return offset == rlp_.size(); }

std::vector<uint8_t> RLPParser::next() {
  if (rlp_[offset] < 0x80) {
    std::vector<uint8_t> simple;
    simple.push_back(rlp_[offset]);
    offset++;
    return simple;
  } else if (rlp_[offset] < 0xb8) {
    size_t length = rlp_[offset] - 0x80;
    offset++;
    return short_run(length);
  } else if (rlp_[offset] < 0xc0) {
    size_t length_length = rlp_[offset] - 0xb7;
    offset++;
    return long_run(length_length);
  } else if (rlp_[offset] < 0xf8) {
    size_t length = rlp_[offset] - 0xc0;
    offset++;
    return short_run(length);
  } else {
    size_t length_length = rlp_[offset] - 0xf7;
    offset++;
    return long_run(length_length);
  }
}

std::vector<uint8_t> RLPParser::short_run(size_t length) {
  std::vector<uint8_t> short_string;
  if (length > 0) {
    std::copy(rlp_.begin() + offset, rlp_.begin() + offset + length,
              std::back_inserter(short_string));
    offset += length;
  }
  return short_string;
}

std::vector<uint8_t> RLPParser::long_run(size_t length_length) {
  size_t length = 0;
  for (size_t i = 0; i < length_length; i++) {
    length = length << 8;
    length += rlp_[offset];
    offset++;
  }
  std::vector<uint8_t> long_string;
  std::copy(rlp_.begin() + offset, rlp_.begin() + offset + length,
            std::back_inserter(long_string));
  offset += length;
  return long_string;
}

