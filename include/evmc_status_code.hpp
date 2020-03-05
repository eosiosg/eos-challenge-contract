//
// Created by Yu Yang Zhang on 3/5/20.
//

#ifndef TEST_CONTRACT_EVMC_STATUS_CODE_HPP
#define TEST_CONTRACT_EVMC_STATUS_CODE_HPP

//enum evmc_status_code
//{
//	/** Execution finished with success. */
//	EVMC_SUCCESS = 0,
//
//	/** Generic execution failure. */
//	EVMC_FAILURE = 1,
//
//	/**
//	 * Execution terminated with REVERT opcode.
//	 *
//	 * In this case the amount of gas left MAY be non-zero and additional output
//	 * data MAY be provided in ::evmc_result.
//	 */
//	EVMC_REVERT = 2,
//
//	/** The execution has run out of gas. */
//	EVMC_OUT_OF_GAS = 3,
//
//	/**
//	 * The designated INVALID instruction has been hit during execution.
//	 *
//	 * The EIP-141 (https://github.com/ethereum/EIPs/blob/master/EIPS/eip-141.md)
//	 * defines the instruction 0xfe as INVALID instruction to indicate execution
//	 * abortion coming from high-level languages. This status code is reported
//	 * in case this INVALID instruction has been encountered.
//	 */
//	EVMC_INVALID_INSTRUCTION = 4,
//
//	/** An undefined instruction has been encountered. */
//	EVMC_UNDEFINED_INSTRUCTION = 5,
//
//	/**
//	 * The execution has attempted to put more items on the EVM stack
//	 * than the specified limit.
//	 */
//	EVMC_STACK_OVERFLOW = 6,
//
//	/** Execution of an opcode has required more items on the EVM stack. */
//	EVMC_STACK_UNDERFLOW = 7,
//
//	/** Execution has violated the jump destination restrictions. */
//	EVMC_BAD_JUMP_DESTINATION = 8,
//
//	/**
//	 * Tried to read outside memory bounds.
//	 *
//	 * An example is RETURNDATACOPY reading past the available buffer.
//	 */
//	EVMC_INVALID_MEMORY_ACCESS = 9,
//
//	/** Call depth has exceeded the limit (if any) */
//	EVMC_CALL_DEPTH_EXCEEDED = 10,
//
//	/** Tried to execute an operation which is restricted in static mode. */
//	EVMC_STATIC_MODE_VIOLATION = 11,
//
//	/**
//	 * A call to a precompiled or system contract has ended with a failure.
//	 *
//	 * An example: elliptic curve functions handed invalid EC points.
//	 */
//	EVMC_PRECOMPILE_FAILURE = 12,
//
//	/**
//	 * Contract validation has failed (e.g. due to EVM 1.5 jump validity,
//	 * Casper's purity checker or ewasm contract rules).
//	 */
//	EVMC_CONTRACT_VALIDATION_FAILURE = 13,
//
//	/**
//	 * An argument to a state accessing method has a value outside of the
//	 * accepted range of values.
//	 */
//	EVMC_ARGUMENT_OUT_OF_RANGE = 14,
//
//	/**
//	 * A WebAssembly `unreachable` instruction has been hit during execution.
//	 */
//	EVMC_WASM_UNREACHABLE_INSTRUCTION = 15,
//
//	/**
//	 * A WebAssembly trap has been hit during execution. This can be for many
//	 * reasons, including division by zero, validation errors, etc.
//	 */
//	EVMC_WASM_TRAP = 16,
//
//	/** EVM implementation generic internal error. */
//	EVMC_INTERNAL_ERROR = -1,
//
//	/**
//	 * The execution of the given code and/or message has been rejected
//	 * by the EVM implementation.
//	 *
//	 * This error SHOULD be used to signal that the EVM is not able to or
//	 * willing to execute the given code type or message.
//	 * If an EVM returns the ::EVMC_REJECTED status code,
//	 * the Client MAY try to execute it in other EVM implementation.
//	 * For example, the Client tries running a code in the EVM 1.5. If the
//	 * code is not supported there, the execution falls back to the EVM 1.0.
//	 */
//	EVMC_REJECTED = -2,
//
//	/** The VM failed to allocate the amount of memory needed for execution. */
//	EVMC_OUT_OF_MEMORY = -3
//};

#include <map>
#include <string>

namespace evmc {
	std::map<int, std::string> get_evmc_status_code_map() {
		std::map<int, std::string> evmc_status_code_map;
		evmc_status_code_map.insert ( std::pair<int, std::string>(0,  "EVMC_SUCCESS") );
		evmc_status_code_map.insert ( std::pair<int, std::string>(1,  "EVMC_FAILURE") );
		evmc_status_code_map.insert ( std::pair<int, std::string>(2,  "EVMC_REVERT") );
		evmc_status_code_map.insert ( std::pair<int, std::string>(3,  "EVMC_OUT_OF_GAS") );
		evmc_status_code_map.insert ( std::pair<int, std::string>(4,  "EVMC_INVALID_INSTRUCTION") );
		evmc_status_code_map.insert ( std::pair<int, std::string>(5,  "EVMC_UNDEFINED_INSTRUCTION") );
		evmc_status_code_map.insert ( std::pair<int, std::string>(6,  "EVMC_STACK_OVERFLOW") );
		evmc_status_code_map.insert ( std::pair<int, std::string>(7,  "EVMC_STACK_UNDERFLOW") );
		evmc_status_code_map.insert ( std::pair<int, std::string>(8,  "EVMC_BAD_JUMP_DESTINATION") );
		evmc_status_code_map.insert ( std::pair<int, std::string>(9,  "EVMC_INVALID_MEMORY_ACCESS") );
		evmc_status_code_map.insert ( std::pair<int, std::string>(10, "EVMC_CALL_DEPTH_EXCEEDED") );
		evmc_status_code_map.insert ( std::pair<int, std::string>(11, "EVMC_STATIC_MODE_VIOLATION") );
		evmc_status_code_map.insert ( std::pair<int, std::string>(12, "EVMC_PRECOMPILE_FAILURE") );
		evmc_status_code_map.insert ( std::pair<int, std::string>(13, "EVMC_CONTRACT_VALIDATION_FAILURE") );
		evmc_status_code_map.insert ( std::pair<int, std::string>(14, "EVMC_ARGUMENT_OUT_OF_RANGE") );
		evmc_status_code_map.insert ( std::pair<int, std::string>(15, "EVMC_WASM_UNREACHABLE_INSTRUCTION") );
		evmc_status_code_map.insert ( std::pair<int, std::string>(16, "EVMC_WASM_TRAP") );
		evmc_status_code_map.insert ( std::pair<int, std::string>(-1, "EVMC_INTERNAL_ERROR") );
		evmc_status_code_map.insert ( std::pair<int, std::string>(-2, "EVMC_REJECTED") );
		evmc_status_code_map.insert ( std::pair<int, std::string>(-3, "EVMC_OUT_OF_MEMORY") );
		return evmc_status_code_map;
	}
}


#endif //TEST_CONTRACT_EVMC_STATUS_CODE_HPP
