# EOSEVM - Running Solidity Smart Contract on EOS

## Description
Some of features of EOSEVM include: 

1. Running solidity smart contract on EOSIO
2. Simulate an EVM Interpreter in EOSIO smart contract and execute EVM transactions as faithfully to the Ethereum Yellow Paper as possible
3. Connect to EVMC, replace the EVMs any time and without efforts, same for evmjit and ewasm
4. Create account in two ways. One is ETH address associate EOS account uniquely, the other is native ETH address which user must own private key
5. Verify signature in two ways. Similar to account creation, one is EOS associate account **reqiure_auth**, the other is native ETH address recover.
6. Persist Solidity smart contract data with native EOSIO multi-index. Revert **dirty state** if vm execution failed.
7. Gas free. Maintain whole gas system to calculate gas, and force set gas price = 0. 
8. Simulate transaction execution in API node.

## EOSEVM Challenge Solution and Implementation

### Requirement 1: 
```
The Application MUST persist an “Account Table” consisting of

A unique 160bit account ID
A nonce (sequence number)
An EOSIO token balance (aka SYS)
[optional] A unique associated EOSIO account
```
### Solution 1:
- 160bit ETH address ID generated by the rightmost 160 bits of the Keccak hash of the RLP encoding of the structure containing only the EOSIO account name and the arbitrary input string
- Nonce represented by **uint256_t** is consistent with go-ethereum
- Balance represented by uint256\_t alise type of eosio::checksum256. Balance is recorded as uint256_t instead of asset because native Wei has 18 digits after the decimal point and can not represent with asset in some cases
- Two types of ETH address
	- native ETH address, the user must have ETH private key. field leaves blank
	- EOS associate fake ETH address, the user do not have ETH private key. The field will be set EOS account **compulsory**.

### Implementation 1:
```c
struct [[eosio::table("eos_evm")]] st_account {
	uint64_t           id;
	eth_addr_160       eth_address;
	uint256_t          nonce;
	uint256_t          balance;
	name               eosio_account;
};
```

### Requirement 2: 
```
The Application MUST persist an “Account State Table” per account, if it would not be empty, consisting of

A unique 256bit key
A 256bit value
```
### Solution 2:
- The EVM smart contract data persistence in account state table as a key-value database.
- The EVMC host function **get storage**, **set storage** hook multi-index with solidity smart contract

### Implementation 2:
```c
struct [[eosio::table("eos_evm")]] st_account_state {
	uint64_t           id;
	uint256_t          key;
	uint256_t          value;
};
```

### Requirement 3:
```
The Application MUST persist an “Account Code Table” per account, if it would not be empty, consisting of

EVM bytecode associated with the account
```

### Solution 3:
- The application store account code as a vector of uint8_t to account code table

### Implementation 3:

```c
struct [[eosio::table("eos_evm")]] st_account_code {
	uint64_t             id;
	eth_addr_160         eth_address;
	std::vector<uint8_t> bytecode;
};
```

### Requirement 4: 

```
The Application MUST execute EVM transactions as faithfully to the Ethereum Yellow Paper as possible with the following notes:

There will be no effective BLOCK gas limit. Instructions that return block limit should return a sufficiently large supply
The TRANSACTION gas limit will be enforced
The sender WILL NOT be billed for the gas, the gas price MAY, therefore, be locked at some suitable value
All other gas mechanics/instructions should be maintained
Block number and timestamp should represent the native EOSIO block number and time
Block hash, coinbase, and difficulty should return static values
```
### Solution 4:

1. Block gas limit is large supply which set at MAX_UINT64
2. Transaction gas limit decoded from raw transaction will be enforced, if reach the gas limitation, VM execute result will be OUT\_OF\_GAS
3. Gas price is forced set to 0 to make sure **Gas fee = gas * gas price = 0**
4. Gas includes two parts in implementation. **gas usage = intrinsic gas + VM execution gas**. 

	- The intrisinc gas also include two parts 
		- **base gas**, base gas also have two kinds. if message call, **TxGas = 21000** if contract creation, **TxGasContractCreation = 53000**
		- **data gas**, [the "intrinsic gas" fee for data is 4 gas per zero byte and 68 gas per nonzero byte](https://github.com/ethereum/wiki/wiki/Design-Rationale#gas-and-fees)

	- VM execution gas maintenance
		- VM execution gas consumption calculated along with opcodes execution
  
  
5. - Use EOSIO intrinsic function to represent Block number
   - Use EOSIO time_point represent block timestamp information
   
6.  Block hash, coinbase, and difficulty return static values


### Implementation 4

- The application provides gas manager to **intrinsic\_gas**, **buy\_gas**,  **refund\_gas**, **use\_gas** to make sure gas calculation is correct


### Requirement 5: 

```
The Application MUST implement an action named “raw”

Whose inputs are
A binary Ethereum transaction encoded as it appears in a serialized Ethereum block
[optional] A 160bit account identifier “Sender”
Which results in
Appropriate Updates to Account, Account State, and Account Code Tables reflecting the application of the transaction
Log output (via EOSIO print intrinsics)
IF the “R” and “S” values of the transaction are NOT 0
A transaction containing this action must fail if the signature (V, R, S) within the input does not recover to a valid and known 160bit account identifier in the Accounts Table
IF the “R” and “S” values of the transaction are 0
A transaction containing this action must fail if “Sender” input parameter is not present or does not refer to a valid and known 160bit account identifier in the Accounts Table
If the associated entry in the Accounts Table has no Associated EOSIO Account
OR if the transaction has not been authorized by the Associated EOSIO Account
```

### Solution 5:

1. Raw action first param transaction_code is **A binary Ethereum transaction encoded with RLP algorithm** which contains 

	- 5 fields nonce, gasPrice, gasLimit, to, value
	- or 8 fields nonce, gasPrice, gasLimit, to, value and signature related v,r,s

	if 5 fields, means **no ETH signature**, the second param must be the 160bit ETH address sender. if 8 fields, means has ETH signature. 

2. IF the “R” and “S” values of the transaction are NOT 0, it means RLP decoded transaction has 8 fields include the signature v, r, s. Then the application chooses to recover ETH address from signature fields. And check if recovered ETH address in account table to verify the signature
3. IF the “R” and “S” values of the transaction are 0, it means RLP decoded transaction has 5 fields. Then the application chooses to use EOS intrinsic function **require\_auth** to verify the ETH address(the second param) associate EOSIO account signature. 

From this point of view, speculate **two kinds** of account type in **account table**.
	
- **native ETH address**, the user must have ETH private key
- **EOS associate fake ETH address**, user does not have ETH private key

3. From [Byzantium revision](https://eips.ethereum.org/EIPS/eip-140), the EVM smart contract support **revert**. Need to revert all state changes in **account state table**. The application provide a solution to record history of **setting storage**. If vm execution result != EVMC_SUCCESS, It will roll back all multi-index change base on the history storage status.
	- if EVMC_STORAGE_ADDED, it will to erase record
	- if EVMC_STORAGE_MODIFIED or EVMC_STORAGE_MODIFIED_AGAIN need to update to origin record
	- if EVMC_STORAGE_DELETED need to emplace in multi-index

### Implementation 5

```c
[[eosio::action]]
void raw(const hex_code &trx_code, const binary_extension<eth_addr_160> &sender);
```

- RLP decode trx\_code with field **nonce, gasPrice, gasLimit, to, value, and signature related v,r,s**
- Two types of **signature verification**, differentiate by if trx\_code has field **v, r, s**. if exist, recover native ETH address. if not, **require\_auth** with **second param sender** associated EOS account
- Two types of **action types** in raw action. There are two types of action in ETH transaction shown in ETH yellow paper differentiate by trx\_code **to** field.
   	       
	- **contract creation**, evm execution result data is **evm code body**. Generate contract address with **keccak(RLP(ETH sender + nonce))**, deploy contract to contract address
	- **message call**, get contract **evm code** from account code table, parse message data from trx\_code and fill into VM to execute, evm execution result data is as the case may be.
   	   
- Gas calculation. maintain native gas system include **intrinsic gas** and **vm gas** usage. Buy gas and refund gas also avalible.
- Value transfer. If value != 0, transfer value from **sender** to **to** address.
- If vm execution result != EVMC_SUCCESS. Then need to revert dirty storage
	- if EVMC_STORAGE_ADDED need to erase
	- if EVMC_STORAGE_MODIFIED or EVMC_STORAGE_MODIFIED_AGAIN need to update to origin
	- if EVMC_STORAGE_DELETED need to emplace
- Print vm receipt in **JSON** format and parse easily in JS client

### Requirement 6: 

```   
The Application MUST implement an action named “create”

Whose inputs are
An EOSIO account
An arbitrary-length string
Which results in a new Account Table entry with
Balance = 0
Nonce = 1
Account identifier = the rightmost 160 bits of the Keccak hash of the RLP encoding of the structure containing only the EOSIO account name and the arbitrary input string
A transaction containing this action must fail if it is not authorized by the EOSIO account listed in the inputs
A transaction containing this action must fail if an Account Table entry exists with this EOSIO account associated
```

### Solution 6:

1. Create action is create 160 bits ETH address. Speculate two kinds of ETH address type from the raw action interpretation.

	- **native ETH address**, the user must have ETH private key
	- **EOS associate fake ETH address**, user do not have ETH private key

2. Balance represented by **uint256_t** alias type of eosio::checksum256. Balance is recorded as **uint256_t** instead of **asset** because **native Wei** has **18 digits after the decimal point** and can not represent with asset in some cases
3. Nonce represented by **uint256_t** is consistent with go-ethereum

### Implementation 6:

```c
[[eosio::action]]
void create(const name &eos_account, const binary_extension<std::string> &eth_address);
```

- If the second param has **160 bits**, then set ETH address directly with this param value in account table
- If the second param arbitrary length string, then generate a fake ETH address which user does not have the private key with above **RLP algorithm**


### Requirement 7: 

```
The Application MUST respond to EOSIO token transfers

Provided that the EOSIO account in the “from” field of the transfer maps to a known and valid Account Table entry through the entry’s unique associated EOSIO account
Transferred tokens should be added to the Account Table entry’s balance
```

### Solution 7:

1. ontransfer action will be notified when **linked token contract** transfer action is triggered
2. Add balance to account table entry. The EOS token sender must be associate EOS account record in account table
3. The asset precision formally **sym_precision**. Native ETH Wei is **18 digits after the decimal point**. Transit asset amount to Wei, 

	**Wei = amount \* 10 ^ (18 - sym_precision)**
	
### Implementation 7:
```c
[[eosio::on_notify("*::transfer")]]
void ontransfer(const name &from, const name &to, const asset &quantity, const std::string memo);
```

- use **[[eosio::on_notify("\*::transfer")]]** to be notified. Make sure from account not in previleged accounts list **eosio.bpay**, **eosio.names**, **eosio.ram**, **eosio.ramfee**, **eosio.saving**, **eosio.stake**, **eosio.vpay** 

### Requirement 8:
 
```
The Application MUST implement an action named “withdraw”

Whose inputs are
An EOSIO account
A token amount
Which results in
Deducting the amount from the associated Account Table entry’s balance
Sending an inline EOSIO token transfer for the amount to the EOSIO account
A transaction containing this action must fail if it is not authorized by the EOSIO account listed in the inputs OR if such a withdrawal would leave the Account Table entry’s balance negative
```

### Solution 8:

1. The withdraw action will send back the native token to EOS associate account.

### Implementation 8:

```c
[[eosio::action]]
void withdraw(const name &eos_account, const asset &amount);
```

1. The withdraw action will push an **inline action** for send correspond to amount of token
2. The application need to **updateauth** to eosio.code


### Requirement 9:
```
The Application MUST implement some method of specifying the “CHAIN_ID” for EIP-155 compatibility.

This MAY be done at compile time
This MAY be done with an additional initialization action
```

### Solution 9:

- [EIP-155](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md) is a hard fork at block number: 2,675,000 in ETH.  v = CHAIN\_ID * 2 + 35 or v = CHAIN\_ID * 2 + 36 when CHAIN\_id = 1, v = 37 or 38. 
- The application only support EIP-155 rules **signature recover**


### Additional actions
1. simulate action

	- Explanation
	 - Mock API node to send a non-state transaction. Such as check account balance, allowance in ERC20. 

	- Implementation

	```c
	[[eosio::action]]
	void simulate(const hex_code &trx_code, const binary_extension<eth_addr_160> &sender);
	```
	 - execute same logic with raw action
	 - always assertion failure
	 - JS client can get transaction **JSON receipt** in **assertion failure pending output console**

2. link token

	- record configurable **singleton** extended_symbol in token contract

	- Explanation
		- record **singleton** extended_symbol in token contract as native **'ether token'** for value transfer and gas fee payment (even though gas price is forced set to 0)

	- Implementation
	
	```c
	[[eosio::action]]
	void linktoken(const extended_symbol &contract);
	```


3. log action
	- log receipt information, include EVM execution result, output, data, signature information, gas price, gas usage, emit_logs.


	- Explanation
		- user can check detail EVM execution receipt on chain

	- Implementation
		- send and inline transaction recorded on the blockchain

	```c
	[[eosio::action]]
	void log(const std::string &status_code, 
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
	 const std::string &eth_emit_logs
	);
	```
