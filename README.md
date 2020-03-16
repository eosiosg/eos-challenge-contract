## --- contract build ---

 - How to Build -
   - cd to 'build' directory
   - run the command 'cmake ..'
   - run the command 'make'

 - After build -
   - The built smart contract is under the 'eos_evm' directory in the 'build' directory
   - You can then do a 'set contract' action with 'cleos' and point in to the './build/eos_evm' directory

 - Additions to CMake should be done to the CMakeLists.txt in the './src' directory and not in the top level CMakeLists.txt
 
## Add evmone as static library


## Add ethash and keccak lib to smart contract
#### 1. clone ethash
```
git clone https://github.com/chfast/ethash
```
#### 2. add lib to CMakeList.txt
```
add_subdirectory(ethash)
link_libraries(ethash)
link_libraries(keccak)
```

## Add intx to smart contract
#### Add intx source code to include folder directy to build with smart contract
