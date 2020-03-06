## --- contract build ---

 - How to Build -
   - cd to 'build' directory
   - run the command 'cmake ..'
   - run the command 'make'

 - After build -
   - The built smart contract is under the 'eos_evm' directory in the 'build' directory
   - You can then do a 'set contract' action with 'cleos' and point in to the './build/eos_evm' directory

 - Additions to CMake should be done to the CMakeLists.txt in the './src' directory and not in the top level CMakeLists.txt
 
 
 ## Add secp256k1 to smart contract
 #### 1. build and generate file
```
 $ ./autogen.sh
 $ ./configure
```
It will generate file libsecp256k1-config.h. and file ecmult_static_context.h
 #### 2. modify file libsecp256k1-config.h. 
```
#define USE_FIELD_INV_BUILTIN 1
#define USE_SCALAR_INV_BUILTIN 1
#define USE_NUM_NONE 1
//#define USE_NUM_GMP 1 // disable  GMP
//#define HAVE_LIBGMP 1
//#define USE_ASM_X86_64 1
```
#### 3. add CMakeList.txt in src/secp256k1-eosio folder

#### 4. add lib in src/CMakeList.txt
```
add_subdirectory(secp256k1-eosio)
link_libraries(secp256k1)
```

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