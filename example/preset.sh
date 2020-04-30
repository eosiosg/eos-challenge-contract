#!/usr/bin/env bash

set -v

cleos wallet import --private-key 5KMgea7s31sAAj8pEZeKmZXvzSo6spxtwmfUibckVmNwN7e44d4
cleos wallet import --private-key 5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3

# create system account
SYSTEM_ACCOUNT="eosio.bpay eosio.msig eosio.names eosio.ram eosio.ramfee eosio.saving eosio.stake eosio.token eosio.vpay"

for sa in $SYSTEM_ACCOUNT
do
    echo $sa
    cleos -u $remote create account eosio $sa EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV -p eosio
done

cleos -u $remote set contract eosio.token ${systemContract}/eosio.token eosio.token.wasm eosio.token.abi -p eosio.token

cleos -u $remote push action eosio.token create '["eosio", "10000000000.0000 EOS", 0, 0, 0]' -p eosio.token
cleos -u $remote push action eosio.token issue '["eosio", "1000000000.0000 EOS", "issue 1B to eosio"]' -p eosio

# deploy system contract
cleos -u $remote set contract eosio ${systemContract}/eosio.system eosio.system.wasm eosio.system.abi -p eosio


cleos -u ${remote} system newaccount eosio eosevm111111 EOS7bSJkk2bC3nn7ME2Xv2Uf6ossmQU1zKvmvwmTc7gaH8ZcGGy62 EOS7bSJkk2bC3nn7ME2Xv2Uf6ossmQU1zKvmvwmTc7gaH8ZcGGy62 --stake-cpu "1000 EOS" --stake-net "1000 EOS" --buy-ram "1000 EOS" -p eosio
cleos -u ${remote} transfer eosio ${contract} "1000.0000 EOS" -p eosio
cleos -u ${remote} system newaccount eosio eosevm11111b EOS7bSJkk2bC3nn7ME2Xv2Uf6ossmQU1zKvmvwmTc7gaH8ZcGGy62 EOS7bSJkk2bC3nn7ME2Xv2Uf6ossmQU1zKvmvwmTc7gaH8ZcGGy62 --stake-cpu "1000 EOS" --stake-net "1000 EOS" --buy-ram "1000 EOS" -p eosio
cleos -u ${remote} transfer eosio ${accountb} "1000.0000 EOS" -p eosio
cleos -u ${remote} system newaccount eosio eosevm11111c EOS7bSJkk2bC3nn7ME2Xv2Uf6ossmQU1zKvmvwmTc7gaH8ZcGGy62 EOS7bSJkk2bC3nn7ME2Xv2Uf6ossmQU1zKvmvwmTc7gaH8ZcGGy62 --stake-cpu "1000 EOS" --stake-net "1000 EOS" --buy-ram "1000 EOS" -p eosio
cleos -u ${remote} transfer eosio ${accountc} "1000.0000 EOS" -p eosio
cleos -u ${remote} system newaccount eosio eosevm11111d EOS7bSJkk2bC3nn7ME2Xv2Uf6ossmQU1zKvmvwmTc7gaH8ZcGGy62 EOS7bSJkk2bC3nn7ME2Xv2Uf6ossmQU1zKvmvwmTc7gaH8ZcGGy62 --stake-cpu "1000 EOS" --stake-net "1000 EOS" --buy-ram "1000 EOS" -p eosio
cleos -u ${remote} transfer eosio ${accountd} "1000.0000 EOS" -p eosio

