#!/usr/bin/env bash

set -v

# create system account
SYSTEM_ACCOUNT="eosio.bpay eosio.msig eosio.names eosio.ram eosio.ramfee eosio.saving eosio.stake eosio.token eosio.vpay"

for sa in $SYSTEM_ACCOUNT
do
    echo $sa
    cleos -u $remote create account eosio $sa EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV -p eosio
done

cleos -u $remote set contract eosio.token ../${systemContract}/eosio.token eosio.token.wasm eosio.token.abi -p eosio.token

cleos -u $remote push action eosio.token create '["eosio", "10000000000.0000 EOS", 0, 0, 0]' -p eosio.token
cleos -u $remote push action eosio.token issue '["eosio", "1000000000.0000 EOS", "issue 1B to eosio"]' -p eosio

# deploy system contract
cleos -u $remote set contract eosio ../${systemContract}/eosio.system eosio.system.wasm eosio.system.abi -p eosio

cleos -u ${remote} system newaccount eosio eosevm111111 EOS54HgSQ9d6qjUT7pEZgbP83zQpcymR4QW1jz2jPDEdbAeKGaUif EOS54HgSQ9d6qjUT7pEZgbP83zQpcymR4QW1jz2jPDEdbAeKGaUif --stake-cpu "1000 EOS" --stake-net "1000 EOS" --buy-ram "1000 EOS" -p eosio
cleos -u ${remote} transfer eosio ${contract} "1000.0000 EOS" -p eosio
cleos -u ${remote} system newaccount eosio eosevm11111b EOS54HgSQ9d6qjUT7pEZgbP83zQpcymR4QW1jz2jPDEdbAeKGaUif EOS54HgSQ9d6qjUT7pEZgbP83zQpcymR4QW1jz2jPDEdbAeKGaUif --stake-cpu "1000 EOS" --stake-net "1000 EOS" --buy-ram "1000 EOS" -p eosio
cleos -u ${remote} transfer eosio ${accountb} "1000.0000 EOS" -p eosio
cleos -u ${remote} system newaccount eosio eosevm11111c EOS54HgSQ9d6qjUT7pEZgbP83zQpcymR4QW1jz2jPDEdbAeKGaUif EOS54HgSQ9d6qjUT7pEZgbP83zQpcymR4QW1jz2jPDEdbAeKGaUif --stake-cpu "1000 EOS" --stake-net "1000 EOS" --buy-ram "1000 EOS" -p eosio
cleos -u ${remote} transfer eosio ${accountc} "1000.0000 EOS" -p eosio
cleos -u ${remote} system newaccount eosio eosevm11111d EOS54HgSQ9d6qjUT7pEZgbP83zQpcymR4QW1jz2jPDEdbAeKGaUif EOS54HgSQ9d6qjUT7pEZgbP83zQpcymR4QW1jz2jPDEdbAeKGaUif --stake-cpu "1000 EOS" --stake-net "1000 EOS" --buy-ram "1000 EOS" -p eosio
cleos -u ${remote} transfer eosio ${accountd} "1000.0000 EOS" -p eosio


cleos -u ${remote} set contract ${contract}  ../${buildfolder}/eos_evm -p ${contract}

cleos -u ${remote} push action ${contract} linktoken '[{"sym":"4,EOS", "contract":"eosio.token"}]' -p ${contract}
cleos -u $remote push action eosio updateauth '['"${contract}"',"active","owner",
{"threshold":1,"keys":[{"key":"EOS54HgSQ9d6qjUT7pEZgbP83zQpcymR4QW1jz2jPDEdbAeKGaUif","weight":1}],
"waits":[],"accounts":[{"weight":1,"permission":{"actor":'"${contract}"',"permission":"eosio.code"}}]}]' -p ${contract}

# create account
cleos -u ${remote} push action ${contract} create '['"${accountb}"', "aaaaaa"]' -p ${accountb}
cleos -u ${remote} push action ${contract} create '['"${accountb}"', d81f4358cb8cab53d005e7f47c7ba3f5116000a6]' -p ${accountb}
cleos -u ${remote} push action ${contract} create '['"${accountc}"', "aaaaaa"]' -p ${accountc}
cleos -u ${remote} push action ${contract} create '['"${accountc}"', 39944247c2edf660d86d57764b58d83b8eee9014]' -p ${accountc}
cleos -u ${remote} push action ${contract} create '['"${accountd}"', "aaaaaa"]' -p ${accountd}
cleos -u ${remote} push action ${contract} create '['"${accountd}"', e327e755438fbdf9e60891d9b752da10a38514d1]' -p ${accountd}