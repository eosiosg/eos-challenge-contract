#!/usr/bin/env bash

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