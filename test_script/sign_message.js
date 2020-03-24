
///ETH private key
///
///(0) d81f4358cb8cab53d005e7f47c7ba3f5116000a6 (100 ETH) bpb
///(1) 39944247c2edf660d86d57764b58d83b8eee9014 (100 ETH) bpc
///(2) e327e755438fbdf9e60891d9b752da10a38514d1 (100 ETH) bpd
///(3) 8aAFae259C494870AC4E34e9E6019788787dDd77 (100 ETH)
///(4) 37840eE7603305F5F3d8fd26d41A4C3a5d7375da (100 ETH)
///(5) eAD1a186688C5A9c967B427B632EaEFE8043B12c (100 ETH)
///(6) 713D1Ff9A73a7aC655F6F638316CBfdCf6da4B48 (100 ETH)
///(7) Cbf129e6Dd638cbc5b88C328087a6A963A73CeDd (100 ETH)
///(8) 5E9eb0EEd9B9afd8712e8611Bf5a6D593f7705Fd (100 ETH)
///(9) a64428bee004C975FFcA398673c4D6E21a057FB6 (100 ETH)
///
///Private Keys
///==================
///(0) cbb1981be330b0d97e620a61b913f678fc9c12c059a70badf92d0db317ff804f bpb
///(1) 3f04415249414ff900b464f8d588517146c4ec39a3ae9855282030fa3de3862f bpc
///(2) 9089c365c66ca5d1ea63f1a42a569326d887e680b2256fe79897a2da5aa708ea bpd
///(3) 23c29d7d2eb5078c33ec80d5c0d86bcc0a0f5b58a24ee0d5904c7dd965956efb
///(4) 9587828e1281a552977f6619e3cf540ad3344fd31d90dce44daaaed2f70683dd
///(5) 7b697d4cccd589c1d065a18f315b5a5582e97984313fc9bb013dfd458769a829
///(6) 62c0788dd9f80919ed4f44392321892228a99deb31c0ba22060060f9ccc338a9
///(7) cdc2fa8a012050cf0b3d1c2dc56fd8bb27ee74f3832627f48919977233d5fd64
///(8) 8fa52da70a645fe2daab8bcc24b523680dc6c4350985ea270cbe5d29d92fc8b0
///(9) 70458e863ddd01cbc5cb6891d399836a17f8d78a06ec6b4c12fae71352848344

/// create contract
const EthereumTx = require('ethereumjs-tx').Transaction
let privateKey = Buffer.from(
    'cbb1981be330b0d97e620a61b913f678fc9c12c059a70badf92d0db317ff804f',
    'hex',
)

txParams = {
    nonce: '0x02',
    gasPrice: '0x09184e72a000',
    gasLimit: '0x27100',
    to: '0x',
    value: '0x00',
    data: '0x6060604052341561000f57600080fd5b604051610dd1380380610dd18339810160405280805190602001909190805182019190602001805190602001909190805182019190505083600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508360008190555082600390805190602001906100a79291906100e3565b5081600460006101000a81548160ff021916908360ff16021790555080600590805190602001906100d99291906100e3565b5050505050610188565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f1061012457805160ff1916838001178555610152565b82800160010185558215610152579182015b82811115610151578251825591602001919060010190610136565b5b50905061015f9190610163565b5090565b61018591905b80821115610181576000816000905550600101610169565b5090565b90565b610c3a806101976000396000f3006060604052600436106100af576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806306fdde03146100b4578063095ea7b31461014257806318160ddd1461019c57806323b872dd146101c557806327e235e31461023e578063313ce5671461028b5780635c658165146102ba57806370a082311461032657806395d89b4114610373578063a9059cbb14610401578063dd62ed3e1461045b575b600080fd5b34156100bf57600080fd5b6100c76104c7565b6040518080602001828103825283818151815260200191508051906020019080838360005b838110156101075780820151818401526020810190506100ec565b50505050905090810190601f1680156101345780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b341561014d57600080fd5b610182600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091908035906020019091905050610565565b604051808215151515815260200191505060405180910390f35b34156101a757600080fd5b6101af610657565b6040518082815260200191505060405180910390f35b34156101d057600080fd5b610224600480803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803590602001909190505061065d565b604051808215151515815260200191505060405180910390f35b341561024957600080fd5b610275600480803573ffffffffffffffffffffffffffffffffffffffff169060200190919050506108f7565b6040518082815260200191505060405180910390f35b341561029657600080fd5b61029e61090f565b604051808260ff1660ff16815260200191505060405180910390f35b34156102c557600080fd5b610310600480803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610922565b6040518082815260200191505060405180910390f35b341561033157600080fd5b61035d600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610947565b6040518082815260200191505060405180910390f35b341561037e57600080fd5b610386610990565b6040518080602001828103825283818151815260200191508051906020019080838360005b838110156103c65780820151818401526020810190506103ab565b50505050905090810190601f1680156103f35780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b341561040c57600080fd5b610441600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091908035906020019091905050610a2e565b604051808215151515815260200191505060405180910390f35b341561046657600080fd5b6104b1600480803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610b87565b6040518082815260200191505060405180910390f35b60038054600181600116156101000203166002900480601f01602080910402602001604051908101604052809291908181526020018280546001816001161561010002031660029004801561055d5780601f106105325761010080835404028352916020019161055d565b820191906000526020600020905b81548152906001019060200180831161054057829003601f168201915b505050505081565b600081600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925846040518082815260200191505060405180910390a36001905092915050565b60005481565b600080600260008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054905082600160008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020541015801561072e5750828110155b151561073957600080fd5b82600160008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000828254019250508190555082600160008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825403925050819055507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8110156108865782600260008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825403925050819055505b8373ffffffffffffffffffffffffffffffffffffffff168573ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef856040518082815260200191505060405180910390a360019150509392505050565b60016020528060005260406000206000915090505481565b600460009054906101000a900460ff1681565b6002602052816000526040600020602052806000526040600020600091509150505481565b6000600160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b60058054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015610a265780601f106109fb57610100808354040283529160200191610a26565b820191906000526020600020905b815481529060010190602001808311610a0957829003601f168201915b505050505081565b600081600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205410151515610a7e57600080fd5b81600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000828254039250508190555081600160008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825401925050819055508273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040518082815260200191505060405180910390a36001905092915050565b6000600260008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050929150505600a165627a7a72305820c4fde1a7c25d01c2c831892bb28af4a76928a6ac10d854b6e98b38d49891c19c002900000000000000000000000000000000000000000000000000000000000027100000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000005666972737400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000054574686572000000000000000000000000000000000000000000000000000000',
}

// The second parameter is not necessary if these values are used
let tx = new EthereumTx(txParams, { chain: 'mainnet', hardfork: 'petersburg' })
tx.sign(privateKey)
serializedTx = tx.serialize()

feeCost = tx.getUpfrontCost()
console.log('Total Amount of wei needed:' + feeCost.toString())

// Lets serialize the transaction

console.log('---create contract Serialized TX----')
console.log(serializedTx.toString('hex'))
console.log('--------------------')

// len: f889
// 8086
// gas price: 09184e72a000
// 82
// gas limit 2710
// 94000000000000000000000000000000000000000080a4
// data: 7f7465737432000000000000000000000000000000000000000000000000000000600057
// v 26
//a0 e334b3350ecadf15dfe6ac58c75b386e6b5e6ef997589e62368c7c74777abd67
//a0 0ace9b8c332799dd54da03c8a44c3191b456b2f067ad575d4022d3a81e9318c7



// ----------------------------------------------------------------------------------------------
/// tranfer value

txParams = {
    nonce: '0x03',
    gasPrice: '0x09184e72a000',
    gasLimit: '0x27100',
    to: '0xcfe5e259e2c3558479db3aadbc1cb6e7c7c34548',
    value: '0x00',
    data: '0xa9059cbb00000000000000000000000039944247c2edf660d86d57764b58d83b8eee90140000000000000000000000000000000000000000000000000000000000000064',
}

// The second parameter is not necessary if these values are used
tx = new EthereumTx(txParams, { chain: 'mainnet', hardfork: 'petersburg' })
tx.sign(privateKey)
serializedTx = tx.serialize()

feeCost = tx.getUpfrontCost()
console.log('Total Amount of wei needed:' + feeCost.toString())

// Lets serialize the transaction

console.log('---transfer 39944247c2edf660d86d57764b58d83b8eee9014 100 Serialized TX----')
console.log(serializedTx.toString('hex'))
console.log('--------------------')


// ----------------------------------------------------------------------------------------------

txParams = {
    nonce: '0x04',
    gasPrice: '0x09184e72a000',
    gasLimit: '0x27100',
    to: '0xcfe5e259e2c3558479db3aadbc1cb6e7c7c34548',
    value: '0x00',
    data: '0xa9059cbb000000000000000000000000e327e755438fbdf9e60891d9b752da10a38514d100000000000000000000000000000000000000000000000000000000000001f4',
}

// The second parameter is not necessary if these values are used
tx = new EthereumTx(txParams, { chain: 'mainnet', hardfork: 'petersburg' })
tx.sign(privateKey)
serializedTx = tx.serialize()

feeCost = tx.getUpfrontCost()
console.log('Total Amount of wei needed:' + feeCost.toString())

// Lets serialize the transaction

console.log('---transfer e327e755438fbdf9e60891d9b752da10a38514d1 500 Serialized TX----')
console.log(serializedTx.toString('hex'))
console.log('--------------------')

// ----------------------------------------------------------------------------------------------



// ----------------------------------------------------------------------------------------------

txParams = {
    nonce: '0x05',
    gasPrice: '0x09184e72a000',
    gasLimit: '0x27100',
    to: '0xcfe5e259e2c3558479db3aadbc1cb6e7c7c34548',
    value: '0x00',
    data: '0x70a0823100000000000000000000000039944247c2edf660d86d57764b58d83b8eee9014',
}

// The second parameter is not necessary if these values are used
tx = new EthereumTx(txParams, { chain: 'mainnet', hardfork: 'petersburg' })
tx.sign(privateKey)
serializedTx = tx.serialize()

feeCost = tx.getUpfrontCost()
console.log('Total Amount of wei needed:' + feeCost.toString())

// Lets serialize the transaction

console.log('---balance of bpc 39944247c2edf660d86d57764b58d83b8eee9014 Serialized TX----')
console.log(serializedTx.toString('hex'))
console.log('--------------------')

// ----------------------------------------------------------------------------------------------

txParams = {
    nonce: '0x06',
    gasPrice: '0x09184e72a000',
    gasLimit: '0x27100',
    to: '0xcfe5e259e2c3558479db3aadbc1cb6e7c7c34548',
    value: '0x00',
    data: '0x70a08231000000000000000000000000e327e755438fbdf9e60891d9b752da10a38514d1',
}

// The second parameter is not necessary if these values are used
tx = new EthereumTx(txParams, { chain: 'mainnet', hardfork: 'petersburg' })
tx.sign(privateKey)
serializedTx = tx.serialize()

feeCost = tx.getUpfrontCost()
console.log('Total Amount of wei needed:' + feeCost.toString())

// Lets serialize the transaction

console.log('---balance of bpd e327e755438fbdf9e60891d9b752da10a38514d1 Serialized TX----')
console.log(serializedTx.toString('hex'))
console.log('--------------------')

// ----------------------------------------------------------------------------------------------

privateKey = Buffer.from(
    '9089c365c66ca5d1ea63f1a42a569326d887e680b2256fe79897a2da5aa708ea',
    'hex',
)

txParams = {
    nonce: '0x02',
    gasPrice: '0x09184e72a000',
    gasLimit: '0x27100',
    to: '0xcfe5e259e2c3558479db3aadbc1cb6e7c7c34548',
    value: '0x00',
    data: '0x095ea7b3000000000000000000000000e327e755438fbdf9e60891d9b752da10a38514d100000000000000000000000000000000000000000000000000000000000000c8',
}

// The second parameter is not necessary if these values are used
tx = new EthereumTx(txParams, { chain: 'mainnet', hardfork: 'petersburg' })
tx.sign(privateKey)
serializedTx = tx.serialize()

feeCost = tx.getUpfrontCost()
console.log('Total Amount of wei needed:' + feeCost.toString())

// Lets serialize the transaction

console.log('---approve  bpd approve bpc 200 Serialized TX----')
console.log(serializedTx.toString('hex'))
console.log('--------------------')

// ----------------------------------------------------------------------------------------------

privateKey = Buffer.from(
    '9089c365c66ca5d1ea63f1a42a569326d887e680b2256fe79897a2da5aa708ea',
    'hex',
)

txParams = {
    nonce: '0x03',
    gasPrice: '0x09184e72a000',
    gasLimit: '0x27100',
    to: '0xcfe5e259e2c3558479db3aadbc1cb6e7c7c34548',
    value: '0x00',
    data: '0xdd62ed3e000000000000000000000000e327e755438fbdf9e60891d9b752da10a38514d1000000000000000000000000e327e755438fbdf9e60891d9b752da10a38514d1',
}

// The second parameter is not necessary if these values are used
tx = new EthereumTx(txParams, { chain: 'mainnet', hardfork: 'petersburg' })
tx.sign(privateKey)
serializedTx = tx.serialize()

feeCost = tx.getUpfrontCost()
console.log('Total Amount of wei needed:' + feeCost.toString())

// Lets serialize the transaction

console.log('---allowance bpd approve bpc 200 Serialized TX----')
console.log(serializedTx.toString('hex'))
console.log('--------------------')

// ----------------------------------------------------------------------------------------------


privateKey = Buffer.from(
    '9089c365c66ca5d1ea63f1a42a569326d887e680b2256fe79897a2da5aa708ea',
    'hex',
)

txParams = {
    nonce: '0x04',
    gasPrice: '0x09184e72a000',
    gasLimit: '0x27100',
    to: '0xcfe5e259e2c3558479db3aadbc1cb6e7c7c34548',
    value: '0x00',
    data: '0x23b872dd000000000000000000000000e327e755438fbdf9e60891d9b752da10a38514d100000000000000000000000039944247c2edf660d86d57764b58d83b8eee90140000000000000000000000000000000000000000000000000000000000000014',
}

// The second parameter is not necessary if these values are used
tx = new EthereumTx(txParams, { chain: 'mainnet', hardfork: 'petersburg' })
tx.sign(privateKey)
serializedTx = tx.serialize()

feeCost = tx.getUpfrontCost()
console.log('Total Amount of wei needed:' + feeCost.toString())

// Lets serialize the transaction

console.log('---transfer bpd to bpc 20 Serialized TX----')
console.log(serializedTx.toString('hex'))
console.log('--------------------')

// ----------------------------------------------------------------------------------------------

txParams = {
    nonce: '0x05',
    gasPrice: '0x09184e72a000',
    gasLimit: '0x27100',
    to: '0xcfe5e259e2c3558479db3aadbc1cb6e7c7c34548',
    value: '0x00',
    data: '0x70a0823100000000000000000000000039944247c2edf660d86d57764b58d83b8eee9014',
}

// The second parameter is not necessary if these values are used
tx = new EthereumTx(txParams, { chain: 'mainnet', hardfork: 'petersburg' })
tx.sign(privateKey)
serializedTx = tx.serialize()

feeCost = tx.getUpfrontCost()
console.log('Total Amount of wei needed:' + feeCost.toString())

// Lets serialize the transaction

console.log('---balance of bpc 39944247c2edf660d86d57764b58d83b8eee9014 Serialized TX----')
console.log(serializedTx.toString('hex'))
console.log('--------------------')

// ----------------------------------------------------------------------------------------------

