/*
*
* this script is to use private key sign a message
* usage: npm install ethereumjs-tx --save
* */
const EthereumTx = require('ethereumjs-tx').Transaction
const privateKey = Buffer.from(
    'cbb1981be330b0d97e620a61b913f678fc9c12c059a70badf92d0db317ff804f',
    'hex',
)

const txParams = {
    nonce: '0x00',
    gasPrice: '0x09184e72a000',
    gasLimit: '0x2710',
    to: '0x0000000000000000000000000000000000000000',
    value: '0x00',
    data: '0x7f7465737432000000000000000000000000000000000000000000000000000000600057',
}

// The second parameter is not necessary if these values are used
const tx = new EthereumTx(txParams, { chain: 'mainnet', hardfork: 'petersburg' })
tx.sign(privateKey)
const serializedTx = tx.serialize()

const feeCost = tx.getUpfrontCost()
console.log('Total Amount of wei needed:' + feeCost.toString())

// Lets serialize the transaction

console.log('---Serialized TX----')
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
//a0 0ace9b8c332799dd54da03c8a44c3191b456b2f067ad575d4022d3a81e9318c
