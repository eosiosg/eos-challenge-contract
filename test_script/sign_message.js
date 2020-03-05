/***
*
* this script is to use private key sign a message
* usage: npm install ethereumjs-tx --save
* */

///ETH private key
///
///(0) 0xD81F4358cB8cab53D005e7f47c7ba3F5116000A6 (100 ETH)
///(1) 0x39944247C2eDF660D86D57764B58d83B8EEE9014 (100 ETH)
///(2) 0xE327e755438fBDf9e60891d9B752DA10a38514D1 (100 ETH)
///(3) 0x8aAFae259C494870AC4E34e9E6019788787dDd77 (100 ETH)
///(4) 0x37840eE7603305F5F3d8fd26d41A4C3a5d7375da (100 ETH)
///(5) 0xeAD1a186688C5A9c967B427B632EaEFE8043B12c (100 ETH)
///(6) 0x713D1Ff9A73a7aC655F6F638316CBfdCf6da4B48 (100 ETH)
///(7) 0xCbf129e6Dd638cbc5b88C328087a6A963A73CeDd (100 ETH)
///(8) 0x5E9eb0EEd9B9afd8712e8611Bf5a6D593f7705Fd (100 ETH)
///(9) 0xa64428bee004C975FFcA398673c4D6E21a057FB6 (100 ETH)
///
///Private Keys
///==================
///(0) 0xcbb1981be330b0d97e620a61b913f678fc9c12c059a70badf92d0db317ff804f
///(1) 0x3f04415249414ff900b464f8d588517146c4ec39a3ae9855282030fa3de3862f
///(2) 0x9089c365c66ca5d1ea63f1a42a569326d887e680b2256fe79897a2da5aa708ea
///(3) 0x23c29d7d2eb5078c33ec80d5c0d86bcc0a0f5b58a24ee0d5904c7dd965956efb
///(4) 0x9587828e1281a552977f6619e3cf540ad3344fd31d90dce44daaaed2f70683dd
///(5) 0x7b697d4cccd589c1d065a18f315b5a5582e97984313fc9bb013dfd458769a829
///(6) 0x62c0788dd9f80919ed4f44392321892228a99deb31c0ba22060060f9ccc338a9
///(7) 0xcdc2fa8a012050cf0b3d1c2dc56fd8bb27ee74f3832627f48919977233d5fd64
///(8) 0x8fa52da70a645fe2daab8bcc24b523680dc6c4350985ea270cbe5d29d92fc8b0
///(9) 0x70458e863ddd01cbc5cb6891d399836a17f8d78a06ec6b4c12fae71352848344

const EthereumTx = require('ethereumjs-tx').Transaction
const privateKey = Buffer.from(
    'cbb1981be330b0d97e620a61b913f678fc9c12c059a70badf92d0db317ff804f',
    'hex',
)

const txParams = {
    nonce: '0x01',
    gasPrice: '0x09184e72a000',
    gasLimit: '0x27100',
    to: '0x763c40c946471528d2ed5f12ee81d972ab777d73',
    value: '0x00',
    data: '0xa9059cbb000000000000000000000000d81f4358cb8cab53d005e7f47c7ba3f5116000a60000000000000000000000000000000000000000000000000000000000000064',
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
//a0 0ace9b8c332799dd54da03c8a44c3191b456b2f067ad575d4022d3a81e9318c7
