const bitcoin = require('bitcoinjs-lib');

const seed = "67f93560761e20617de26e0cb84f7234aaf373ed2e66295c3d7397e6d7ebe882ea396d5d293808b0defd7edd2babd4c091ad942e6a9351e6d075a29d4df872af";

const m = bitcoin.bip32.fromSeed(Buffer.from(seed, 'hex'));
console.log('address', m.toBase58()) 
// const child = m.deriveHardened(0).derive(0).derive(0); //BIP32
const child = m.deriveHardened(44).deriveHardened(0).deriveHardened(0).derive(0).derive(0); //BIP44
console.log('address ', bitcoin.payments.p2pkh({pubkey: child.publicKey}).address);
console.log('publicKey', child.publicKey.toString('hex'))

// for(let i = 0; i < 20; i++){
//     const child = m.deriveHardened(44).deriveHardened(0).deriveHardened(0).derive(0).derive(i); //BIP44
//     console.log('address ' + i, bitcoin.payments.p2pkh({pubkey: child.publicKey}).address)    
// }

