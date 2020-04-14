const crypto = require('crypto');
const ecc = require('tiny-secp256k1');
const bs58check = require('bs58check');
const bs58 = require('bs58');
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');

const seed = "67f93560761e20617de26e0cb84f7234aaf373ed2e66295c3d7397e6d7ebe882ea396d5d293808b0defd7edd2babd4c091ad942e6a9351e6d075a29d4df872af";

(async main => {
    try {
        /**
         * 1. Generate Master Key
         */
        const data = Buffer.from(seed, 'hex');
        const key = Buffer.from('Bitcoin seed', 'utf8');

        const hmac = crypto.createHmac('sha512', key).update(data).digest(); //HMAC-SHA512 

        const masterPrivateKey = hmac.slice(0, 32);
        const chainCode = hmac.slice(32);

        const keys = ec.keyFromPrivate(masterPrivateKey); //get public key
        const masterPublicKey = keys.getPublic(true, 'hex'); //compress format

        console.log('chainCode', chainCode.toString('hex'));
        console.log('masterPrivateKey', masterPrivateKey.toString('hex'));
        console.log('masterPublicKey', masterPublicKey);
        
        console.log('---------------------------')
        /**
         * 2. Generate normal extended private child key
         */
        let i = 0; //child index number        
        // i = 2147483648; // Hardened Child
        childExtendedPrivateKey(masterPublicKey, chainCode, i, masterPrivateKey);
        // childExtendedPublicKey(masterPublicKey, chainCode, i);

        // toBase58(masterPublicKey, chainCode.toString('hex'), masterPrivateKey.toString('hex'));

    } catch (error) {
        console.log('error', error);
    }
})();

function toBase58(parentPublicKey, chainCode, parentPrivateKey){
    //4 bytes version
    const version = '0488ade4' // private = 0x0488ade4 (xprv), public = 0x0488b21e (xpub)
    //1 byte depth
    const depth = "01"; // 0x00 for master nodes, 0x01 for level-1 descendants, ....
    //4 bytes fingerprint
    const fingerprint = createFingerprint(parentPublicKey); // 0x00000000 if master key
    //4 bytes child number (index)
    const childNumber = "00000000" // 0x00000000 if master key
    //32 bytes chain code
    chainCode = chainCode;
    //33 bytes key
    const key = "00" + parentPrivateKey; // 0x00 + key for private keys

    const serialized = version + depth + fingerprint + childNumber + chainCode + key;
    const buffer = Buffer.from(serialized + checksum(serialized), 'hex');

    const extendedPrivateKey = bs58.encode(buffer);
    console.log('extended private key', extendedPrivateKey);
    return extendedPrivateKey;
}

function checksum(hex){
    if(!Buffer.isBuffer(hex)){
        hex = Buffer.from(hex, 'hex');
    }
    //sha256 twice
    const hash1 = crypto.createHash('sha256').update(hex).digest();
    const hash2 = crypto.createHash('sha256').update(hash1).digest();
    //take first 4 bytes
    const result = hash2.slice(0, 4).toString('hex');
    return result;
}

function createFingerprint(parentPublicKey){
    if(!Buffer.isBuffer(parentPublicKey)){
        parentPublicKey = Buffer.from(parentPublicKey, 'hex');
    }

    const hash160 = crypto.createHash('ripemd160').update(crypto.createHash('sha256').update(parentPublicKey).digest()).digest(); // hash160 = ripemd160(sha256(key))
    const fingerprint = hash160.slice(0, 4).toString('hex'); // take first 4 bytes and covert to hex string
    // console.log('fingerprint', fingerprint);
    return fingerprint;
}

// function base58_encode(hex){
//     const base58chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
//     if(hex.length === 0) return '';

//     let res = '';
//     let i = parseInt(hex, 16);
    
//     while(i > 0){
//         const remain = i % 58;
//         console.log('char', base58chars.charAt(remain))
//         res += base58chars.charAt(remain);
//         i = i/58;
//     }
//     return res;
// }

function childExtendedPrivateKey(parentPublicKey, key, index, parentPrivateKey){    
    const data = Buffer.allocUnsafe(37); // 37 bytes = 1 byte: 0x00 for hardened + 32 bytes public key + 4 byte index
    if(!Buffer.isBuffer(parentPublicKey)){
        parentPublicKey = Buffer.from(parentPublicKey, 'hex');        
    }
    
    const isHardened = index >= 2147483648; // 2^31
    console.log('index', index);

    if(isHardened){ 
        //data = 0x00 + private key + index
        data[0] = 0x00;
        parentPrivateKey.copy(data, 1);
        data.writeUInt32BE(index, 33);
    }else{
        //data = public key + index
        parentPublicKey.copy(data, 0);
        data.writeUInt32BE(index, 33);       
    }

    //Put data and key through HMAC-SHA512
    const hmac = crypto.createHmac('sha512', key).update(data).digest();    
    const IL = hmac.slice(0, 32);
    const childChainCode = hmac.slice(32);
    
    //Caculate child key
    const childPrivateKey  = ecc.privateAdd(parentPrivateKey, IL); // parse256(IL) + kpar (mod n)

    const keyPair = ec.keyFromPrivate(childPrivateKey); //get public key
    const childPublicKey = keyPair.getPublic(true, 'hex'); //compress format
    
    // console.log('childChainCode', childChainCode.toString('hex'));
    // console.log('childPrivateKey', childPrivateKey.toString('hex'));
    console.log('childPublicKey', childPublicKey);
    console.log('address', pubKey2Addr(childPublicKey, 'p2pkh'));
}

function childExtendedPublicKey(parentPublicKey, key, index){    
    const data = Buffer.allocUnsafe(37); // 37 bytes = 1 byte: 0x00 for hardened + 32 bytes public key + 4 byte index
    if(!Buffer.isBuffer(parentPublicKey)){
        parentPublicKey = Buffer.from(parentPublicKey, 'hex');        
    }
    
    const isHardened = index >= 2147483648; // 2^31
    console.log('index', index);

    if(isHardened){ 
        return;
    }
    
    //data = public key + index
    parentPublicKey.copy(data, 0);
    data.writeUInt32BE(index, 33);       

    //Put data and key through HMAC-SHA512
    const hmac = crypto.createHmac('sha512', key).update(data).digest();    
    const IL = hmac.slice(0, 32);
    const childChainCode = hmac.slice(32);
    
    //Caculate child key
    const childPublicKey  = ecc.pointAddScalar(parentPublicKey, IL, true); //point(parse256(IL)) + Kpar = G*IL + Kpar
    
    // console.log('childChainCode', childChainCode.toString('hex'));
    console.log('childPublicKey', childPublicKey.toString('hex'));
    console.log('address', pubKey2Addr(childPublicKey, 'p2pkh'));
}

function pubKey2Addr(publicKey, type){
    if(!Buffer.isBuffer(publicKey)){
        publicKey = Buffer.from(publicKey, 'hex');
    }

    //hash160 pubkey
    const hash160 = crypto.createHash('ripemd160').update(crypto.createHash('sha256').update(publicKey).digest()).digest(); // hash160 = ripemd160(sha256(key))

    let prefix = '';
    switch (type) {
        case 'p2pkh':
            prefix = '00'; // 1address - For standard bitcoin addresses
            break;
        case 'p2sh':
            prefix = '05'; // 3address - For sending to an address that requires multiple signatures (multisig)
            break;
        default:
            break;
    }

    const cs = checksum(prefix + hash160.toString('hex'));
    const addr = prefix + hash160.toString('hex') + cs;
    const address = bs58check.encode(Buffer.from(addr, 'hex'));
    return address;
}