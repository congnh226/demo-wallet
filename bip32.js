const crypto = require('crypto');
const ecc = require('tiny-secp256k1');
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
        // childExtendedPrivateKey(masterPublicKey, chainCode, i, masterPrivateKey);
        childExtendedPublicKey(masterPublicKey, chainCode, i);

    } catch (error) {
        console.log('error', error);
    }
})();

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
    
    console.log('childChainCode', childChainCode.toString('hex'));
    console.log('childPrivateKey', childPrivateKey.toString('hex'));
    console.log('childPublicKey', childPublicKey);
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
    
    console.log('childChainCode', childChainCode.toString('hex'));
    console.log('childPublicKey', childPublicKey.toString('hex'));
}