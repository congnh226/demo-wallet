const crypto = require('crypto');
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
        // console.log('order of the curve', ec.n.toString());
        normalChildExtendedPrivateKey(masterPublicKey + i, chainCode, masterPrivateKey);

    } catch (error) {
        console.log('error', error);
    }
})();

function normalChildExtendedPrivateKey(data, key, parentPrivateKey){
    if(!Buffer.isBuffer(data)){
        data = Buffer.from(data, 'hex');
    }
    if(!Buffer.isBuffer(parentPrivateKey)){
        parentPrivateKey = Buffer.from(parentPrivateKey, 'hex');
    }

    const hmac = crypto.createHmac('sha512', key).update(data).digest();
    const IL = hmac.slice(0, 32);
    
    //TODO
    let childPrivateKey = (parentPrivateKey + IL) % ec.n; // (IL + parentKey) % n
    console.log('childPrivate Key ', );
    childPrivateKey = childPrivateKey.toString(16);
    
    // const childChainCode = hmac.slice(32);

    // const keyPair = ec.keyFromPrivate(childPrivateKey); //get public key
    // const childPublicKey = keyPair.getPublic(true, 'hex'); //compress format
    
    // console.log('childChainCode', childChainCode.toString('hex'));
    // console.log('childPrivateKey', childPrivateKey.toString('hex'));
    // console.log('childPublicKey', childPublicKey);
}