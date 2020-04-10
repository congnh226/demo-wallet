const crypto = require('crypto');
const wordList = require('./wordlist.json');

(async main => {
    try {
        /**
         * 1. Generate Entropy
         */
        const bytes = crypto.randomBytes(16); // 16 bytes = 128 bits 
        const entropy = Buffer.from(bytes, 'hex');        
        const entropyBits = bytesToBinary(Array.from(entropy)); //convert bytes to a string of bits (base 2)
        console.log('entropyBits', entropyBits);

        /**
         * 2. Entropy to Mnemonic
         */
        // 2.1. Add checksum
        const size = entropyBits.length / 32; // number of bits to take from hash of entropy (1 bit checksum for every 32 bits entropy)
        const sha256 = crypto.createHash('sha256').update(entropy).digest(); // hash of entropy (in raw binary)
        const checksum = bytesToBinary(Array.from(sha256)).slice(0, size); // take 1 bit for every 32 bits of entropy       
        console.log('checksum', checksum);

        const full = entropyBits + checksum;
        console.log('full', full);

        //2.2. Split to array of 11 bits
        const chunks = full.match(/(.{1,11})/g);
        console.log('chunks', chunks);

        //2.3. Convert chunk to array of words
        const sentence = chunks.map((piece) => {
            const index = parseInt(piece, 2); // convert bit to integer
            return wordList[index]; 
        });
        
        const mnemonic = sentence.join(' '); // merge to string
        console.log('mnemonic:', mnemonic); 

        /**
         * 3. Menomic to Seed
         */
        const passphrase = ''; //optional
        const salt = 'mnemonic' + passphrase; // "mnemonic" is always used in the salt with optional passphrase appended to it

        crypto.pbkdf2(Buffer.from(mnemonic, 'utf8'), Buffer.from(salt, 'utf8'), 2048, 64, 'sha512', (error, res) => {
            if(error){
                console.log(error)
            }
            console.log('seed:', res.toString('hex'));
        });

    } catch (error) {
        console.log(error);
    }
})()



function bytesToBinary(bytes){
    return bytes.map((x) => lpad(x.toString(2), '0', 8)).join('');
}

function lpad(str, padString, length) {
    while (str.length < length)
        str = padString + str;
    return str;
}