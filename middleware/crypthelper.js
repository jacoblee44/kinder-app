'use strict';
const crypto = require('crypto');

const aesKey = '123&@#wpc435lin2fir2e32!';
exports.aesEncode = function ( plaintext ) {
    var mykey = crypto.createCipher('aes-128-cbc', aesKey);
    var mystr = mykey.update( plaintext , 'utf8', 'hex')
    mystr += mykey.final('hex');
    return mystr;
}
exports.aesDecode = function ( ciphertext ) {
    var mykey = crypto.createDecipher('aes-128-cbc', aesKey);
    var mystr = mykey.update(ciphertext, 'hex', 'utf8')
    mystr += mykey.final('utf8');
    return mystr;
}
