var crypto = require('crypto');
var secp256k1 = require('secp256k1');

const msg = process.argv[2];
if (msg == null) {
    console.log("There is nothing to sign");
} else {
    signMsg(msg);
}


function digest(str, algo = "sha256") {
    return crypto.createHash(algo).update(str).digest();
}

function genPrivateKey() {
    let privateKey;
    do {
        privateKey = crypto.randomBytes(32);
        // console.debug("try: " + privateKey);
    } while (!secp256k1.privateKeyVerify(privateKey));
    return privateKey;
}



function signMsg(str) {
    const digested = digest(msg);

    console.log("Incoming  message: " + str + ",\n\tmessage digest: " + digested.toString("hex"));

    // generate privateKey
    let privateKey = genPrivateKey();

    // get the public key in a compressed format
    const publicKey = secp256k1.publicKeyCreate(privateKey);

    console.log("keypair: "  + "\n\tpublicKey: " + publicKey.toString("hex") + "\n\tprivateKey: " + privateKey.toString("hex"));

    // sign the message
    const sigObj = secp256k1.sign(digested, privateKey);
    const sig = sigObj.signature;
    console.log("Signature:", sig.toString("hex"));

    // unsuccessfull verification
    const digest_bad = digest("str" + " ");
    let verified = secp256k1.verify(digest_bad, sig, publicKey);
    console.log("Trying to verify message with public key. Result: " + verified);

    // successfull verification
    verified = secp256k1.verify(digested, sig, publicKey);
    console.log("Trying to verify message with public key. Result: " + verified);
}

