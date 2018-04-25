var crypto = require('crypto');
var secp256k1 = require('secp256k1');

const msg = process.argv[2];
if (msg == null) {
    console.log("There is nothing to sign");
} else {
    signMsg(msg);
    diffiHelmanAlg(msg);
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

    console.log("keypair: " + "\n\tpublicKey: " + publicKey.toString("hex") + "\n\tprivateKey: " + privateKey.toString("hex"));

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

// Предположим, существует два абонента: Алиса и Боб. Обоим абонентам известны некоторые два числа  g и p,
// которые не являются секретными и могут быть известны также другим заинтересованным лицам.
// Для того, чтобы создать неизвестный более никому секретный ключ, оба абонента генерируют большие случайные числа:
// Алиса — число a, Боб — число b. Затем Алиса вычисляет остаток от деления
// A=(g^a) mod p (1)
// и пересылает его Бобу, а Боб вычисляет остаток от деления (2):
// B=(g^b) mod p (2)
// и передаёт Алисе. Предполагается, что злоумышленник может получить оба этих значения, но не модифицировать их
// (то есть, у него нет возможности вмешаться в процесс передачи).
//
// На втором этапе Алиса на основе имеющегося у неё a и полученного по сети B вычисляет значение (3)://
// (B^a) mod p=g^{ab} mod p (3)
// Боб на основе имеющегося у него b и полученного по сети A вычисляет значение (4):
// (A^b) mod p=g^{ab} mod p (4)
// Как нетрудно видеть, у Алисы и Боба получилось одно и то же число (5):
// K=g^{ab} mod p (5)
// Его они и могут использовать в качестве секретного ключа, поскольку здесь злоумышленник встретится с практически
// неразрешимой (за разумное время) проблемой вычисления (3) или (4) по перехваченным g^a  mod p и  g^b mod p,
// если числа p, a, b выбраны достаточно большими.

function diffieHelmanAlg(str) {
    // TODO: change random numbers:
    // обычно значения p и g генерируются на одной стороне и передаются другой), где
    // p является случайным простым числом
    // (p-1)/2 также должно быть случайным простым числом (для повышения безопасности)[5]
    // g является первообразным корнем по модулю p (также является простым числом)

    const g = parseInt(crypto.randomBytes(4).toString("hex"), 16) % 50 + 1;
    const p = parseInt(crypto.randomBytes(4).toString("hex"), 16) % 100 + 1;
    console.log("Random numbers:" + "\n\tg = " + g + "\n\tp = " + p);

    // secret Alice number
    const a = parseInt(crypto.randomBytes(32).toString("hex"), 16) % 100 + 1;
    // secret Bob number
    const b = parseInt(crypto.randomBytes(32).toString("hex"), 16) % 100 + 1;

    console.log("Alice secret number:" + a);
    console.log("Bob secret number:" + b);

    const A = Math.pow(g, a) % p;
    console.log("Calculated A:" + A);

    const B = Math.pow(g, b) % p;
    console.log("Calculated B:" + B);

    const Ka = Math.pow(B, a) % p;
    const Kb = Math.pow(A, b) % p;

    console.log("Calculated Ka:" + Ka);
    console.log("Calculated Kb:" + Kb);

}
