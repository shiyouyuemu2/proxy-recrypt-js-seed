# js_sdk
JS  sdk for Proxy Re-encryption compitable with py_sdk

support secp256k1

[test](./test.js)
```js
    //generate_key_pair 方法可以使用seed参数，固定seed后生成的私钥和公钥也固定不变。seed为1-191位字符串
    var kp_A = Proxy.generate_key_pair();
    var sk_A = Proxy.to_hex(kp_A.get_private_key().to_bytes());
    var pk_A = Proxy.to_hex(kp_A.get_public_key().to_bytes());

    var kp_B = Proxy.generate_key_pair();
    var sk_B = Proxy.to_hex(kp_B.get_private_key().to_bytes());
    var pk_B = Proxy.to_hex(kp_B.get_public_key().to_bytes());

    let obj = PRE.encryptData(pk_A, "test data")
    console.log(obj)
    let rk = PRE.generateReEncrytionKey(sk_A, pk_B);
    PRE.reEncryption(rk, obj)

    let decryptData = PRE.decryptData(sk_B, obj)
    console.log(decryptData)
```
