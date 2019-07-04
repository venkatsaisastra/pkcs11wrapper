[![Build Status](https://secure.travis-ci.org/xipki/pkcs11wrapper.svg)](http://travis-ci.org/xipki/pkcs11wrapper)
[![GitHub release](https://img.shields.io/github/release/xipki/pkcs11wrapper.svg)](https://github.com/xipki/pkcs11wrapper/releases)
[![Github forks](https://img.shields.io/github/forks/xipki/pkcs11wrapper.svg)](https://github.com/xipki/pkcs11wrapper/network)
[![Github stars](https://img.shields.io/github/stars/xipki/pkcs11wrapper.svg)](https://github.com/xipki/pkcs11wrapper/stargazers)

[Original Readme.txt](IAIK.Readme.txt)

Use xipki/pkcs11wrapper in your project
=====
- Maven  
  ```
  <dependency>
      <groupId>org.xipki.iaik</groupId>
      <artifactId>sunpkcs11-wrapper</artifactId>
      <version>1.4.5</version>
  </dependency>
  ```
- Or copy the following jar file to your classpath:
  - [sunpkcs11-wrapper-1.4.5.jar](https://github.com/xipki/pkcs11wrapper/releases/download/v1.4.5/sunpkcs11-wrapper-1.4.5.jar)

JUnit tests
=====
- Configure the library and PIN of your HSM module in the file `example/data/pkcs11.properties`.
- `mvn test`  
   - By default the speed test will run with 2 threads, you can change the
     value via the Java property `speed.threads`, e.g.
    `-Dspeed.threads=5` to use 5 threads.
   - By default the speed test will take 3 seconds, you can change the
     value via the Java property `speed.duration`, e.g.
    `-Dspeed.duration=10s` for 10 seconds.

Changes compared to [mikma/pkcs11wrapper](https://github.com/mikma/pkcs11wrapper)
=============================================

- No external library is required
- Require OpenJDK or Oracle Java Runtime 1.8 or higher
- Support PKCS#11 version 2.40
- Support EdDSA Ed25519 (Signature and Keypair generation)
- Port from [mikma/pkcs11wrapper](https://github.com/mikma/pkcs11wrapper) to this project
  - For `*SecretKey`, please use the constructor `ValuedSecretKey(long keyType)` instead, e.g. use `new ValuedSecretKey(PKCS11Constants.CKK_AES)` for AES SecretKey.
  - For `ECDSAPrivateKey` and `ECDSAPublicKey`, please use `ECPrivateKey` and `ECPublicKey` instead.
  - `iaik.pkcs.pkcs11.objects.Object` is renamed to `iaik.pkcs.pkcs11.objects.PKCS11Object`.
  - `Token.closeAllSession()` cannot be supported, since it is not supported in the underlying JNI (JDK's SunPKCS11 provider). Please manage your session by yourself. You can close a single session by `Session.closeSession()`.
  - Unlike the original PKCS#11 wrapper, we only call `Module.initialize()` once per native .so/.dll. Once `Module.finalize(Object)` has been called, the module cannot be initialized anymore.
