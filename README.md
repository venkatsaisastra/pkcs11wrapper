[![Build Status](https://secure.travis-ci.org/xipki/pkcs11wrapper.svg)](http://travis-ci.org/xipki/pkcs11wrapper)
[![GitHub release](https://img.shields.io/github/release/xipki/pkcs11wrapper.svg)](https://github.com/xipki/pkcs11wrapper/releases)
[![Github forks](https://img.shields.io/github/forks/xipki/pkcs11wrapper.svg)](https://github.com/xipki/pkcs11wrapper/network)
[![Github stars](https://img.shields.io/github/stars/xipki/pkcs11wrapper.svg)](https://github.com/xipki/pkcs11wrapper/stargazers)

Changes of current branch sunpkcs11 compared to master
=============================================

- No external library is required

- Require OpenJDK or Oracle Java Runtime 1.8 or higher

- Support PKCS#11 version 2.40

- Use xipki/pkcs11wrapper in your project:
  - Maven  
    ```
    <dependency>
        <groupId>org.xipki.iaik</groupId>
        <artifactId>sunpkcs11-wrapper</artifactId>
        <version>1.4.4</version>
    </dependency>
    ```
  - Or copy the following jar files to your classpath:
    - [sunpkcs11-wrapper-1.4.4.jar](http://central.maven.org/maven2/org/xipki/iaik/sunpkcs11-wrapper/1.4.4/sunpkcs11-wrapper-1.4.4.jar)
    - [pkcs11-constants-1.4.4.jar](http://central.maven.org/maven2/org/xipki/iaik/pkcs11-constants/1.4.4/pkcs11-constants-1.4.4.jar)
- Port from mikma/pkcs11wrapper to xipki/pkcs11wrapper
  - For `*SecretKey`, please use class `ValuedSecretKey(long keyType)` instead, e.g. use `new ValuedSecretKey(PKCS11Constants.CKK_AES)` for `new AESSecretKey()`.
  - For `ECDSAPrivateKey` and `ECDSAPublicKey`, please use `ECPrivateKey` and `ECPublicKey` instead.
  - `Object` is renamed to `PKCS11Object`.
  - `Parameters` is renamed to `Params`. And the package `iaik.pkcs.pkcs11.parameters` is renamed to `iaik.pkcs.pkcs11.params`.
  - `PKCS11Constants` is repackaged to `iaik.pkcs.pkcs11.constants`.
  - `Functions` is repackaged to `iaik.pkcs.pkcs11.constants`.
  - `Token.closeAllSession()` cannot be supported, since it is not supported in the underlying JNI (JDK's SunPKCS11 provider). Please manage your session by yourself. You can close a single session by `Session.closeSession()`.
  - Unlike the original PKCS#11 wrapper, we only call initialize() once per native .so/.dll. Once finalize(Object) has been called, the module cannot be initialized anymore.

IAIK PKCS#11 Wrapper for Java, Version 1.3
=============================================

The PKCS#11 API is specified in the ANSI-C programming 
language. This library maps the complete PKCS#11 API to 
an equivalent Java API in a straight forward style. 
This allows to access PKCS#11 modules from Java.

It does not contain a JCA/JCE provider implementation. 
This means that the PKCS#11 Wrapper alone is not 
compatible with the Java cryptographic APIs like JCA 
and JCE.
There is a different product which provides this - the 
IAIK PKCS#11 Provider. 

The current version of this package is available from

http://jce.iaik.tugraz.at/download/

After the installation has finished use your favorite 
browser to view the Readme.html for further information.


Your SIC/IAIK JavaSecurity Team
