package demo.pkcs.pkcs11.wrapper.speed.keygeneration;

public class AES192KeyGenSpeed extends AESKeyGenSpeed {

  @Override
  protected int getKeyByteLen() {
    return 24;
  }

}
