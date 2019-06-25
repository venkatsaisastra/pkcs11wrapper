package demo.pkcs.pkcs11.wrapper.speed.keygeneration;

public class AES128KeyGenSpeed extends AESKeyGenSpeed {

  @Override
  protected int getKeyByteLen() {
    return 16;
  }

}
