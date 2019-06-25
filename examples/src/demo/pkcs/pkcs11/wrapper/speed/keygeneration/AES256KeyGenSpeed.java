package demo.pkcs.pkcs11.wrapper.speed.keygeneration;

public class AES256KeyGenSpeed extends AESKeyGenSpeed {

  @Override
  protected int getKeyByteLen() {
    return 32;
  }

}
