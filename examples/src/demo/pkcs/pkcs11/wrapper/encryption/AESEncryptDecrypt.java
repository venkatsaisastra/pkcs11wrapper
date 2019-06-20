package demo.pkcs.pkcs11.wrapper.encryption;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.ValuedSecretKey;
import iaik.pkcs.pkcs11.parameters.InitializationVectorParameters;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * This demo program uses a PKCS#11 module to encrypt and decrypt via AES.
 */
public class AESEncryptDecrypt extends SymmEncryptDecrypt {

  private final byte[] iv;
  
  public AESEncryptDecrypt() {
    iv = randomBytes(16);
  }

  @Override
  protected Mechanism getKeyGenMech(Token token) throws TokenException {
    return getSupportedMechanism(token, PKCS11Constants.CKM_AES_KEY_GEN);
  }

  @Override
  protected Mechanism getEncryptionMech(Token token) throws TokenException {
    Mechanism mech = getSupportedMechanism(token, PKCS11Constants.CKM_AES_CBC_PAD);
    InitializationVectorParameters encryptIVParameters = new InitializationVectorParameters(iv);
    mech.setParameters(encryptIVParameters);
    return mech;
  }

  @Override
  protected ValuedSecretKey getKeyTemplate() {
    ValuedSecretKey keyTemplate = ValuedSecretKey.newAESSecretKey();
    keyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
    keyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
    keyTemplate.getValueLen().setLongValue(Long.valueOf(16));
    return keyTemplate;
  }

}
