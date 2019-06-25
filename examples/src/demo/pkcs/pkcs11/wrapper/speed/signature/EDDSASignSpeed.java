package demo.pkcs.pkcs11.wrapper.speed.signature;

import org.junit.Test;

import demo.pkcs.pkcs11.wrapper.TestBase;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.ECPrivateKey;
import iaik.pkcs.pkcs11.objects.ECPublicKey;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import junit.framework.Assert;

public class EDDSASignSpeed extends TestBase {

  private class MyExecutor extends SignExecutor {

    public MyExecutor(Token token, char[] pin) throws TokenException {
      super(Functions.mechanismCodeToString(
          PKCS11Constants.CKM_EC_EDWARDS_KEY_PAIR_GEN) + " (Ed25519) Speed",
      Mechanism.get(PKCS11Constants.CKM_EC_EDWARDS_KEY_PAIR_GEN), token, pin,
      Mechanism.get(PKCS11Constants.CKM_EDDSA), 107);
    }

    @Override
    protected PrivateKey getMinimalPrivateKeyTemplate() {
      return new ECPrivateKey();
    }

    @Override
    protected PublicKey getMinimalPublicKeyTemplate() {
      ECPublicKey publicKeyTemplate = new ECPublicKey();
      // set the general attributes for the public key
      // OID: 1.3.101.112 (Ed25519)
      byte[] encodedCurveOid = new byte[] {0x06, 0x03, 0x2b, 0x65, 0x70};
      publicKeyTemplate.getEcdsaParams().setByteArrayValue(encodedCurveOid);
      return publicKeyTemplate;
    }

  }

  @Test
  public void main() throws TokenException {
    Token token = getNonNullToken();
    Session session = openReadOnlySession(token);
    try {
      MyExecutor executor = new MyExecutor(token, getModulePin());
      executor.setThreads(getSpeedTestThreads());
      executor.setDuration(getSpeedTestDuration());
      executor.execute();
      Assert.assertEquals("no error", 0, executor.getErrorAccout());
    } finally {
      session.closeSession();
    }
  }

}
