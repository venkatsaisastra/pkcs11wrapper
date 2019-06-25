package demo.pkcs.pkcs11.wrapper.speed.signature;

import org.junit.Test;

import demo.pkcs.pkcs11.wrapper.TestBase;
import demo.pkcs.pkcs11.wrapper.util.Util;
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
      super(Functions.mechanismCodeToString(signMechanism) + " (Ed25519) Speed",
      Mechanism.get(keypairGenMechanism), token, pin,
      Mechanism.get(signMechanism), 107);
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

  private static final long keypairGenMechanism =
      PKCS11Constants.CKM_EC_EDWARDS_KEY_PAIR_GEN;

  private static final long signMechanism = PKCS11Constants.CKM_EDDSA;

  @Test
  public void main() throws TokenException {
    Token token = getNonNullToken();
    if (!Util.supports(token, keypairGenMechanism)) {
      System.out.println(Functions.mechanismCodeToString(keypairGenMechanism)
          + " is not supported, skip test");
      return;
    }

    if (!Util.supports(token, signMechanism)) {
      System.out.println(Functions.mechanismCodeToString(signMechanism)
          + " is not supported, skip test");
      return;
    }

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
