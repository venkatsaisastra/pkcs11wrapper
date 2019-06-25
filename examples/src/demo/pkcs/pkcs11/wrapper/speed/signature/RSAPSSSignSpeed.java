package demo.pkcs.pkcs11.wrapper.speed.signature;

import org.junit.Test;

import demo.pkcs.pkcs11.wrapper.TestBase;
import demo.pkcs.pkcs11.wrapper.util.Util;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.parameters.RSAPkcsPssParameters;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import junit.framework.Assert;

public class RSAPSSSignSpeed extends TestBase {

  private class MyExecutor extends SignExecutor {

    public MyExecutor(Token token, char[] pin) throws TokenException {
      super(Functions.mechanismCodeToString(signMechanism)
              + " (2048) Sign Speed",
          Mechanism.get(keypairGenMechanism), token, pin,
          signMechanism2, 32);
    }

    @Override
    protected PrivateKey getMinimalPrivateKeyTemplate() {
      return new RSAPrivateKey();
    }

    @Override
    protected PublicKey getMinimalPublicKeyTemplate() {
      RSAPublicKey publicKeyTemplate = new RSAPublicKey();
      publicKeyTemplate.getModulusBits().setLongValue(Long.valueOf(2048));
      return publicKeyTemplate;
    }

  }

  private static final long keypairGenMechanism =
      PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN;

  private static final long signMechanism = PKCS11Constants.CKM_RSA_PKCS;

  private final Mechanism signMechanism2;

  public RSAPSSSignSpeed() {
    signMechanism2 = Mechanism.get(PKCS11Constants.CKM_RSA_PKCS_PSS);
    RSAPkcsPssParameters parameters = new RSAPkcsPssParameters(
        PKCS11Constants.CKM_SHA256, PKCS11Constants.CKG_MGF1_SHA256, 32);
    signMechanism2.setParameters(parameters);
  }

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
