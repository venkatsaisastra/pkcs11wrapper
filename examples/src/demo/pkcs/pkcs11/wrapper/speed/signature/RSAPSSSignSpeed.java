package demo.pkcs.pkcs11.wrapper.speed.signature;

import org.junit.Test;

import demo.pkcs.pkcs11.wrapper.TestBase;
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
      super(Functions.mechanismCodeToString(PKCS11Constants.CKM_RSA_PKCS_PSS)
              + " (2048) Sign Speed",
          Mechanism.get(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN), token, pin,
          signMechanism, 32);
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

  private final Mechanism signMechanism;

  public RSAPSSSignSpeed() {
    signMechanism = Mechanism.get(PKCS11Constants.CKM_RSA_PKCS_PSS);
    RSAPkcsPssParameters parameters = new RSAPkcsPssParameters(
        PKCS11Constants.CKM_SHA256, PKCS11Constants.CKG_MGF1_SHA256, 32);
    signMechanism.setParameters(parameters);
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
