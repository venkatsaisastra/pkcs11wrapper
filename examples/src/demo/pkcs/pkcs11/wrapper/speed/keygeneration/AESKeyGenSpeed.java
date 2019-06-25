package demo.pkcs.pkcs11.wrapper.speed.keygeneration;

import org.junit.Test;

import demo.pkcs.pkcs11.wrapper.TestBase;
import demo.pkcs.pkcs11.wrapper.util.Util;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.ValuedSecretKey;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import junit.framework.Assert;

public abstract class AESKeyGenSpeed extends TestBase {

  private class MyExecutor extends KeyGenExecutor {

    public MyExecutor(Token token, char[] pin) throws TokenException {
      super(mechanism, getKeyByteLen(), token, pin);
    }

    @Override
    protected ValuedSecretKey getMinimalKeyTemplate() {
      ValuedSecretKey template = ValuedSecretKey.newAESSecretKey();
      template.getValueLen().setLongValue(Long.valueOf(getKeyByteLen()));
      return template;
    }

  }

  private static final long mechanism = PKCS11Constants.CKM_AES_KEY_GEN;

  protected abstract int getKeyByteLen();

  @Test
  public void main() throws TokenException {
    Token token = getNonNullToken();
    if (!Util.supports(token, mechanism)) {
      System.out.println(Functions.mechanismCodeToString(mechanism)
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
