package demo.pkcs.pkcs11.wrapper.speed.keygeneration;

import java.util.Random;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import demo.pkcs.pkcs11.wrapper.speed.ConcurrentSessionBagEntry;
import demo.pkcs.pkcs11.wrapper.speed.Pkcs11Executor;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.ValuedSecretKey;
import iaik.pkcs.pkcs11.wrapper.Functions;

public abstract class KeyGenExecutor extends Pkcs11Executor {

  private static final Logger LOG =
      LoggerFactory.getLogger(KeyGenExecutor.class);

  public class MyRunnable implements Runnable {

    public MyRunnable() {
    }

    @Override
    public void run() {
      while (!stop()) {
        try {
          // generate key on token
          ValuedSecretKey secretKeyTemplate = getMinimalKeyTemplate();
          secretKeyTemplate.getToken().setBooleanValue(inToken);
          if (inToken) {
            byte[] id = new byte[20];
            new Random().nextBytes(id);
            secretKeyTemplate.getId().setByteArrayValue(id);
          }

          secretKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
          secretKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
          secretKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);

          ConcurrentSessionBagEntry sessionBag = borrowSession();
          ValuedSecretKey key;
          try {
            Session session = sessionBag.value();
            key = (ValuedSecretKey) session.generateKey(
                    mechanism, secretKeyTemplate);
            session.destroyObject(key);
          } finally {
            requiteSession(sessionBag);
          }

          account(1, 0);
        } catch (Throwable th) {
          System.err.println(th.getMessage());
          LOG.error("error", th);
          account(1, 1);
        }
      }
    }

  }

  private final Mechanism mechanism;

  private final boolean inToken;

  public KeyGenExecutor(long mechnism, int keyLen, Token token, char[] pin,
      boolean inToken) throws TokenException {
    super(describe(mechnism, keyLen, inToken), token, pin);
    this.mechanism = new Mechanism(mechnism);
    this.inToken = inToken;
  }

  protected abstract ValuedSecretKey getMinimalKeyTemplate();

  @Override
  protected Runnable getTestor() throws Exception {
    return new MyRunnable();
  }

  private static String describe(long mechnism, int keyLen, boolean inToken) {
    StringBuilder sb = new StringBuilder(100)
      .append(Functions.mechanismCodeToString(mechnism))
      .append(" (");
    if (keyLen > 0) {
      sb.append(keyLen * 8).append(" bits, ");
    }

    sb.append("inToken: ").append(inToken).append(") Speed");
    return sb.toString();
  }

}
