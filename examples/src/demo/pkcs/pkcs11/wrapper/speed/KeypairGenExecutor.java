package demo.pkcs.pkcs11.wrapper.speed;

import java.util.Random;
import java.util.concurrent.TimeUnit;

import org.xipki.util.BenchmarkExecutor;
import org.xipki.util.concurrent.ConcurrentBag;

import demo.pkcs.pkcs11.wrapper.util.Util;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.wrapper.Functions;

public abstract class KeypairGenExecutor extends BenchmarkExecutor {

  public class MyRunnable implements Runnable {

    public MyRunnable() {
    }

    @Override
    public void run() {
      while (!stop()) {
        try {
          // generate keypair on token
          PrivateKey privateKeyTemplate = getMinimalPrivateKeyTemplate();
          PublicKey publicKeyTemplate = getMinimalPublicKeyTemplate();
          publicKeyTemplate.getToken().setBooleanValue(Boolean.FALSE);
          byte[] id = new byte[20];
          new Random().nextBytes(id);
          publicKeyTemplate.getId().setByteArrayValue(id);

          privateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
          privateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
          privateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);
          privateKeyTemplate.getId().setByteArrayValue(id);

          privateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
          publicKeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);

          // netscape does not set these attribute, so we do no either
          publicKeyTemplate.getKeyType().setPresent(false);
          publicKeyTemplate.getObjectClass().setPresent(false);
          privateKeyTemplate.getKeyType().setPresent(false);
          privateKeyTemplate.getObjectClass().setPresent(false);

          ConcurrentSessionBagEntry sessionBag = borrowSession();
          KeyPair keypair;
          try {
            Session session = sessionBag.value();
            keypair = session.generateKeyPair(mechanism, publicKeyTemplate,
                privateKeyTemplate);
          } finally {
            requiteSigner(sessionBag);
          }

          // we use here explicitly not the same session.
          sessionBag = null;
          sessionBag = borrowSession();
          try {
            Session session = sessionBag.value();
            session.destroyObject(keypair.getPrivateKey());
            session.destroyObject(keypair.getPublicKey());
          } finally {
            requiteSigner(sessionBag);
          }

          account(1, 0);
        } catch (Throwable th) {
          account(1, 1);
        }
      }
    }

  }

  private final ConcurrentBag<ConcurrentSessionBagEntry> sessions =
      new ConcurrentBag<>();

  private final Mechanism mechanism;

  public KeypairGenExecutor(long mechnism, Token token, char[] pin)
      throws TokenException {
    super(Functions.mechanismCodeToString(mechnism) + " Speed");

    this.mechanism = new Mechanism(mechnism);
    for (int i = 0; i < 5; i++) {
      Session session = Util.openAuthorizedSession(token, true, pin);
      sessions.add(new ConcurrentSessionBagEntry(session));
    }
    
    setDuration("10s");
  }

  protected abstract PrivateKey getMinimalPrivateKeyTemplate();

  protected abstract PublicKey getMinimalPublicKeyTemplate();

  @Override
  protected Runnable getTestor() throws Exception {
    return new MyRunnable();
  }

  public ConcurrentSessionBagEntry borrowSession() {
    ConcurrentSessionBagEntry signer = null;
    try {
      signer = sessions.borrow(1000, TimeUnit.MILLISECONDS);
    } catch (InterruptedException ex) { // CHECKSTYLE:SKIP
    }

    if (signer == null) {
      throw new IllegalStateException("no idle signer available");
    }

    return signer;
  }

  public void requiteSigner(ConcurrentSessionBagEntry session) {
    sessions.requite(session);
  }

}
