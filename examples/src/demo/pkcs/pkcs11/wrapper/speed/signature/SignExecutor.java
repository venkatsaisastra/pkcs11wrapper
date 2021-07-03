/*
*
* Copyright (c) 2019 Lijun Liao
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

package demo.pkcs.pkcs11.wrapper.speed.signature;

import demo.pkcs.pkcs11.wrapper.TestBase;
import demo.pkcs.pkcs11.wrapper.speed.ConcurrentSessionBagEntry;
import demo.pkcs.pkcs11.wrapper.speed.Pkcs11Executor;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Random;

/**
 * Sign executor base class.
 *
 * @author Lijun Liao
 */
public abstract class SignExecutor extends Pkcs11Executor {

  private static final Logger LOG = LoggerFactory.getLogger(SignExecutor.class);

  public class MyRunnable implements Runnable {

    public MyRunnable() {
    }

    @Override
    public void run() {
      while (!stop()) {
        try {
          byte[] data = TestBase.randomBytes(inputLen);

          ConcurrentSessionBagEntry sessionBag = borrowSession();
          try {
            Session session = sessionBag.value();
            // initialize for signing
            session.signInit(signMechanism, keypair.getPrivateKey());
            // This signing operation is implemented in most of the drivers
            session.sign(data);
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

  private final Mechanism signMechanism;

  private final int inputLen;

  private final KeyPair keypair;

  public SignExecutor(String description, Mechanism keypairGenMechanism,
      Token token, char[] pin, Mechanism signMechanism, int inputLen)
          throws TokenException {
    super(description, token, pin);
    this.signMechanism = signMechanism;
    this.inputLen = inputLen;

    // generate keypair on token
    PublicKey publicKeyTemplate = getMinimalPublicKeyTemplate();

    PrivateKey privateKeyTemplate = getMinimalPrivateKeyTemplate();
    privateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
    privateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);

    publicKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
    privateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);

    byte[] id = new byte[20];
    new Random().nextBytes(id);
    publicKeyTemplate.getId().setByteArrayValue(id);
    privateKeyTemplate.getId().setByteArrayValue(id);

    publicKeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);
    privateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);

    // netscape does not set these attribute, so we do no either
    publicKeyTemplate.getKeyType().setPresent(false);
    privateKeyTemplate.getKeyType().setPresent(false);

    publicKeyTemplate.getObjectClass().setPresent(false);
    privateKeyTemplate.getObjectClass().setPresent(false);

    ConcurrentSessionBagEntry sessionBag = borrowSession();
    try {
      Session session = sessionBag.value();
      keypair = session.generateKeyPair(keypairGenMechanism,
          publicKeyTemplate, privateKeyTemplate);
    } finally {
      requiteSession(sessionBag);
    }

  }

  protected abstract PrivateKey getMinimalPrivateKeyTemplate();

  protected abstract PublicKey getMinimalPublicKeyTemplate();

  @Override
  protected Runnable getTestor() throws Exception {
    return new MyRunnable();
  }

  @Override
  public void close() {
    if (keypair != null) {
      ConcurrentSessionBagEntry sessionBag = borrowSession();
      try {
        Session session = sessionBag.value();
        session.destroyObject(keypair.getPrivateKey());
        session.destroyObject(keypair.getPublicKey());
      } catch (Throwable th) {
        LOG.error("could not destroy generated objects", th);
      } finally {
        requiteSession(sessionBag);
      }
    }

    super.close();
  }

}
