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

package demo.pkcs.pkcs11.wrapper.encryption;

import demo.pkcs.pkcs11.wrapper.TestBase;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;

/**
 * This demo shows how to use a PKCS#11 token to decrypt a session key
 * encrypted by RSA.
 *
 * @author Lijun Liao
 */
public class RSADecrypt extends TestBase {

  @Test
  public void main() throws TokenException {
    Token token = getNonNullToken();

    Session session = openReadWriteSession(token);
    try {
      main0(token, session);
    } finally {
      session.closeSession();
    }
  }

  private void main0(Token token, Session session) throws TokenException {
    // check, if this token can do RSA decryption
    Mechanism encMech = getSupportedMechanism(token,
        PKCS11Constants.CKM_RSA_PKCS);
    if (!token.getMechanismInfo(encMech).isDecrypt()) {
      LOG.info("This token does not support RSA decryption according to PKCS!");
      throw new TokenException("RSA decryption not supported!");
    }

    final boolean inToken = false;
    KeyPair keypair = generateRSAKeypair(token, session, 2048, inToken);
    PrivateKey privKey = keypair.getPrivateKey();
    PublicKey pubKey = keypair.getPublicKey();

    byte[] sessionKey = new byte[16];
    byte[] buffer = new byte[1024 / 8 + 32];
    session.encryptInit(encMech, pubKey);
    int len = session.encrypt(sessionKey, 0, sessionKey.length,
        buffer, 0, buffer.length);
    byte[] encryptedSessionKey = Arrays.copyOf(buffer, len);
    Arrays.fill(buffer, (byte) 0);

    // decrypt
    session.decryptInit(encMech, privKey);
    len = session.decrypt(encryptedSessionKey, 0, encryptedSessionKey.length,
        buffer, 0, buffer.length);
    byte[] decryptedSessionKey = Arrays.copyOf(buffer, len);
    Arrays.fill(buffer, (byte) 0);

    Assert.assertArrayEquals(sessionKey, decryptedSessionKey);
    LOG.info("finished");
  }

}
