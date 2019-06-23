// Copyright (c) 2002 Graz University of Technology. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. The end-user documentation included with the redistribution, if any, must
//    include the following acknowledgment:
//
//    "This product includes software developed by IAIK of Graz University of
//     Technology."
//
//    Alternately, this acknowledgment may appear in the software itself, if and
//    wherever such third-party acknowledgments normally appear.
//
// 4. The names "Graz University of Technology" and "IAIK of Graz University of
//    Technology" must not be used to endorse or promote products derived from
//    this software without prior written permission.
//
// 5. Products derived from this software may not be called "IAIK PKCS Wrapper",
//    nor may "IAIK" appear in their name, without prior written permission of
//    Graz University of Technology.
//
// THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED
// WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE LICENSOR BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
// OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
// OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
// ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package demo.pkcs.pkcs11.wrapper.encryption;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;

import demo.pkcs.pkcs11.wrapper.TestBase;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.ValuedSecretKey;

/**
 * This demo program uses a PKCS#11 module to encrypt a given file and test if
 * the data can be decrypted.
 */
public abstract class MultipleStepsSymmEncryptDecrypt extends TestBase {

  protected abstract Mechanism getKeyGenMech(Token token) throws TokenException;

  protected abstract ValuedSecretKey getKeyTemplate();

  protected abstract Mechanism getEncryptionMech(Token token)
      throws TokenException;

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
    LOG.info("##################################################");
    LOG.info("generate secret encryption/decryption key");
    Mechanism keyMechanism = getKeyGenMech(token);

    ValuedSecretKey keyTemplate = getKeyTemplate();
    keyTemplate.getToken().setBooleanValue(false);

    ValuedSecretKey encryptionKey = (ValuedSecretKey)
        session.generateKey(keyMechanism, keyTemplate);
    LOG.info("##################################################");
    LOG.info("encrypting data");

    byte[] rawData = randomBytes(1024);

    // be sure that your token can process the specified mechanism
    Mechanism encryptionMechanism = getEncryptionMech(token);

    // initialize for encryption
    session.encryptInit(encryptionMechanism, encryptionKey);

    ByteArrayOutputStream bout = new ByteArrayOutputStream(rawData.length);
    byte[] buffer = new byte[128];

    int len;

    // update
    for (int i = 0; i < rawData.length; i += 64) {
      int inLen = Math.min(rawData.length - i, 64);

      len = session.encryptUpdate(rawData, i, inLen,
          buffer, 0, buffer.length);
      if (len > 0) {
        bout.write(buffer, 0, len);
      }
    }

    // final
    len = session.encryptFinal(buffer, 0, buffer.length);
    if (len > 0) {
      bout.write(buffer, 0, len);
    }
    Arrays.fill(buffer, (byte) 0);

    byte[] encryptedData = bout.toByteArray();

    LOG.info("##################################################");
    LOG.info("trying to decrypt");

    Mechanism decryptionMechanism = getEncryptionMech(token);

    // initialize for decryption
    session.decryptInit(decryptionMechanism, encryptionKey);

    bout.reset();

    // update
    for (int i = 0; i < encryptedData.length; i += 64) {
      int inLen = Math.min(encryptedData.length - i, 64);

      len = session.decryptUpdate(encryptedData, i, inLen,
          buffer, 0, buffer.length);
      if (len > 0) {
        bout.write(buffer, 0, len);
      }
    }

    // final
    len = session.decryptFinal(buffer, 0, buffer.length);
    if (len > 0) {
      bout.write(buffer, 0, len);
    }
    Arrays.fill(buffer, (byte) 0);

    byte[] decryptedData = bout.toByteArray();
    Assert.assertArrayEquals(rawData, decryptedData);
  }

}
