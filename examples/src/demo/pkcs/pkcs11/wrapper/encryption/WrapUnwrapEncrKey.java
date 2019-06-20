// Copyright (c) 2002 Graz University of Technology. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
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
//    Technology" must not be used to endorse or promote products derived from this
//    software without prior written permission.
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

import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;

import demo.pkcs.pkcs11.wrapper.TestBase;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.SecretKey;
import iaik.pkcs.pkcs11.objects.ValuedSecretKey;
import iaik.pkcs.pkcs11.parameters.InitializationVectorParameters;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * This demo program uses a PKCS#11 module to wrap and unwrap a secret key. The key to be wrapped
 * must be extractable otherwise it can't be wrapped.
 */
public abstract class WrapUnwrapEncrKey extends TestBase {
  
  protected abstract Mechanism getSecretKeyMech(Token token) throws TokenException;

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
    println("################################################################################");
    println("generate secret encryption/decryption key");
    Mechanism keyMechanism = getSupportedMechanism(token, PKCS11Constants.CKM_AES_KEY_GEN);

    ValuedSecretKey secretEncryptionKeyTemplate = ValuedSecretKey.newAESSecretKey();
    secretEncryptionKeyTemplate.getToken().setBooleanValue(Boolean.FALSE);
    secretEncryptionKeyTemplate.getValueLen().setLongValue(Long.valueOf(16));
    secretEncryptionKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
    secretEncryptionKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
    secretEncryptionKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);
    secretEncryptionKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
    secretEncryptionKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);

    ValuedSecretKey encryptionKey = (ValuedSecretKey) session.generateKey(keyMechanism,
        secretEncryptionKeyTemplate);

    byte[] rawData = randomBytes(1517);

    // be sure that your token can process the specified mechanism
    Mechanism encryptionMechanism = getSupportedMechanism(token, PKCS11Constants.CKM_AES_CBC_PAD);
    Mechanism wrapMechanism = getSupportedMechanism(token, PKCS11Constants.CKM_AES_KEY_WRAP);

    byte[] encryptInitializationVector = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    InitializationVectorParameters encryptInitializationVectorParameters =
        new InitializationVectorParameters(encryptInitializationVector);
    encryptionMechanism.setParameters(encryptInitializationVectorParameters);

    // initialize for encryption
    session.encryptInit(encryptionMechanism, encryptionKey);

    byte[] buffer = new byte[rawData.length + 64];
    int cipherLen = session.encrypt(rawData, 0, rawData.length, buffer, 0, buffer.length);
    byte[] encryptedData = Arrays.copyOf(buffer, cipherLen);

    println("################################################################################");
    println("generate secret wrapping key");

    Mechanism wrapKeyMechanism = getSupportedMechanism(token, PKCS11Constants.CKM_AES_KEY_GEN);
    ValuedSecretKey wrapKeyTemplate = ValuedSecretKey.newAESSecretKey();
    wrapKeyTemplate.getToken().setBooleanValue(Boolean.FALSE);
    wrapKeyTemplate.getValueLen().setLongValue(Long.valueOf(16));
    wrapKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
    wrapKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
    wrapKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);
    wrapKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
    wrapKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);
    wrapKeyTemplate.getWrap().setBooleanValue(Boolean.TRUE);

    ValuedSecretKey wrappingKey = (ValuedSecretKey) session.generateKey(wrapKeyMechanism,
        wrapKeyTemplate);

    println("wrapping key");

    byte[] wrappedKey = session.wrapKey(wrapMechanism, wrappingKey, encryptionKey);
    ValuedSecretKey keyTemplate = new ValuedSecretKey(PKCS11Constants.CKK_AES);
    keyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
    keyTemplate.getToken().setBooleanValue(Boolean.FALSE);

    println("unwrapping key");

    SecretKey unwrappedKey = (SecretKey) session.unwrapKey(wrapMechanism,
        wrappingKey, wrappedKey, keyTemplate);

    println("################################################################################");
    println("trying to decrypt");

    Mechanism decryptionMechanism = getSupportedMechanism(token, PKCS11Constants.CKM_AES_CBC_PAD);
    byte[] decryptInitializationVector = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    InitializationVectorParameters decryptInitializationVectorParameters = new InitializationVectorParameters(
        decryptInitializationVector);
    decryptionMechanism.setParameters(decryptInitializationVectorParameters);

    // initialize for decryption
    session.decryptInit(decryptionMechanism, unwrappedKey);

    int decryptLen = session.decrypt(encryptedData, 0, encryptedData.length, buffer, 0, buffer.length);
    byte[] decryptedData = Arrays.copyOf(buffer, decryptLen);
    Arrays.fill(buffer, (byte) 0);

    Assert.assertArrayEquals(rawData, decryptedData);

    println("################################################################################");
  }

}
