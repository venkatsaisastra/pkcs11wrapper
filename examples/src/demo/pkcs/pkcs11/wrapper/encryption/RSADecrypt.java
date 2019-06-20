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
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * This demo shows how to use a PKCS#11 token to decrypt a session key encrypted by RSA.
 *
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
    Mechanism encMech = getSupportedMechanism(token, PKCS11Constants.CKM_RSA_PKCS);
    if (!token.getMechanismInfo(encMech).isDecrypt()) {
      print("This token does not support RSA decryption according to PKCS!");
      throw new TokenException("RSA decryption not supported!");
    }

    final boolean inToken = false;
    KeyPair keypair = generateRSAKeypair(token, session, 2048, inToken);
    PrivateKey privKey = keypair.getPrivateKey();
    PublicKey pubKey = keypair.getPublicKey();
    
    byte[] sessionKey = new byte[16];
    byte[] buffer = new byte[1024 / 8 + 32];
    session.encryptInit(encMech, pubKey);
    int len = session.encrypt(sessionKey, 0, sessionKey.length, buffer, 0, buffer.length);
    byte[] encryptedSessionKey = Arrays.copyOf(buffer, len);
    Arrays.fill(buffer, (byte) 0); 
    
    // decrypt
    session.decryptInit(encMech, privKey);
    len = session.decrypt(encryptedSessionKey, 0, encryptedSessionKey.length,buffer, 0, buffer.length);
    byte[] decryptedSessionKey = Arrays.copyOf(buffer, len);
    Arrays.fill(buffer, (byte) 0);
    
    Assert.assertArrayEquals(sessionKey, decryptedSessionKey);
    println("finished");
  }

}
