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

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.ValuedSecretKey;
import iaik.pkcs.pkcs11.parameters.InitializationVectorParameters;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * This demo program uses a PKCS#11 module to encrypt and decrypt via AES.
 */
public class TripleDESPadEncryptDecrypt extends SymmEncryptDecrypt {

  private final byte[] iv;

  public TripleDESPadEncryptDecrypt() {
    iv = randomBytes(8);
  }

  @Override
  protected Mechanism getKeyGenMech(Token token) throws TokenException {
    return getSupportedMechanism(token, PKCS11Constants.CKM_DES3_KEY_GEN);
  }

  @Override
  protected Mechanism getEncryptionMech(Token token) throws TokenException {
    Mechanism mech = getSupportedMechanism(token,
        PKCS11Constants.CKM_DES3_CBC_PAD);
    InitializationVectorParameters encryptIVParameters =
        new InitializationVectorParameters(iv);
    mech.setParameters(encryptIVParameters);
    return mech;
  }

  @Override
  protected ValuedSecretKey getKeyTemplate() {
    ValuedSecretKey keyTemplate = ValuedSecretKey.newDES3SecretKey();
    keyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
    keyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
    return keyTemplate;
  }

}
