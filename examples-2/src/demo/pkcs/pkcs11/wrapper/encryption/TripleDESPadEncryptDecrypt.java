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

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.DES3SecretKey;
import iaik.pkcs.pkcs11.objects.SecretKey;
import iaik.pkcs.pkcs11.parameters.InitializationVectorParameters;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * This demo program uses a PKCS#11 module to encrypt and decrypt via AES.
 *
 * @author Lijun Liao
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
  protected SecretKey getKeyTemplate() {
    SecretKey keyTemplate = new DES3SecretKey();
    keyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
    keyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
    return keyTemplate;
  }

}
