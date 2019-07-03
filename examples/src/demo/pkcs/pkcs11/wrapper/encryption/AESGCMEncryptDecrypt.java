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

import org.junit.Test;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.ValuedSecretKey;
import iaik.pkcs.pkcs11.parameters.GCMParameters;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * This demo program uses a PKCS#11 module to encrypt and decrypt via
 * CKM_AES_GCM.
 *
 * @author Lijun Liao
 */
public class AESGCMEncryptDecrypt extends SymmEncryptDecrypt {

  private final byte[] iv;

  private final byte[] aad;

  public AESGCMEncryptDecrypt() {
    iv = randomBytes(12);
    aad = new byte[20];
    // aad = "hello".getBytes();
  }

  @Test
  @Override
  public void main() throws TokenException {
    // check whether supported in current JDK
    try {
      new GCMParameters(16, new byte[12], null);
    } catch (IllegalStateException ex) {
      System.err.println("Unsupported in current JDK, skip");
      return;
    }

    super.main();
  }

  @Override
  protected Mechanism getKeyGenMech(Token token) throws TokenException {
    return getSupportedMechanism(token, PKCS11Constants.CKM_AES_KEY_GEN);
  }

  @Override
  protected Mechanism getEncryptionMech(Token token) throws TokenException {
    Mechanism mech = getSupportedMechanism(token, PKCS11Constants.CKM_AES_GCM);
    GCMParameters params = new GCMParameters(16, iv, aad);
    mech.setParameters(params);
    return mech;
  }

  @Override
  protected ValuedSecretKey getKeyTemplate() {
    ValuedSecretKey keyTemplate = ValuedSecretKey.newAESSecretKey();
    keyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
    keyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
    keyTemplate.getValueLen().setLongValue(Long.valueOf(16));
    return keyTemplate;
  }

}
