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

package demo.pkcs.pkcs11.wrapper.keygeneration;

import demo.pkcs.pkcs11.wrapper.TestBase;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.ValuedSecretKey;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import org.junit.Test;

/**
 * This demo program shows how to generate secret keys.
 *
 * @author Lijun Liao
 */
public class GenerateKey extends TestBase {

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
    Mechanism mech = getSupportedMechanism(token,
        PKCS11Constants.CKM_GENERIC_SECRET_KEY_GEN);
    LOG.info("##################################################");
    LOG.info("Generating generic secret key");

    ValuedSecretKey secretKeyTemplate = ValuedSecretKey.newGenericSecretKey();
    secretKeyTemplate.getValueLen().setLongValue(16L);
    secretKeyTemplate.getToken().setBooleanValue(Boolean.FALSE);

    ValuedSecretKey secretKey = (ValuedSecretKey) session.generateKey(
        mech, secretKeyTemplate);

    LOG.info("the secret key is\n{}", secretKey);
    LOG.info("##################################################");
  }

}
