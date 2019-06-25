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

package demo.pkcs.pkcs11.wrapper.speed;

import org.junit.Test;

import demo.pkcs.pkcs11.wrapper.TestBase;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * EDDSA Keypair Generation Speed Test
 *
 * @author Lijun Liao
 */
public class RSAKeypairGenSpeed extends TestBase {

  private class MyExecutor extends KeypairGenExecutor {

    public MyExecutor(Token token, char[] pin) throws TokenException {
      super(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN, token, pin);
    }

    @Override
    protected PrivateKey getMinimalPrivateKeyTemplate() {
      return new RSAPrivateKey();
    }

    @Override
    protected PublicKey getMinimalPublicKeyTemplate() {
      RSAPublicKey publicKeyTemplate = new RSAPublicKey();
      publicKeyTemplate.getModulusBits().setLongValue(Long.valueOf(2048));
      return publicKeyTemplate;
    }

  }

  @Test
  public void main() throws TokenException {
    Token token = getNonNullToken();
    Session session = openReadOnlySession(token);
    try {
      MyExecutor executor = new MyExecutor(token, getModulePin());
      executor.setThreads(4);
      executor.execute();
    } finally {
      session.closeSession();
    }
  }

}
