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

package demo.pkcs.pkcs11.wrapper.speed.keygeneration;

import org.junit.Test;

import demo.pkcs.pkcs11.wrapper.TestBase;
import demo.pkcs.pkcs11.wrapper.util.Util;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import junit.framework.Assert;

/**
 * EDDSA Keypair Generation Speed Test
 *
 * @author Lijun Liao
 */
public class RSAKeypairGenSpeed extends TestBase {

  private class MyExecutor extends KeypairGenExecutor {

    public MyExecutor(Token token, char[] pin, boolean inToken)
        throws TokenException {
      super(Functions.mechanismCodeToString(mechanism)
          + " (2048, inToken: " + inToken + ") Speed",
          mechanism, token, pin, inToken);
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

  private static final long mechanism =
      PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN;

  @Test
  public void main() throws TokenException {
    Token token = getNonNullToken();
    if (!Util.supports(token, mechanism)) {
      System.out.println(Functions.mechanismCodeToString(mechanism)
          + " is not supported, skip test");
      return;
    }

    boolean[] inTokens = new boolean[] {false, true};
    for (boolean inToken : inTokens) {
      MyExecutor executor = new MyExecutor(token, getModulePin(), inToken);
      executor.setThreads(getSpeedTestThreads());
      executor.setDuration(getSpeedTestDuration());
      executor.execute();
      Assert.assertEquals("no error", 0, executor.getErrorAccout());
    }
  }

}
