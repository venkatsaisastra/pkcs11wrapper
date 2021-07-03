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

package demo.pkcs.pkcs11.wrapper.speed.encryption;

import demo.pkcs.pkcs11.wrapper.TestBase;
import demo.pkcs.pkcs11.wrapper.util.Util;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.ValuedSecretKey;
import iaik.pkcs.pkcs11.parameters.GCMParameters;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import junit.framework.Assert;
import org.junit.Test;
import org.xipki.util.BenchmarkExecutor;

/**
 * This demo program uses a PKCS#11 module to encrypt and decrypt via
 * CKM_AES_CBC_PAD.
 *
 * @author Lijun Liao
 */
public class AESGCMPadEncryptDecryptSpeed extends TestBase {

  private class MyEncryptExecutor extends EncryptExecutor {

    public MyEncryptExecutor(Token token, char[] pin) throws TokenException {
      super(Functions.mechanismCodeToString(encryptMechanism)
              + " (" + keyLen + ") Encrypt Speed",
          getKeyGenMech(token), token, pin,
          getEncryptionMech(token), inputLen);
    }

    @Override
    protected ValuedSecretKey getMinimalKeyTemplate() {
      return getMinimalKeyTemplate0();
    }

  }

  private class MyDecryptExecutor extends DecryptExecutor {

    public MyDecryptExecutor(Token token, char[] pin) throws TokenException {
      super(Functions.mechanismCodeToString(encryptMechanism)
              + " (" + keyLen + ") Decrypt Speed",
          getKeyGenMech(token), token, pin,
          getEncryptionMech(token), inputLen);
    }

    @Override
    protected ValuedSecretKey getMinimalKeyTemplate() {
      return getMinimalKeyTemplate0();
    }

  }

  private static final long keyGenMechanism =
      PKCS11Constants.CKM_AES_KEY_GEN;

  private static final long encryptMechanism = PKCS11Constants.CKM_AES_GCM;

  private static final int inputLen = 1024;

  private static final String inputUnit = "KiB";

  private static final int keyLen = 256;

  private final byte[] iv;

  private final byte[] aad;

  public AESGCMPadEncryptDecryptSpeed() {
    iv = randomBytes(12);
    aad = "hello".getBytes();
  }

  private Mechanism getKeyGenMech(Token token) throws TokenException {
    return getSupportedMechanism(token, keyGenMechanism);
  }

  private Mechanism getEncryptionMech(Token token) throws TokenException {
    Mechanism mech = getSupportedMechanism(token, encryptMechanism);
    GCMParameters params = new GCMParameters(16, iv, aad);
    mech.setParameters(params);
    return mech;
  }

  private ValuedSecretKey getMinimalKeyTemplate0() {
    ValuedSecretKey keyTemplate = ValuedSecretKey.newAESSecretKey();
    keyTemplate.getValueLen().setLongValue((long) (keyLen / 8));
    return keyTemplate;
  }

  @Test
  public void main() throws TokenException {
    Token token = getNonNullToken();
    if (!Util.supports(token, keyGenMechanism)) {
      System.out.println(Functions.mechanismCodeToString(keyGenMechanism)
          + " is not supported, skip test");
      return;
    }

    if (!Util.supports(token, encryptMechanism)) {
      System.out.println(Functions.mechanismCodeToString(encryptMechanism)
          + " is not supported, skip test");
      return;
    }

    // check whether supported in current JDK
    try {
      new GCMParameters(16, new byte[12], null);
    } catch (IllegalStateException ex) {
      System.err.println("AES-GCM unsupported in current JDK, skip");
      return;
    }

    BenchmarkExecutor executor = new MyEncryptExecutor(token, getModulePin());
    executor.setThreads(getSpeedTestThreads());
    executor.setDuration(getSpeedTestDuration());
    executor.setUnit(inputUnit);
    executor.execute();
    Assert.assertEquals("Encrypt speed", 0, executor.getErrorAccout());

    executor = new MyDecryptExecutor(token, getModulePin());
    executor.setThreads(getSpeedTestThreads());
    executor.setDuration(getSpeedTestDuration());
    executor.setUnit(inputUnit);
    executor.execute();
    Assert.assertEquals("Decrypt speed", 0, executor.getErrorAccout());
  }

}
