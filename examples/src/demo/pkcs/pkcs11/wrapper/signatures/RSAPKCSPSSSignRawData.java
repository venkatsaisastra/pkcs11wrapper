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

package demo.pkcs.pkcs11.wrapper.signatures;

import java.math.BigInteger;

import org.junit.Test;

import demo.pkcs.pkcs11.wrapper.TestBase;
import demo.pkcs.pkcs11.wrapper.util.Util;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.parameters.RSAPkcsPssParameters;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * Signs some raw data on the token using CKM_RSA_PKCS_PSS.
 *
 * @author Lijun Liao
 */
public class RSAPKCSPSSSignRawData extends TestBase {

  @Test
  public void main() throws TokenException {
    Token token = getNonNullToken();
    Session session = openReadOnlySession(token);
    try {
      main0(token, session);
    } finally {
      session.closeSession();
    }
  }

  private void main0(Token token, Session session) throws TokenException {
    LOG.info("##################################################");
    LOG.info("generate signature key pair");

    final long mechCode = PKCS11Constants.CKM_RSA_PKCS_PSS;
    if (!Util.supports(token, mechCode)) {
      System.out.println("Unsupported mechanism "
          + Functions.mechanismCodeToString(mechCode));
      return;
    }
    // be sure that your token can process the specified mechanism
    Mechanism signatureMechanism = getSupportedMechanism(token, mechCode);

    final boolean inToken = false;
    KeyPair generatedKeyPair =
        generateRSAKeypair(token, session, 2048, inToken);
    PrivateKey generatedPrivateKey = generatedKeyPair.getPrivateKey();

    LOG.info("##################################################");
    LOG.info("signing data");
    byte[] dataToBeSigned = randomBytes(32); // hash value

    RSAPkcsPssParameters pssParams = new RSAPkcsPssParameters(
        PKCS11Constants.CKM_SHA256, PKCS11Constants.CKG_MGF1_SHA256, 32);
    signatureMechanism.setParameters(pssParams);

    // initialize for signing
    session.signInit(signatureMechanism, generatedPrivateKey);

    // This signing operation is implemented in most of the drivers
    byte[] signatureValue = session.sign(dataToBeSigned);

    LOG.info("The signature value is: {}",
        new BigInteger(1, signatureValue).toString(16));

    LOG.info("##################################################");
  }

}
