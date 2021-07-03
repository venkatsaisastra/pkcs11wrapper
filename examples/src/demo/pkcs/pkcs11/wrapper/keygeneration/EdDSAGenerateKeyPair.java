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
import demo.pkcs.pkcs11.wrapper.util.Util;
import iaik.pkcs.pkcs11.*;
import iaik.pkcs.pkcs11.objects.ECPrivateKey;
import iaik.pkcs.pkcs11.objects.ECPublicKey;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.PKCS11Object;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;

/**
 * This demo program generates an Ed25519 key-pair on the token.
 *
 * @author Lijun Liao
 */
public class EdDSAGenerateKeyPair extends TestBase {

  @Test
  public void main()
      throws TokenException, NoSuchAlgorithmException, InvalidKeySpecException {
    Token token = getNonNullToken();
    Session session = openReadWriteSession(token);
    try {
      main0(token, session);
    } finally {
      session.closeSession();
    }
  }

  private void main0(Token token, Session session)
      throws TokenException {
    LOG.info("##################################################");
    LOG.info("Generating new EdDSA (curve Ed25519) key-pair... ");

    // first check out what attributes of the keys we may set
    HashSet<Mechanism> supportedMechanisms = new HashSet<>(
        Arrays.asList(token.getMechanismList()));

    MechanismInfo signatureMechanismInfo;
    if (supportedMechanisms.contains(
        Mechanism.get(PKCS11Constants.CKM_EDDSA))) {
      signatureMechanismInfo = token.getMechanismInfo(Mechanism
          .get(PKCS11Constants.CKM_EDDSA));
    } else {
      signatureMechanismInfo = null;
    }

    final long mechCode = PKCS11Constants.CKM_EC_EDWARDS_KEY_PAIR_GEN;
    if (!Util.supports(token, mechCode)) {
      System.out.println("Unsupported mechanism "
          + Functions.mechanismCodeToString(mechCode));
      return;
    }

    Mechanism keyPairGenerationMechanism = getSupportedMechanism(
            token, mechCode);

    ECPublicKey publicKeyTemplate = new ECPublicKey();
    ECPrivateKey privateKeyTemplate = new ECPrivateKey();

    // set the general attributes for the public key
    // OID: 1.3.101.112 (Ed25519)
    byte[] encodedCurveOid = new byte[] {0x06, 0x03, 0x2b, 0x65, 0x70};
    publicKeyTemplate.getEcdsaParams().setByteArrayValue(encodedCurveOid);
    publicKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
    byte[] id = new byte[20];
    new Random().nextBytes(id);
    publicKeyTemplate.getId().setByteArrayValue(id);

    privateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
    privateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
    privateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);
    privateKeyTemplate.getId().setByteArrayValue(id);

    // set the attributes in a way netscape does, this should work with most
    // tokens
    if (signatureMechanismInfo != null) {
      publicKeyTemplate.getVerify().setBooleanValue(
          signatureMechanismInfo.isVerify());
      publicKeyTemplate.getVerifyRecover().setBooleanValue(
          signatureMechanismInfo.isVerifyRecover());
      publicKeyTemplate.getEncrypt().setBooleanValue(
          signatureMechanismInfo.isEncrypt());
      publicKeyTemplate.getDerive().setBooleanValue(
          signatureMechanismInfo.isDerive());
      publicKeyTemplate.getWrap().setBooleanValue(
          signatureMechanismInfo.isWrap());
      privateKeyTemplate.getSign().setBooleanValue(
          signatureMechanismInfo.isSign());
      privateKeyTemplate.getSignRecover().setBooleanValue(
          signatureMechanismInfo.isSignRecover());
      privateKeyTemplate.getDecrypt().setBooleanValue(
          signatureMechanismInfo.isDecrypt());
      privateKeyTemplate.getDerive().setBooleanValue(
          signatureMechanismInfo.isDerive());
      privateKeyTemplate.getUnwrap().setBooleanValue(
          signatureMechanismInfo.isUnwrap());
    } else {
      // if we have no information we assume these attributes
      privateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
      privateKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);

      publicKeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);
      publicKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
    }

    // netscape does not set these attribute, so we do no either
    publicKeyTemplate.getKeyType().setPresent(false);
    publicKeyTemplate.getObjectClass().setPresent(false);

    privateKeyTemplate.getKeyType().setPresent(false);
    privateKeyTemplate.getObjectClass().setPresent(false);

    KeyPair generatedKeyPair = session.generateKeyPair(
        keyPairGenerationMechanism, publicKeyTemplate,
        privateKeyTemplate);
    ECPublicKey generatedPublicKey =
        (ECPublicKey) generatedKeyPair.getPublicKey();
    ECPrivateKey generatedPrivateKey =
        (ECPrivateKey) generatedKeyPair.getPrivateKey();
    // no we may work with the keys...

    try {
      LOG.info("Success");
      LOG.info("The public key is");
      LOG.info("__________________________________________________");
      LOG.info("{}", generatedPublicKey);
      LOG.info("__________________________________________________");
      LOG.info("The private key is");
      LOG.info("__________________________________________________");
      LOG.info("{}", generatedPrivateKey);
      LOG.info("__________________________________________________");

      LOG.info("##################################################");
      ECPublicKey exportablePublicKey = generatedPublicKey;
      byte[] encodedPoint =
          exportablePublicKey.getEcPoint().getByteArrayValue();
      byte[] curveOid =
          exportablePublicKey.getEcdsaParams().getByteArrayValue();

      LOG.info("Public Key (Point): {}", Functions.toHexString(encodedPoint));
      LOG.info("Public Key (Curve OID): {}", Functions.toHexString(curveOid));

      // now we try to search for the generated keys
      LOG.info("##################################################");
      LOG.info("Trying to search for the public key of the generated key-pair"
          + " by ID: {}", Functions.toHexString(id));
      // set the search template for the public key
      ECPublicKey exportPublicKeyTemplate = new ECPublicKey();
      exportPublicKeyTemplate.getId().setByteArrayValue(id);

      session.findObjectsInit(exportPublicKeyTemplate);
      PKCS11Object[] foundPublicKeys = session.findObjects(1);
      session.findObjectsFinal();

      if (foundPublicKeys.length != 1) {
        LOG.error("Error: Cannot find the public key under the given ID!");
      } else {
        LOG.info("Found public key!");
        LOG.info("__________________________________________________");
        LOG.info("{}", foundPublicKeys[0]);
        LOG.info("__________________________________________________");
      }

      LOG.info("##################################################");
    } finally {
      session.destroyObject(generatedPrivateKey);
      session.destroyObject(generatedPublicKey);
    }

  }

}
