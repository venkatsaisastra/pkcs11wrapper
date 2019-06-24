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

package demo.pkcs.pkcs11.wrapper.keygeneration;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;

import org.junit.Test;

import demo.pkcs.pkcs11.wrapper.TestBase;
import demo.pkcs.pkcs11.wrapper.util.Util;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.MechanismInfo;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.ECPrivateKey;
import iaik.pkcs.pkcs11.objects.ECPublicKey;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.PKCS11Object;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * This demo program generates a 2048 bit RSA key-pair on the token.
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
      throws TokenException, NoSuchAlgorithmException, InvalidKeySpecException {
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

      LOG.info("Public Key (Point): ", Functions.toHexString(encodedPoint));
      LOG.info("Public Key (Curve OID): ", Functions.toHexString(curveOid));

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
