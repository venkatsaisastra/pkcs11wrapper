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

import demo.pkcs.pkcs11.wrapper.TestBase;
import demo.pkcs.pkcs11.wrapper.util.Util;
import iaik.pkcs.pkcs11.*;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.PKCS11Object;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import org.junit.Test;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;

/**
 * This demo program generates a 2048 bit RSA key-pair on the token.
 *
 * @author Lijun Liao
 */
public class RSAGenerateKeyPair extends TestBase {

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
    LOG.info("Generating new 2048 bit RSA key-pair... ");

    // first check out what attributes of the keys we may set
    HashSet<Mechanism> supportedMechanisms = new HashSet<>(
        Arrays.asList(token.getMechanismList()));

    MechanismInfo signatureMechanismInfo;
    if (supportedMechanisms.contains(
        Mechanism.get(PKCS11Constants.CKM_RSA_PKCS))) {
      signatureMechanismInfo = token.getMechanismInfo(Mechanism
          .get(PKCS11Constants.CKM_RSA_PKCS));
    } else if (supportedMechanisms.contains(
        Mechanism.get(PKCS11Constants.CKM_RSA_X_509))) {
      signatureMechanismInfo = token.getMechanismInfo(Mechanism
          .get(PKCS11Constants.CKM_RSA_X_509));
    } else if (supportedMechanisms.contains(
        Mechanism.get(PKCS11Constants.CKM_RSA_9796))) {
      signatureMechanismInfo = token.getMechanismInfo(Mechanism
          .get(PKCS11Constants.CKM_RSA_9796));
    } else if (supportedMechanisms.contains(Mechanism
        .get(PKCS11Constants.CKM_RSA_PKCS_OAEP))) {
      signatureMechanismInfo = token.getMechanismInfo(Mechanism
          .get(PKCS11Constants.CKM_RSA_PKCS_OAEP));
    } else {
      signatureMechanismInfo = null;
    }

    final long mechCode = PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN;
    if (!Util.supports(token, mechCode)) {
      System.out.println("Unsupported mechanism "
          + Functions.mechanismCodeToString(mechCode));
      return;
    }

    Mechanism keyPairGenerationMechanism = getSupportedMechanism(
            token, mechCode);

    RSAPublicKey publicKeyTemplate = new RSAPublicKey();
    RSAPrivateKey privateKeyTemplate = new RSAPrivateKey();

    // set the general attributes for the public key
    publicKeyTemplate.getModulusBits().setLongValue(2048L);
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
    RSAPublicKey generatedPublicKey =
        (RSAPublicKey) generatedKeyPair.getPublicKey();
    RSAPrivateKey generatedPrivateKey =
        (RSAPrivateKey) generatedKeyPair.getPrivateKey();
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
      RSAPublicKey exportablePublicKey = generatedPublicKey;
      BigInteger modulus = new BigInteger(1, exportablePublicKey.getModulus()
          .getByteArrayValue());
      BigInteger publicExponent = new BigInteger(1, exportablePublicKey
          .getPublicExponent().getByteArrayValue());
      RSAPublicKeySpec rsaPublicKeySpec =
          new RSAPublicKeySpec(modulus, publicExponent);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      java.security.interfaces.RSAPublicKey javaRsaPublicKey =
          (java.security.interfaces.RSAPublicKey)
            keyFactory.generatePublic(rsaPublicKeySpec);
      X509EncodedKeySpec x509EncodedPublicKey =
          keyFactory.getKeySpec(javaRsaPublicKey, X509EncodedKeySpec.class);
      x509EncodedPublicKey.getEncoded();

      // now we try to search for the generated keys
      LOG.info("##################################################");
      LOG.info("Trying to search for the public key of the generated key-pair"
          + " by ID: {}", Functions.toHexString(id));
      // set the search template for the public key
      RSAPublicKey exportRsaPublicKeyTemplate = new RSAPublicKey();
      exportRsaPublicKeyTemplate.getId().setByteArrayValue(id);

      session.findObjectsInit(exportRsaPublicKeyTemplate);
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
