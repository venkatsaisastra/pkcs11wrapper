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

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;

import org.junit.Test;

import demo.pkcs.pkcs11.wrapper.TestBase;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.MechanismInfo;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.PKCS11Object;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * This demo program generates a 2048 bit RSA key-pair on the token.
 */
public class GenerateKeyPair extends TestBase {

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

    Mechanism keyPairGenerationMechanism = getSupportedMechanism(
            token, PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN);
    RSAPublicKey rsaPublicKeyTemplate = new RSAPublicKey();
    RSAPrivateKey rsaPrivateKeyTemplate = new RSAPrivateKey();

    // set the general attributes for the public key
    rsaPublicKeyTemplate.getModulusBits().setLongValue(Long.valueOf(2048));
    byte[] publicExponentBytes = { 0x01, 0x00, 0x01 }; // 2^16 + 1
    rsaPublicKeyTemplate.getPublicExponent().setByteArrayValue(
        publicExponentBytes);
    rsaPublicKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
    byte[] id = new byte[20];
    new Random().nextBytes(id);
    rsaPublicKeyTemplate.getId().setByteArrayValue(id);

    rsaPrivateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
    rsaPrivateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
    rsaPrivateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);
    rsaPrivateKeyTemplate.getId().setByteArrayValue(id);

    // set the attributes in a way netscape does, this should work with most
    // tokens
    if (signatureMechanismInfo != null) {
      rsaPublicKeyTemplate.getVerify().setBooleanValue(
          signatureMechanismInfo.isVerify());
      rsaPublicKeyTemplate.getVerifyRecover().setBooleanValue(
          signatureMechanismInfo.isVerifyRecover());
      rsaPublicKeyTemplate.getEncrypt().setBooleanValue(
          signatureMechanismInfo.isEncrypt());
      rsaPublicKeyTemplate.getDerive().setBooleanValue(
          signatureMechanismInfo.isDerive());
      rsaPublicKeyTemplate.getWrap().setBooleanValue(
          signatureMechanismInfo.isWrap());
      rsaPrivateKeyTemplate.getSign().setBooleanValue(
          signatureMechanismInfo.isSign());
      rsaPrivateKeyTemplate.getSignRecover().setBooleanValue(
          signatureMechanismInfo.isSignRecover());
      rsaPrivateKeyTemplate.getDecrypt().setBooleanValue(
          signatureMechanismInfo.isDecrypt());
      rsaPrivateKeyTemplate.getDerive().setBooleanValue(
          signatureMechanismInfo.isDerive());
      rsaPrivateKeyTemplate.getUnwrap().setBooleanValue(
          signatureMechanismInfo.isUnwrap());
    } else {
      // if we have no information we assume these attributes
      rsaPrivateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
      rsaPrivateKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);

      rsaPublicKeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);
      rsaPublicKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
    }

    // netscape does not set these attribute, so we do no either
    rsaPublicKeyTemplate.getKeyType().setPresent(false);
    rsaPublicKeyTemplate.getObjectClass().setPresent(false);

    rsaPrivateKeyTemplate.getKeyType().setPresent(false);
    rsaPrivateKeyTemplate.getObjectClass().setPresent(false);

    KeyPair generatedKeyPair = session.generateKeyPair(
        keyPairGenerationMechanism, rsaPublicKeyTemplate,
        rsaPrivateKeyTemplate);
    RSAPublicKey generatedRSAPublicKey =
        (RSAPublicKey) generatedKeyPair.getPublicKey();
    RSAPrivateKey generatedRSAPrivateKey =
        (RSAPrivateKey) generatedKeyPair.getPrivateKey();
    // no we may work with the keys...

    LOG.info("Success");
    LOG.info("The public key is");
    LOG.info("__________________________________________________");
    LOG.info("{}", generatedRSAPublicKey);
    LOG.info("__________________________________________________");
    LOG.info("The private key is");
    LOG.info("__________________________________________________");
    LOG.info("{}", generatedRSAPrivateKey);
    LOG.info("__________________________________________________");

    LOG.info("##################################################");
    RSAPublicKey exportableRsaPublicKey = generatedRSAPublicKey;
    BigInteger modulus = new BigInteger(1, exportableRsaPublicKey.getModulus()
        .getByteArrayValue());
    BigInteger publicExponent = new BigInteger(1, exportableRsaPublicKey
        .getPublicExponent().getByteArrayValue());
    RSAPublicKeySpec rsaPublicKeySpec =
        new RSAPublicKeySpec(modulus, publicExponent);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    java.security.interfaces.RSAPublicKey javaRsaPublicKey =
        (java.security.interfaces.RSAPublicKey)
          keyFactory.generatePublic(rsaPublicKeySpec);
    X509EncodedKeySpec x509EncodedPublicKey = (X509EncodedKeySpec)
        keyFactory.getKeySpec(javaRsaPublicKey, X509EncodedKeySpec.class);
    x509EncodedPublicKey.getEncoded();

    // now we try to search for the generated keys
    LOG.info("##################################################");
    LOG.info("Trying to search for the public key of the generated key-pair by"
        + " ID: {}", Functions.toHexString(id));
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
  }

}
