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

package demo.pkcs.pkcs11.wrapper;

import java.io.InputStream;
import java.security.SecureRandom;
import java.util.Properties;
import java.util.Random;

import demo.pkcs.pkcs11.wrapper.util.Util;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

public class TestBase {

  private static String modulePath;

  private static String modulePin;

  private static Integer slotIndex;

  private static Module module;

  private static RuntimeException initException;

  private static SecureRandom random = new SecureRandom();

  static {
    Properties props = new Properties();
    try {
      props.load(TestBase.class.getResourceAsStream("/pkcs11.properties"));
      modulePath = props.getProperty("module.path");
      modulePin = props.getProperty("module.pin");
      String str = props.getProperty("module.slotIndex");
      slotIndex = (str == null) ? null : Integer.parseInt(str);
      module = Module.getInstance(modulePath);
      module.initialize(null);
    } catch (Exception ex) {
      initException = new RuntimeException(ex);
    }
  }

  protected Token getNonNullToken() throws TokenException {
    Token token = getToken();
    if (token == null) {
      println("We have no token to proceed. Finished.");
      throw new TokenException("No token found!");
    }
    return token;
  }

  protected Token getToken() throws TokenException {
    if (initException != null) {
      throw initException;
    }
    return Util.selectToken(module, slotIndex);
  }

  protected Module getModule() {
    if (initException != null) {
      throw initException;
    }
    return module;
  }

  protected Session openReadOnlySession(Token token)
      throws TokenException {
    return Util.openAuthorizedSession(token, false,
            modulePin == null ? null : modulePin.toCharArray());
  }

  protected Session openReadOnlySession() throws TokenException {
    return openReadOnlySession(getToken());
  }

  protected Session openReadWriteSession(Token token)
      throws TokenException {
    return Util.openAuthorizedSession(token, true,
            modulePin == null ? null : modulePin.toCharArray());
  }

  protected Session openReadWriteSession() throws TokenException {
    return openReadWriteSession(getToken());
  }

  protected void print(Object obj) {
    System.out.print(obj);
  }

  protected void println(Object obj) {
    System.out.println(obj);
  }

  protected void println() {
    System.out.println();
  }

  protected InputStream getResourceAsStream(String path) {
    return getClass().getResourceAsStream(path);
  }

  protected byte[] randomBytes(int len) {
    byte[] ret = new byte[len];
    random.nextBytes(ret);
    return ret;
  }

  protected void assertSupport(Token token, Mechanism mech)
      throws TokenException {
    if (Util.supports(token, mech.getMechanismCode())) {
      return;
    } else {
      String msg = "Mechanism " + mech.getName() + " is not supported";
      println(msg);
      throw new TokenException(msg);
    }
  }

  protected Mechanism getSupportedMechanism(Token token, long mechCode)
      throws TokenException {
    Mechanism mech = Mechanism.get(mechCode);
    assertSupport(token, mech);
    return mech;
  }

  protected KeyPair generateRSAKeypair(
      Token token, Session session, int keysize, boolean inToken)
      throws TokenException {
    Mechanism keyPairGenMechanism = getSupportedMechanism(token,
        PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN);
    RSAPublicKey rsaPublicKeyTemplate = new RSAPublicKey();
    RSAPrivateKey rsaPrivateKeyTemplate = new RSAPrivateKey();

    // set the general attributes for the public key
    rsaPublicKeyTemplate.getModulusBits().setLongValue(new Long(1024));
    byte[] publicExponentBytes = { 0x01, 0x00, 0x01 }; // 2^16 + 1
    rsaPublicKeyTemplate.getPublicExponent()
        .setByteArrayValue(publicExponentBytes);
    rsaPublicKeyTemplate.getToken().setBooleanValue(Boolean.FALSE);
    byte[] id = new byte[20];
    new Random().nextBytes(id);
    rsaPublicKeyTemplate.getId().setByteArrayValue(id);

    rsaPrivateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
    rsaPrivateKeyTemplate.getToken().setBooleanValue(inToken);
    rsaPrivateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);
    rsaPrivateKeyTemplate.getId().setByteArrayValue(id);

    rsaPrivateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
    rsaPublicKeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);

    // netscape does not set these attribute, so we do no either
    rsaPublicKeyTemplate.getKeyType().setPresent(false);
    rsaPublicKeyTemplate.getObjectClass().setPresent(false);
    rsaPrivateKeyTemplate.getKeyType().setPresent(false);
    rsaPrivateKeyTemplate.getObjectClass().setPresent(false);

    KeyPair generatedKeyPair = session.generateKeyPair(keyPairGenMechanism,
        rsaPublicKeyTemplate, rsaPrivateKeyTemplate);
    return generatedKeyPair;
  }

}
