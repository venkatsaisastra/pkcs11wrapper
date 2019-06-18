// Copyright (c) 2002 Graz University of Technology. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
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
//    Technology" must not be used to endorse or promote products derived from this
//    software without prior written permission.
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

package demo.pkcs.pkcs11.wrapper.basics;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.Extension;

import demo.pkcs.pkcs11.wrapper.util.Util;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.MechanismInfo;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.TokenInfo;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * This demo program can be used to personalize a card. It uploads a private RSA key and the
 * corresponding certificate. The key and the certificate are given as a file in PKCS#12 format. The
 * usage flags of the key object are taken from the key usage flags of the certificate.
 */
public class UploadPrivateKey {

  private static final int digitalSignature  = 0;
  private static final int nonRepudiation    = 1;
  private static final int keyEncipherment   = 2;
  private static final int dataEncipherment  = 3;
  private static final int keyAgreement      = 4;
  private static final int keyCertSign       = 5;
  private static final int cRLSign           = 6;
  // private static final int encipherOnly      = 7;
  // private static final int decipherOnly      = 8; 
  
  static BufferedReader input_;

  static PrintWriter output_;

  static {
    try {
      // output_ = new PrintWriter(new FileWriter("SignAndVerify_output.txt"), true);
      output_ = new PrintWriter(System.out, true);
      input_ = new BufferedReader(new InputStreamReader(System.in));
    } catch (Throwable thr) {
      thr.printStackTrace();
      output_ = new PrintWriter(System.out, true);
      input_ = new BufferedReader(new InputStreamReader(System.in));
    }
  }

  /**
   * Usage: UploadPrivateKey PKCS#11-module PKCS#12-encoded-private-key-and-certificate
   * PKCS#12-password [slot-id] [pin]
   */
  public static void main(String[] args) throws Exception {
    if (args.length < 3) {
      printUsage();
      throw new IOException("Missing argument!");
    }

    Module pkcs11Module = Module.getInstance(args[0]);
    pkcs11Module.initialize(null);

    Token token;
    if (3 < args.length)
      token = Util.selectToken(pkcs11Module, output_, input_, args[3]);
    else
      token = Util.selectToken(pkcs11Module, output_, input_);
    if (token == null) {
      output_.println("We have no token to proceed. Finished.");
      output_.flush();
      throw new TokenException("No token found!");
    }
    TokenInfo tokenInfo = token.getTokenInfo();

    output_
        .println("################################################################################");
    output_.println("Information of Token:");
    output_.println(tokenInfo);
    output_
        .println("################################################################################");

    output_
        .println("################################################################################");
    output_.println("Reading private key and certifiacte from: " + args[1]);
    char[] filePassword = args[2].toCharArray();
    InputStream dataInputStream = new FileInputStream(args[1]);
    KeyStore keystore = KeyStore.getInstance("PKCS12");
    keystore.load(dataInputStream, filePassword);

    String keyAlias = null;
    Enumeration<String> aliases = keystore.aliases();
    while (aliases.hasMoreElements()) {
      String alias = aliases.nextElement();
      if (keystore.isKeyEntry(alias)) {
        keyAlias = alias;
        break;
      }
    }

    if (keyAlias == null) {
      output_.println("Found no private Key in the PKCS#12 file.");
      throw new IOException("Given file does not include a key!");
    }

    java.security.PrivateKey jcaPrivateKey = (PrivateKey) keystore.getKey(keyAlias, filePassword);

    if (!jcaPrivateKey.getAlgorithm().equals("RSA")) {
      output_.println("Private Key in the PKCS#12 file is not a RSA key.");
      throw new IOException("Given file does not include a RSA key!");
    }

    java.security.interfaces.RSAPrivateKey jcaRsaPrivateKey = (java.security.interfaces.RSAPrivateKey) jcaPrivateKey;

    output_.println("got private key");

    Certificate[] certificateChain = keystore.getCertificateChain(keyAlias);

    X509Certificate userCertificate = (X509Certificate) certificateChain[0];
    String userCommonName = Util.getCommontName(userCertificate.getSubjectX500Principal());
    MessageDigest sha1 = MessageDigest.getInstance("SHA1");
    byte[] encodedCert = userCertificate.getEncoded();
    byte[] certificateFingerprint = sha1.digest(encodedCert);
    boolean[] keyUsage = userCertificate.getKeyUsage();

    output_.println("got user certifiate");
    output_
        .println("################################################################################");

    Session session;
    if (4 < args.length)
      session = Util.openAuthorizedSession(token,
          Token.SessionReadWriteBehavior.RW_SESSION, output_, input_, args[4]);
    else
      session = Util.openAuthorizedSession(token,
          Token.SessionReadWriteBehavior.RW_SESSION, output_, input_, null);

    output_
        .println("################################################################################");
    output_.println("creating private key object on the card... ");
    output_.flush();

    // check out what attributes of the keys we may set using the mechanism info
    MechanismInfo signatureMechanismInfo;
    if (Util.supports(token, PKCS11Constants.CKM_RSA_PKCS)) {
      signatureMechanismInfo = token.getMechanismInfo(Mechanism
          .get(PKCS11Constants.CKM_RSA_PKCS));
    } else if (Util.supports(token, PKCS11Constants.CKM_RSA_X_509)) {
      signatureMechanismInfo = token.getMechanismInfo(Mechanism
          .get(PKCS11Constants.CKM_RSA_X_509));
    } else if (Util.supports(token, PKCS11Constants.CKM_RSA_9796)) {
      signatureMechanismInfo = token.getMechanismInfo(Mechanism
          .get(PKCS11Constants.CKM_RSA_9796));
    } else if (Util.supports(token, PKCS11Constants.CKM_RSA_PKCS_OAEP)) {
      signatureMechanismInfo = token.getMechanismInfo(Mechanism
          .get(PKCS11Constants.CKM_RSA_PKCS_OAEP));
    } else {
      signatureMechanismInfo = null;
    }

    // create private key object template
    RSAPrivateKey pkcs11RsaPrivateKey = new RSAPrivateKey();

    pkcs11RsaPrivateKey.getSensitive().setBooleanValue(Boolean.TRUE);
    // pkcs11RsaPrivateKey.getExtractable().setBooleanValue(Boolean.FALSE);
    pkcs11RsaPrivateKey.getToken().setBooleanValue(Boolean.TRUE);
    pkcs11RsaPrivateKey.getPrivate().setBooleanValue(Boolean.TRUE);
    X500Name issuerName = X500Name.getInstance(userCertificate.getIssuerX500Principal().getEncoded());
    String keyLabel = userCommonName + "'s " + Util.getRdnValue(issuerName, RFC4519Style.o);
    pkcs11RsaPrivateKey.getLabel().setCharArrayValue(keyLabel.toCharArray());

    byte[] extnValue = userCertificate.getExtensionValue(Extension.subjectKeyIdentifier.getId());
    byte[] newObjectID;
    if (extnValue != null) {
      // we take the key identifier from the certificate
      newObjectID = ASN1OctetString.getInstance(extnValue).getOctets();
    } else {
      // then we simply take the fingerprint of the certificate
      newObjectID = certificateFingerprint;
    }

    pkcs11RsaPrivateKey.getId().setByteArrayValue(newObjectID);

    // pkcs11RsaPrivateKey.getStartDate().setDateValue(userCertificate.getNotBefore());
    // pkcs11RsaPrivateKey.getEndDate().setDateValue(userCertificate.getNotAfter());

    pkcs11RsaPrivateKey.getSubject().setByteArrayValue(
        userCertificate.getSubjectX500Principal().getEncoded());

    if (keyUsage != null) {
      // set the attributes in a way netscape does, this should work with most tokens
      if (signatureMechanismInfo != null) {
        pkcs11RsaPrivateKey
            .getDecrypt()
            .setBooleanValue(
                    (keyUsage[dataEncipherment] || keyUsage[keyCertSign])
                        && signatureMechanismInfo.isDecrypt());
        pkcs11RsaPrivateKey
            .getSign()
            .setBooleanValue(
                (keyUsage[digitalSignature] || keyUsage[keyCertSign]
                    || keyUsage[cRLSign] || keyUsage[nonRepudiation])
                        && signatureMechanismInfo.isSign());
        pkcs11RsaPrivateKey
            .getSignRecover()
            .setBooleanValue(
                (keyUsage[digitalSignature] || keyUsage[keyCertSign]
                    || keyUsage[cRLSign] || keyUsage[nonRepudiation])
                    && signatureMechanismInfo.isSignRecover());
        pkcs11RsaPrivateKey.getDerive().setBooleanValue(
            keyUsage[keyAgreement]
                && signatureMechanismInfo.isDerive());
        pkcs11RsaPrivateKey.getUnwrap().setBooleanValue(
            keyUsage[keyEncipherment]
                && signatureMechanismInfo.isUnwrap());
      } else {
        // if we have no mechanism information, we try to set the flags according to the key usage
        // only
        pkcs11RsaPrivateKey.getDecrypt().setBooleanValue(
            keyUsage[dataEncipherment] || keyUsage[keyCertSign]);
        pkcs11RsaPrivateKey.getSign().setBooleanValue(
            keyUsage[digitalSignature]
                || keyUsage[keyCertSign]
                || keyUsage[cRLSign]
                || keyUsage[nonRepudiation]);
        pkcs11RsaPrivateKey.getSignRecover().setBooleanValue(
            keyUsage[digitalSignature]
                || keyUsage[keyCertSign]
                || keyUsage[cRLSign]
                || keyUsage[nonRepudiation]);
        pkcs11RsaPrivateKey.getDerive().setBooleanValue(
            keyUsage[keyAgreement]);
        pkcs11RsaPrivateKey.getUnwrap().setBooleanValue(
            keyUsage[keyEncipherment]);
      }
    } else {
      // if there is no keyusage extension in the certificate, try to set all flags according to the
      // mechanism info
      if (signatureMechanismInfo != null) {
        pkcs11RsaPrivateKey.getSign().setBooleanValue(
            Boolean.valueOf(signatureMechanismInfo.isSign()));
        pkcs11RsaPrivateKey.getSignRecover().setBooleanValue(
            Boolean.valueOf(signatureMechanismInfo.isSignRecover()));
        pkcs11RsaPrivateKey.getDecrypt().setBooleanValue(
            Boolean.valueOf(signatureMechanismInfo.isDecrypt()));
        pkcs11RsaPrivateKey.getDerive().setBooleanValue(
            Boolean.valueOf(signatureMechanismInfo.isDerive()));
        pkcs11RsaPrivateKey.getUnwrap().setBooleanValue(
            Boolean.valueOf(signatureMechanismInfo.isUnwrap()));
      } else {
        // if we have neither mechanism info nor key usage we just try all
        pkcs11RsaPrivateKey.getSign().setBooleanValue(Boolean.TRUE);
        pkcs11RsaPrivateKey.getSignRecover().setBooleanValue(Boolean.TRUE);
        pkcs11RsaPrivateKey.getDecrypt().setBooleanValue(Boolean.TRUE);
        pkcs11RsaPrivateKey.getDerive().setBooleanValue(Boolean.TRUE);
        pkcs11RsaPrivateKey.getUnwrap().setBooleanValue(Boolean.TRUE);
      }
    }

    pkcs11RsaPrivateKey.getModulus().setByteArrayValue(
        iaik.pkcs.pkcs11.Util.unsignedBigIntergerToByteArray(jcaRsaPrivateKey
            .getModulus()));
    pkcs11RsaPrivateKey.getPrivateExponent().setByteArrayValue(
        iaik.pkcs.pkcs11.Util.unsignedBigIntergerToByteArray(jcaRsaPrivateKey
            .getPrivateExponent()));
    pkcs11RsaPrivateKey
        .getPublicExponent()
        .setByteArrayValue(
            iaik.pkcs.pkcs11.Util
                .unsignedBigIntergerToByteArray(((java.security.interfaces.RSAPublicKey) userCertificate
                    .getPublicKey()).getPublicExponent()));

    if (jcaRsaPrivateKey instanceof java.security.interfaces.RSAPrivateCrtKey) {
      // if we have the CRT field, we write it to the card
      // e.g. gemsafe seems to need it
      java.security.interfaces.RSAPrivateCrtKey crtKey = (java.security.interfaces.RSAPrivateCrtKey) jcaRsaPrivateKey;
      pkcs11RsaPrivateKey.getPrime1().setByteArrayValue(
          iaik.pkcs.pkcs11.Util.unsignedBigIntergerToByteArray(crtKey.getPrimeP()));
      pkcs11RsaPrivateKey.getPrime2().setByteArrayValue(
          iaik.pkcs.pkcs11.Util.unsignedBigIntergerToByteArray(crtKey.getPrimeQ()));
      pkcs11RsaPrivateKey.getExponent1()
          .setByteArrayValue(
              iaik.pkcs.pkcs11.Util.unsignedBigIntergerToByteArray(crtKey
                  .getPrimeExponentP()));
      pkcs11RsaPrivateKey.getExponent2()
          .setByteArrayValue(
              iaik.pkcs.pkcs11.Util.unsignedBigIntergerToByteArray(crtKey
                  .getPrimeExponentQ()));
      pkcs11RsaPrivateKey.getCoefficient()
          .setByteArrayValue(
              iaik.pkcs.pkcs11.Util.unsignedBigIntergerToByteArray(crtKey
                  .getCrtCoefficient()));
    }

    output_.println(pkcs11RsaPrivateKey);
    session.createObject(pkcs11RsaPrivateKey);

    output_
        .println("################################################################################");

    output_
        .println("################################################################################");
    output_.println("creating certificate object on the card... ");
    output_.flush();

    // create certificate object template
    X509PublicKeyCertificate pkcs11X509PublicKeyCertificate = new X509PublicKeyCertificate();

    pkcs11X509PublicKeyCertificate.getToken().setBooleanValue(Boolean.TRUE);
    pkcs11X509PublicKeyCertificate.getPrivate().setBooleanValue(Boolean.FALSE);
    pkcs11X509PublicKeyCertificate.getLabel().setCharArrayValue(keyLabel.toCharArray());
    pkcs11X509PublicKeyCertificate.getSubject().setByteArrayValue(
        userCertificate.getSubjectX500Principal().getEncoded());
    pkcs11X509PublicKeyCertificate.getId().setByteArrayValue(newObjectID);
    pkcs11X509PublicKeyCertificate.getIssuer().setByteArrayValue(
        userCertificate.getIssuerX500Principal().getEncoded());

    pkcs11X509PublicKeyCertificate.getSerialNumber().setByteArrayValue(
        new ASN1Integer(userCertificate.getSerialNumber()).getEncoded());
    pkcs11X509PublicKeyCertificate.getValue().setByteArrayValue(
        userCertificate.getEncoded());

    output_.println(pkcs11X509PublicKeyCertificate);
    session.createObject(pkcs11X509PublicKeyCertificate);

    output_
        .println("################################################################################");

    session.closeSession();
    pkcs11Module.finalize(null);
  }

  public static void printUsage() {
    output_
        .println("Usage: UploadPrivateKey <PKCS#11 module> <PKCS#12 encoded private key and certificate> <PKCS#12 password> [<slot-id>] [<pin>]");
    output_
        .println(" e.g.: UploadPrivateKey pk2priv.dll privatekeyAndCert.p12 filepassword");
    output_.println("The given DLL must be in the search path of the system.");
  }

}
