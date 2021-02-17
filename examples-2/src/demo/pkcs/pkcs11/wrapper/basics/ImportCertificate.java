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

package demo.pkcs.pkcs11.wrapper.basics;

import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAParams;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.crypto.spec.DHParameterSpec;
import javax.security.auth.x500.X500Principal;

import org.junit.Test;

import demo.pkcs.pkcs11.wrapper.TestBase;
import demo.pkcs.pkcs11.wrapper.util.Util;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.TokenInfo;
import iaik.pkcs.pkcs11.objects.DHPrivateKey;
import iaik.pkcs.pkcs11.objects.DSAPrivateKey;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;

/**
 * This demo program imports a given X.509 certificate onto a PKCS#11 token.
 */
public class ImportCertificate extends TestBase {

  private static final String resourceFile = "/demo_cert.der";

  @Test
  public void main()
      throws TokenException, CertificateException, NoSuchAlgorithmException {
    Token token = getNonNullToken();
    TokenInfo tokenInfo = token.getTokenInfo();

    LOG.info("##################################################");
    LOG.info("Information of Token:\n{}", tokenInfo);
    LOG.info("##################################################");

    Session session = openReadWriteSession(token);
    try {
      main0(session);
    } finally {
      session.closeSession();
    }
  }

  private void main0(Session session)
      throws TokenException, CertificateException, NoSuchAlgorithmException {
    LOG.info("Reading certificate from resource file: {}", resourceFile);

    // parse certificate
    CertificateFactory certificateFactory =
        CertificateFactory.getInstance("X.509");
    InputStream inputStream = getResourceAsStream(resourceFile);
    Collection<? extends Certificate> certChain = certificateFactory
        .generateCertificates(inputStream);
    if (certChain.size() < 1) {
      LOG.error("Did not find any certificate in the given input file.");
      throw new CertificateException("No certificate found!");
    }
    X509Certificate x509Certificate =
        (X509Certificate) certChain.iterator().next();
    certChain.remove(x509Certificate);

    LOG.info("##################################################");
    LOG.info("Searching for corresponding private key on token.");

    PublicKey publicKey = x509Certificate.getPublicKey();

    iaik.pkcs.pkcs11.objects.Object searchTemplate = null;
    if (publicKey.getAlgorithm().equalsIgnoreCase("RSA")) {
      java.security.interfaces.RSAPublicKey rsaPublicKey =
          (java.security.interfaces.RSAPublicKey) publicKey;
      RSAPrivateKey rsaPrivateKeySearchTemplate = new RSAPrivateKey();
      byte[] modulus =
          unsignedBigIntergerToByteArray(rsaPublicKey.getModulus());
      rsaPrivateKeySearchTemplate.getModulus().setByteArrayValue(modulus);
      searchTemplate = rsaPrivateKeySearchTemplate;
    } else if (publicKey.getAlgorithm().equalsIgnoreCase("DSA")) {
      java.security.interfaces.DSAPublicKey dsaPublicKey =
          (java.security.interfaces.DSAPublicKey) publicKey;
      DSAParams dsaParams = dsaPublicKey.getParams();
      DSAPrivateKey dsaPrivateKeySearchTemplate = new DSAPrivateKey();
      byte[] g = unsignedBigIntergerToByteArray(dsaParams.getG());
      byte[] p = unsignedBigIntergerToByteArray(dsaParams.getP());
      byte[] q = unsignedBigIntergerToByteArray(dsaParams.getQ());
      dsaPrivateKeySearchTemplate.getBase().setByteArrayValue(g);
      dsaPrivateKeySearchTemplate.getPrime().setByteArrayValue(p);
      dsaPrivateKeySearchTemplate.getSubprime().setByteArrayValue(q);
      searchTemplate = dsaPrivateKeySearchTemplate;
    } else if (publicKey.getAlgorithm().equalsIgnoreCase("DH")
        || publicKey.getAlgorithm().equalsIgnoreCase("DiffieHellman")) {
      javax.crypto.interfaces.DHPublicKey dhPublicKey =
          (javax.crypto.interfaces.DHPublicKey) publicKey;
      DHParameterSpec dhParams = dhPublicKey.getParams();
      DHPrivateKey dhPrivateKeySearchTemplate = new DHPrivateKey();
      byte[] g = unsignedBigIntergerToByteArray(dhParams.getG());
      byte[] p = unsignedBigIntergerToByteArray(dhParams.getP());
      dhPrivateKeySearchTemplate.getBase().setByteArrayValue(g);
      dhPrivateKeySearchTemplate.getPrime().setByteArrayValue(p);
      searchTemplate = dhPrivateKeySearchTemplate;
    }

    byte[] objectID = null;
    if (searchTemplate != null) {
      session.findObjectsInit(searchTemplate);
      iaik.pkcs.pkcs11.objects.Object[] foundKeyObjects =
          session.findObjects(1);
      if (foundKeyObjects.length > 0) {
        Key foundKey = (Key) foundKeyObjects[0];
        objectID = foundKey.getId().getByteArrayValue();
        LOG.info("found a correponding key on the token:\n{}", foundKey);
      } else {
        LOG.info("found no correponding key on the token.");
      }
      session.findObjectsFinal();
    } else {
      LOG.info("public key is neither RSA, DSA nor DH.");
    }

    LOG.info("##################################################");
    LOG.info("Create certificate object(s) on token.");

    // start with user cert
    X509Certificate currentCertificate = x509Certificate;
    boolean importedCompleteChain = false;

    List<iaik.pkcs.pkcs11.objects.Object> importedObjects = new ArrayList<>();

    try {
      while (!importedCompleteChain) {
        // create certificate object template
        X509PublicKeyCertificate pkcs11X509PublicKeyCertificate =
            new X509PublicKeyCertificate();
        X500Principal subjectName =
            currentCertificate.getSubjectX500Principal();
        X500Principal issuerName = currentCertificate.getIssuerX500Principal();
        byte[] encodedSubject = subjectName.getEncoded();
        byte[] encodedIssuer = issuerName.getEncoded();

        String subjectCommonName = Util.getCommontName(subjectName);
        String issuerCommonName = Util.getCommontName(issuerName);
        char[] label = (subjectCommonName + "'s " +
            ((issuerCommonName != null) ? issuerCommonName + " " : "")
            + "Certificate").toCharArray();

        byte[] newObjectID;
        // if we need a new object ID, create one
        if (objectID == null) {
          MessageDigest digest = MessageDigest.getInstance("SHA-1");

          if (publicKey instanceof java.security.interfaces.RSAPublicKey) {
            newObjectID = ((java.security.interfaces.RSAPublicKey) publicKey)
                .getModulus().toByteArray();
            newObjectID = digest.digest(newObjectID);
          } else if (publicKey instanceof
              java.security.interfaces.DSAPublicKey) {
            newObjectID = ((java.security.interfaces.DSAPublicKey) publicKey)
                .getY().toByteArray();
            newObjectID = digest.digest(newObjectID);
          } else {
            byte[] encodedCert = currentCertificate.getEncoded();
            newObjectID = digest.digest(encodedCert);
          }
        } else {
          // we already got one from a corresponding private key before
          newObjectID = objectID;
        }

        byte[] encodedAsn1serialNumber = Util.encodedAsn1Integer(
            currentCertificate.getSerialNumber());

        pkcs11X509PublicKeyCertificate.getToken().setBooleanValue(Boolean.TRUE);
        pkcs11X509PublicKeyCertificate.getPrivate()
            .setBooleanValue(Boolean.FALSE);
        pkcs11X509PublicKeyCertificate.getLabel().setCharArrayValue(label);
        pkcs11X509PublicKeyCertificate.getId().setByteArrayValue(newObjectID);
        pkcs11X509PublicKeyCertificate.getSubject()
            .setByteArrayValue(encodedSubject);
        pkcs11X509PublicKeyCertificate.getIssuer()
            .setByteArrayValue(encodedIssuer);
        pkcs11X509PublicKeyCertificate.getSerialNumber()
            .setByteArrayValue(encodedAsn1serialNumber);
        pkcs11X509PublicKeyCertificate.getValue().setByteArrayValue(
            currentCertificate.getEncoded());

        LOG.info("{}", pkcs11X509PublicKeyCertificate);
        LOG.info("___________________________________________________");
        importedObjects.add(
            session.createObject(pkcs11X509PublicKeyCertificate));

        if (certChain.size() > 0) {
          currentCertificate = (X509Certificate) certChain.iterator().next();
          certChain.remove(currentCertificate);
          objectID = null; // do not use the same ID for other certificates
        } else {
          importedCompleteChain = true;
        }
      }
    } finally {
      // delete the objects just created
      for (iaik.pkcs.pkcs11.objects.Object obj : importedObjects) {
        session.destroyObject(obj);
      }
    }

    LOG.info("##################################################");
  }

  private static byte[] unsignedBigIntergerToByteArray(BigInteger bigInteger) {
    return iaik.pkcs.pkcs11.Util.unsignedBigIntergerToByteArray(bigInteger);
  }

}
