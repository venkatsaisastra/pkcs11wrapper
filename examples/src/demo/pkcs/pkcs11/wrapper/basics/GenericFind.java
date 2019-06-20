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

import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import org.junit.Test;

import demo.pkcs.pkcs11.wrapper.TestBase;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Attribute;
import iaik.pkcs.pkcs11.objects.BooleanAttribute;
import iaik.pkcs.pkcs11.objects.GenericTemplate;
import iaik.pkcs.pkcs11.objects.PKCS11Object;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;

/**
 * This class demonstrates how to use the GenericSearchTemplate class.
 */
public class GenericFind extends TestBase {

  @Test
  public void main() throws TokenException {
    Token token = getNonNullToken();
    Session session = openReadOnlySession(token);
    try {
      main0(session);
    } finally {
      session.closeSession();
    }
  }
  
  private void main0(Session session) throws TokenException {
    // limit output if required
    int limit = 0, counter = 1;
    
    println("################################################################################");
    println("Find all signature keys.");
    GenericTemplate signatureKeyTemplate = new GenericTemplate();
    BooleanAttribute signAttribute = new BooleanAttribute(Attribute.SIGN);
    signAttribute.setBooleanValue(Boolean.TRUE);
    signatureKeyTemplate.addAttribute(signAttribute);

    // this find operation will find all objects that posess a CKA_SIGN attribute with value true
    session.findObjectsInit(signatureKeyTemplate);

    PKCS11Object[] foundSignatureKeyObjects = session.findObjects(1); // find first

    List<PKCS11Object> signatureKeys = null;
    if (foundSignatureKeyObjects.length > 0) {
      signatureKeys = new Vector<>();
      println("________________________________________________________________________________");
      println(foundSignatureKeyObjects[0]);
      signatureKeys.add(foundSignatureKeyObjects[0]);
      while ((foundSignatureKeyObjects = session.findObjects(1)).length > 0
          && (0 == limit || counter < limit)) {
        println("________________________________________________________________________________");
        println(foundSignatureKeyObjects[0]);
        signatureKeys.add(foundSignatureKeyObjects[0]);
        counter++;
      }
      
      println("________________________________________________________________________________");
    } else {
      println("There is no object with a CKA_SIGN attribute set to true.");
      throw new TokenException("There is no object with a CKA_SIGN attribute set to true.");
    }
    session.findObjectsFinal();
    println("################################################################################");
    println("Find corresponding certificates for private signature keys.");

    List<PKCS11Object> privateSignatureKeys = new Vector<>();

    // sort out all signature keys that are private keys
    Iterator<PKCS11Object> signatureKeysIterator = signatureKeys.iterator();
    while (signatureKeysIterator.hasNext()) {
      PKCS11Object signatureKey = (PKCS11Object) signatureKeysIterator.next();
      if (signatureKey instanceof PrivateKey) {
        privateSignatureKeys.add(signatureKey);
      }
    }

    // for each private signature key try to find a public key certificate with the same ID
    Iterator<PKCS11Object> privateSignatureKeysIterator = privateSignatureKeys.iterator();
    Hashtable<PKCS11Object, PKCS11Object> privateKeyToCertificateTable
        = new Hashtable<>(privateSignatureKeys.size());
    while (privateSignatureKeysIterator.hasNext()) {
      PrivateKey privateSignatureKey = (PrivateKey) privateSignatureKeysIterator.next();
      byte[] keyID = privateSignatureKey.getId().getByteArrayValue();
      // this is the implementation that uses a concrete object class (X509PublicKeyCertificate) for
      // searching
      X509PublicKeyCertificate certificateSearchTemplate = new X509PublicKeyCertificate();
      certificateSearchTemplate.getId().setByteArrayValue(keyID);
      /*
       * // this is the implementation that uses GenericSearchTemplate class for searching, the same
       * effect as above GenericTemplate certificateSearchTemplate = new GenericTemplate();
       * LongAttribute objectClassAttribute = new LongAttribute(PKCS11Constants.CKA_CLASS);
       * objectClassAttribute.setLongValue(new Long(PKCS11Constants.CKO_CERTIFICATE));
       * certificateSearchTemplate.addAttribute(objectClassAttribute); LongAttribute
       * certificateTypeAttribute = new LongAttribute(PKCS11Constants.CKA_CERTIFICATE_TYPE);
       * certificateTypeAttribute.setLongValue(new Long(PKCS11Constants.CKC_X_509));
       * certificateSearchTemplate.addAttribute(certificateTypeAttribute); ByteArrayAttribute
       * idAttribute = new ByteArrayAttribute(PKCS11Constants.CKA_ID);
       * idAttribute.setByteArrayValue(keyID); certificateSearchTemplate.addAttribute(idAttribute);
       */

      session.findObjectsInit(certificateSearchTemplate);

      PKCS11Object[] foundCertificateObjects;
      println("________________________________________________________________________________");
      if ((foundCertificateObjects = session.findObjects(1)).length > 0) {
        privateKeyToCertificateTable.put(privateSignatureKey, foundCertificateObjects[0]);
        println("The certificate for this private signature key");
        println(privateSignatureKey);
        
        println("--------------------------------------------------------------------------------");
        println("is");
        println(foundCertificateObjects[0]);
        
      } else {
        println("There is no certificate for this private signature key");
        println(privateSignatureKey);
      }
      println("________________________________________________________________________________");

      session.findObjectsFinal();
    }

    println("found " + counter + " objects on this token");
  }

}
