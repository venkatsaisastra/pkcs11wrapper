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

package iaik.pkcs.pkcs11.objects;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.Util;

/**
 * Objects of this class represent X.509 public key certificate as specified by
 * PKCS#11 v2.11.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 */
public class X509PublicKeyCertificate extends Certificate {

  /**
   * The subject attribute of this certificate.
   */
  protected ByteArrayAttribute subject;

  /**
   * The ID attribute of this certificate.
   */
  protected ByteArrayAttribute id;

  /**
   * The issuer attribute of this certificate.
   */
  protected ByteArrayAttribute issuer;

  /**
   * The serial number attribute of this certificate.
   * Notice that netscape needs the raw serial number, but PKCS#11 defines
   * this attribute as DER encoded integer.
   */
  protected ByteArrayAttribute serialNumber;

  /**
   * The value attribute of this certificate; i.e. BER-encoded certificate.
   */
  protected ByteArrayAttribute value;

  /**
   * This attribute gives the URL where the complete certificate can be
   * obtained.
   */
  protected CharArrayAttribute url;

  /**
   * SHA-1 hash of the subject public key.
   */
  protected ByteArrayAttribute hashOfSubjectPublicKey;

  /**
   * SHA-1 hash of the issuer public key.
   */
  protected ByteArrayAttribute hashOfIssuerPublicKey;

  /**
   * Java MIDP security domain:
   * 0 = unspecified (default value),
   * 1 = manufacturer,
   * 2 = operator,
   * 3 = third party.
   */
  protected LongAttribute javaMidpSecurityDomain;

  /**
   * Default Constructor.
   */
  public X509PublicKeyCertificate() {
    certificateType.setLongValue(CertificateType.X_509_PUBLIC_KEY);
  }

  /**
   * Called by getInstance to create an instance of a PKCS#11 X.509 public key
   * certificate.
   *
   * @param session
   *          The session to use for reading attributes. This session must
   *          have the appropriate rights; i.e. it must be a user-session, if
   *          it is a private object.
   * @param objectHandle
   *          The object handle as given from the PKCS#111 module.
   * @exception TokenException
   *              If getting the attributes failed.
   */
  protected X509PublicKeyCertificate(Session session, long objectHandle)
      throws TokenException {
    super(session, objectHandle);
    certificateType.setLongValue(CertificateType.X_509_PUBLIC_KEY);
  }

  /**
   * The getInstance method of the Certificate class uses this method to
   * create an instance of a PKCS#11 X.509 public key certificate.
   *
   * @param session
   *          The session to use for reading attributes. This session must
   *          have the appropriate rights; i.e. it must be a user-session, if
   *          it is a private object.
   * @param objectHandle
   *          The object handle as given from the PKCS#111 module.
   * @return The object representing the PKCS#11 object. The returned object
   *         can be casted to the according sub-class.
   * @exception TokenException
   *              If getting the attributes failed.
   */
  public static PKCS11Object getInstance(Session session, long objectHandle)
      throws TokenException {
    return new X509PublicKeyCertificate(session, objectHandle);
  }

  /**
   * Put all attributes of the given object into the attributes table of this
   * object. This method is only static to be able to access invoke the
   * implementation of this method for each class separately.
   *
   * @param object
   *          The object to handle.
   */
  protected static void putAttributesInTable(
      X509PublicKeyCertificate object) {
    Util.requireNonNull("object", object);
    object.attributeTable.put(Attribute.SUBJECT, object.subject);
    object.attributeTable.put(Attribute.ID, object.id);
    object.attributeTable.put(Attribute.ISSUER, object.issuer);
    object.attributeTable.put(Attribute.SERIAL_NUMBER, object.serialNumber);
    object.attributeTable.put(Attribute.VALUE, object.value);
    object.attributeTable.put(Attribute.URL, object.url);
    object.attributeTable.put(Attribute.HASH_OF_SUBJECT_PUBLIC_KEY,
        object.hashOfSubjectPublicKey);
    object.attributeTable.put(Attribute.HASH_OF_ISSUER_PUBLIC_KEY,
        object.hashOfIssuerPublicKey);
    object.attributeTable.put(Attribute.JAVA_MIDP_SECURITY_DOMAIN,
        object.javaMidpSecurityDomain);
  }

  /**
   * Allocates the attribute objects for this class and adds them to the
   * attribute table.
   */
  @Override
  protected void allocateAttributes() {
    super.allocateAttributes();

    subject = new ByteArrayAttribute(Attribute.SUBJECT);
    id = new ByteArrayAttribute(Attribute.ID);
    issuer = new ByteArrayAttribute(Attribute.ISSUER);
    serialNumber = new ByteArrayAttribute(Attribute.SERIAL_NUMBER);
    value = new ByteArrayAttribute(Attribute.VALUE);
    url = new CharArrayAttribute(Attribute.URL);
    hashOfSubjectPublicKey = new ByteArrayAttribute(
      Attribute.HASH_OF_SUBJECT_PUBLIC_KEY);
    hashOfIssuerPublicKey = new ByteArrayAttribute(
      Attribute.HASH_OF_ISSUER_PUBLIC_KEY);
    javaMidpSecurityDomain = new LongAttribute(
      Attribute.JAVA_MIDP_SECURITY_DOMAIN);

    putAttributesInTable(this);
  }

  /**
   * Compares all member variables of this object with the other object.
   * Returns only true, if all are equal in both objects.
   *
   * @param otherObject
   *          The other object to compare to.
   * @return True, if other is an instance of this class and all member
   *         variables of both objects are equal. False, otherwise.
   */
  @Override
  public boolean equals(Object otherObject) {
    if (this == otherObject) {
      return true;
    } else if (!(otherObject instanceof X509PublicKeyCertificate)) {
      return false;
    }

    X509PublicKeyCertificate other = (X509PublicKeyCertificate) otherObject;
    return super.equals(other)
        && this.subject.equals(other.subject)
        && this.id.equals(other.id)
        && this.issuer.equals(other.issuer)
        && this.serialNumber.equals(other.serialNumber)
        && this.value.equals(other.value)
        && this.url.equals(other.url)
        && this.hashOfSubjectPublicKey.equals(other.hashOfSubjectPublicKey)
        && this.hashOfIssuerPublicKey.equals(other.hashOfIssuerPublicKey)
        && this.javaMidpSecurityDomain.equals(other.javaMidpSecurityDomain);
  }

  /**
   * Gets the subject attribute of this X.509 public key certificate.
   *
   * @return The subject attribute of this X.509 public key certificate.
   */
  public ByteArrayAttribute getSubject() {
    return subject;
  }

  /**
   * Gets the ID attribute of this X.509 public key certificate.
   *
   * @return The ID attribute of this X.509 public key certificate.
   */
  public ByteArrayAttribute getId() {
    return id;
  }

  /**
   * Gets the issuer attribute of this X.509 public key certificate.
   *
   * @return The issuer attribute of this X.509 public key certificate.
   */
  public ByteArrayAttribute getIssuer() {
    return issuer;
  }

  /**
   * Gets the serial number attribute of this X.509 public key certificate.
   *
   * @return The serial number attribute of this X.509 public key certificate.
   */
  public ByteArrayAttribute getSerialNumber() {
    return serialNumber;
  }

  /**
   * Gets the value attribute of this X.509 public key certificate.
   *
   * @return The value attribute of this X.509 public key certificate.
   */
  public ByteArrayAttribute getValue() {
    return value;
  }

  /**
   * Get the URL attribute of this object.
   *
   * @return Contains the URL as a char array.
   */
  public CharArrayAttribute getUrl() {
    return url;
  }

  /**
   * Gets the hash of subject public key attribute of this X.509 public key
   * certificate.
   *
   * @return The hash of subject public key attribute of this X.509 public key
   *         certificate.
   */
  public ByteArrayAttribute getHashOfSubjectPublicKey() {
    return hashOfSubjectPublicKey;
  }

  /**
   * Gets the hash of issuer public key attribute of this X.509 public key
   * certificate.
   *
   * @return The hash of issuer public key attribute of this X.509 public key
   *         certificate.
   */
  public ByteArrayAttribute getHashOfIssuerPublicKey() {
    return hashOfIssuerPublicKey;
  }

  /**
   * Gets the java midp security domain attribute of the PKCS#11 certificate.
   *
   * @return The java midp security domain category attribute.
   */
  public LongAttribute getJavaMidpSecurityDomain() {
    return javaMidpSecurityDomain;
  }

  /**
   * The overriding of this method should ensure that the objects of this
   * class work correctly in a hashtable.
   *
   * @return The hash code of this object.
   */
  @Override
  public int hashCode() {
    return issuer.hashCode() ^ serialNumber.hashCode();
  }

  /**
   * Read the values of the attributes of this object from the token.
   *
   * @param session
   *          The session to use for reading attributes. This session must
   *          have the appropriate rights; i.e. it must be a user-session, if
   *          it is a private object.
   * @exception TokenException
   *              If getting the attributes failed.
   */
  @Override
  public void readAttributes(Session session) throws TokenException {
    super.readAttributes(session);

    PKCS11Object.getAttributeValues(session, objectHandle, new Attribute[] {
        subject, id, issuer, serialNumber, value,
        url, hashOfSubjectPublicKey, hashOfIssuerPublicKey,
        javaMidpSecurityDomain });
  }

  /**
   * Returns a string representation of the current object. The
   * output is only for debugging purposes and should not be used for other
   * purposes.
   *
   * @return A string presentation of this object for debugging output.
   */
  @Override
  public String toString() {
    String superToString = super.toString();
    return Util.concatObjectsCap(superToString.length() + 200, superToString,
    "\n  Subject (DER, hex): ", subject,
    "\n  ID (hex): ", id,
    "\n  Issuer (DER, hex): ", issuer,
    "\n  Serial Number (DER, hex): ", serialNumber,
    "\n  Value (BER, hex): ", value,
    "\n  URL: ", url,
    "\n  Hash Of Subject Public Key: ", hashOfSubjectPublicKey,
    "\n  Hash Of Issuer Public Key: ", hashOfIssuerPublicKey,
    "\n  Java MIDP Security Domain: ", javaMidpSecurityDomain);
  }

}
