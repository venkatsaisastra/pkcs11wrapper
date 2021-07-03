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
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * An object of this class represents a certificate as defined by PKCS#11.
 * A certificate is of a specific type: X_509_PUBLIC_KEY, X_509_ATTRIBUTE
 * or VENDOR_DEFINED. If an application needs to use vendor-defined
 * certificates,  it must set a VendorDefinedCertificateBuilder using the
 * setVendorDefinedCertificateBuilder method.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 */
public class Certificate extends Storage {

  /**
   * This interface defines the available certificate types as defined by
   * PKCS#11: X_509_PUBLIC_KEY, X_509_ATTRIBUTE or VENDOR_DEFINED.
   *
   * @author Karl Scheibelhofer
   * @version 1.0
   */
  public interface CertificateType {

    /**
     * The identifier for a X.509 public key certificate.
     */
    long X_509_PUBLIC_KEY = PKCS11Constants.CKC_X_509;

    /**
     * The identifier for a X.509 attribute certificate.
     */
    long X_509_ATTRIBUTE = PKCS11Constants.CKC_X_509_ATTR_CERT;

    /**
     * The identifier for a WTL certificate.
     */
    long WTLS = PKCS11Constants.CKC_WTLS;

    /**
     * The identifier for a vendor-defined certificate. Any Long object with
     * a value bigger than this one is also a valid vendor-defined
     * certificate type identifier.
     */
    long VENDOR_DEFINED = PKCS11Constants.CKC_VENDOR_DEFINED;

  }

  /**
   * If an application uses vendor defined certificates, it must implement
   * this interface and install such an object handler using
   * setVendorDefinedCertificateBuilder.
   *
   * @author Karl Scheibelhofer
   * @version 1.0
   */
  public interface VendorDefinedCertificateBuilder {

    /**
     * This method should instantiate an PKCS11Object of this class or of
     * any sub-class. It can use the given handles and PKCS#11 module to
     * retrieve attributes of the PKCS#11 object from the token.
     *
     * @param session
     *          The session to use for reading attributes. This session must
     *          have the appropriate rights; i.e. it must be a user-session,
     *          if it is a private object.
     * @param objectHandle
     *          The object handle as given from the PKCS#111 module.
     * @return The object representing the PKCS#11 object.
     *         The returned object can be casted to the
     *         according sub-class.
     * @exception sun.security.pkcs11.wrapper.PKCS11Exception
     *              If getting the attributes failed.
     */
    PKCS11Object build(Session session, long objectHandle)
        throws sun.security.pkcs11.wrapper.PKCS11Exception;

  }

  /**
   * The currently set vendor defined certificate builder, or null.
   */
  protected static VendorDefinedCertificateBuilder vendorCertificateBuilder;

  /**
   * The type of this certificate. One of CertificateType, or one that has a
   * bigger value than VENDOR_DEFINED.
   */
  protected CertificateTypeAttribute certificateType;

  /**
   * Indicates, if this certificate can be trusted.
   */
  protected BooleanAttribute trusted;

  /**
   * Categorization of the certificate:
   * 0 = unspecified (default),
   * 1 = token user,
   * 2 = authority,
   * 3 = other entity.
   */
  protected LongAttribute certificateCategory;

  /**
   * Checksum of this certificate.
   */
  protected ByteArrayAttribute checkValue;

  /**
   * The start date of this certificate's validity.
   */
  protected DateAttribute startDate;

  /**
   * The end date of this certificate's validity.
   */
  protected DateAttribute endDate;

  /**
   * The default constructor. An application use this constructor to
   * instantiate a certificate that serves as a template. It may also be
   * useful for working with vendor-defined certificates.
   */
  public Certificate() {
    objectClass.setLongValue(ObjectClass.CERTIFICATE);
  }

  /**
   * Constructor taking the reference to the PKCS#11 module for accessing the
   * object's attributes, the session handle to use for reading the attribute
   * values and the object handle. This constructor read all attributes that
   * a storage object must contain.
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
  protected Certificate(Session session, long objectHandle)
      throws TokenException {
    super(session, objectHandle);
    objectClass.setLongValue(ObjectClass.CERTIFICATE);
  }

  /**
   * Get the given certificate type as string.
   *
   * @param certificateType
   *          The certificate type to get as string.
   * @return A string denoting the object certificate type; e.g.
   *         "X.509 Public Key".
   */
  public static String getCertificateTypeName(Long certificateType) {
    Util.requireNonNull("certificateType", certificateType);
    String certificateTypeName;

    if (certificateType.equals(CertificateType.X_509_PUBLIC_KEY)) {
      certificateTypeName = "X.509 Public Key";
    } else if (certificateType.equals(CertificateType.X_509_ATTRIBUTE)) {
      certificateTypeName = "X.509 Attribute";
    } else if ((certificateType & PKCS11Constants.CKC_VENDOR_DEFINED) != 0L) {
      certificateTypeName = "Vendor Defined";
    } else {
      certificateTypeName = "<unknown>";
    }

    return certificateTypeName;
  }

  /**
   * The getInstance method of the PKCS11Object class uses this method to
   * create an instance of a PKCS#11 certificate. This method reads the
   * certificate type attribute and calls the getInstance method of the
   * according sub-class. If the certificate type is a vendor defined it
   * uses the VendorDefinedCertificateBuilder set by the application. If
   * no certificate could be constructed, Returns null.
   *
   * @param session
   *          The session to use for reading attributes. This session must
   *          have the appropriate rights; i.e. it must be a user-session, if
   *          it is a private object.
   * @param objectHandle
   *          The object handle as given from the PKCS#111 module.
   * @return The object representing the PKCS#11 object.
   *         The returned object can be casted to the
   *         according sub-class.
   * @exception TokenException
   *              If getting the attributes failed.
   */
  public static PKCS11Object getInstance(Session session, long objectHandle)
      throws TokenException {
    Util.requireNonNull("session", session);

    CertificateTypeAttribute certificateTypeAttribute
        = new CertificateTypeAttribute();
    getAttributeValue(session, objectHandle, certificateTypeAttribute);

    Long certificateType = certificateTypeAttribute.getLongValue();

    PKCS11Object newObject;

    if (certificateTypeAttribute.isPresent() && (certificateType != null)) {
      if (certificateType.equals(CertificateType.X_509_PUBLIC_KEY)) {
        newObject = X509PublicKeyCertificate.getInstance(session,
            objectHandle);
      } else if (certificateType.equals(
          CertificateType.X_509_ATTRIBUTE)) {
        newObject = X509AttributeCertificate.getInstance(session,
            objectHandle);
      } else if (certificateType.equals(CertificateType.WTLS)) {
        newObject = WTLSCertificate.getInstance(session, objectHandle);
      } else if ((certificateType & PKCS11Constants.CKC_VENDOR_DEFINED) != 0L) {
        newObject = getUnknownCertificate(session, objectHandle);
      } else {
        newObject = getUnknownCertificate(session, objectHandle);
      }
    } else {
      newObject = getUnknownCertificate(session, objectHandle);
    }

    return newObject;
  }

  /**
   * Try to create a certificate which has no or an unknown certificate type
   * attribute.
   * This implementation will try to use a vendor defined certificate builder,
   * if such has been set. If this is impossible or fails, it will create just
   * a simple {@link iaik.pkcs.pkcs11.objects.Certificate Certificate }.
   *
   * @param session
   *          The session to use for reading attributes. This session must
   *          have the appropriate rights; i.e. it must be a user-session, if
   *          it is a private object.
   * @param objectHandle
   *          The object handle as given from the PKCS#111 module.
   * @return A new PKCS11Object.
   * @throws TokenException
   *           If no object could be created.
   */
  protected static PKCS11Object getUnknownCertificate(Session session,
      long objectHandle) throws TokenException {
    Util.requireNonNull("session", session);

    PKCS11Object newObject;
    if (vendorCertificateBuilder != null) {
      try {
        newObject = vendorCertificateBuilder.build(session,
            objectHandle);
      } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
        // we can just treat it like some unknown type of certificate
        newObject = new Certificate(session, objectHandle);
      }
    } else {
      // we can just treat it like some unknown type of certificate
      newObject = new Certificate(session, objectHandle);
    }

    return newObject;
  }

  /**
   * Set a vendor-defined certificate builder that should be called to create
   * an instance of an vendor-defined PKCS#11 certificate; i.e. an instance of
   * a vendor defined sub-class of this class.
   *
   * @param builder
   *          The vendor-defined certificate builder. Null to clear any
   *          previously installed vendor-defined builder.
   */
  public static void setVendorDefinedCertificateBuilder(
      VendorDefinedCertificateBuilder builder) {
    vendorCertificateBuilder = builder;
  }

  /**
   * Get the currently set vendor-defined certificate builder.
   *
   * @return The currently set vendor-defined certificate builder or null if
   *         none is set.
   */
  public static VendorDefinedCertificateBuilder
      getVendorDefinedCertificateBuilder() {
    return vendorCertificateBuilder;
  }

  /**
   * Put all attributes of the given object into the attributes table of this
   * object. This method is only static to be able to access invoke the
   * implementation of this method for each class separately.
   *
   * @param object
   *          The object to handle.
   */
  protected static void putAttributesInTable(Certificate object) {
    Util.requireNonNull("object", object);

    object.attributeTable.put(Attribute.CERTIFICATE_TYPE,
        object.certificateType);
    object.attributeTable.put(Attribute.TRUSTED, object.trusted);
    object.attributeTable.put(Attribute.CERTIFICATE_CATEGORY,
        object.certificateCategory);
    object.attributeTable.put(Attribute.CHECK_VALUE, object.checkValue);
    object.attributeTable.put(Attribute.START_DATE, object.startDate);
    object.attributeTable.put(Attribute.END_DATE, object.endDate);
  }

  /**
   * Allocates the attribute objects for this class and adds them to the
   * attribute table.
   */
  @Override
  protected void allocateAttributes() {
    super.allocateAttributes();

    certificateType = new CertificateTypeAttribute();
    trusted = new BooleanAttribute(Attribute.TRUSTED);
    certificateCategory = new LongAttribute(Attribute.CERTIFICATE_CATEGORY);
    checkValue = new ByteArrayAttribute(Attribute.CHECK_VALUE);
    startDate = new DateAttribute(Attribute.START_DATE);
    endDate = new DateAttribute(Attribute.END_DATE);

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
    } else if (!(otherObject instanceof Certificate)) {
      return false;
    }

    Certificate other = (Certificate) otherObject;
    return super.equals(other)
        && this.certificateType.equals(other.certificateType)
        && this.trusted.equals(other.trusted)
        && this.certificateCategory.equals(other.certificateCategory)
        && this.checkValue.equals(other.checkValue)
        && this.startDate.equals(other.startDate)
        && this.endDate.equals(other.endDate);
  }

  /**
   * Gets the certificate type attribute of the PKCS#11 certificate. Its value
   * must be one of those defined in the CertificateType interface or one with
   * an value bigger than CertificateType.VENDOR_DEFINED.
   *
   * @return The certificate type attribute.
   */
  public LongAttribute getCertificateType() {
    return certificateType;
  }

  /**
   * Gets the trusted attribute of the PKCS#11 certificate.
   *
   * @return The trusted attribute.
   */
  public BooleanAttribute getTrusted() {
    return trusted;
  }

  /**
   * Gets the certificate category attribute of the PKCS#11 certificate.
   *
   * @return The certificate category attribute.
   */
  public LongAttribute getCertificateCategory() {
    return certificateCategory;
  }

  /**
   * Gets the check value attribute of of the PKCS#11 certificate.
   *
   * @return The check value attribute.
   */
  public ByteArrayAttribute getCheckValue() {
    return checkValue;
  }

  /**
   * Gets the start date attribute of the validity of the PKCS#11 certificate.
   *
   * @return The start date of validity.
   */
  public DateAttribute getStartDate() {
    return startDate;
  }

  /**
   * Gets the end date attribute of the validity of the PKCS#11 certificate.
   *
   * @return The end date of validity.
   */
  public DateAttribute getEndDate() {
    return endDate;
  }

  /**
   * The overriding of this method should ensure that the objects of this
   * class work correctly in a hashtable.
   *
   * @return The hash code of this object.
   */
  @Override
  public int hashCode() {
    return certificateType.hashCode();
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

    PKCS11Object.getAttributeValues(session, objectHandle,
        new Attribute[] {
            trusted, certificateCategory, checkValue, startDate, endDate});
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
    return Util.concatObjectsCap(superToString.length() + 100, superToString,
        "\nCertificate Type: ",
          ((certificateType != null) ? certificateType : "<unavailable>"),
        "\nTrusted: ", trusted,
        "\nCertificate Category: ", certificateCategory,
        "\nCheck Value: ", checkValue,
        "\nStart Date: ", startDate,
        "\nEnd Date: ", endDate);
  }

}
