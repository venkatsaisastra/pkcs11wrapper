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

import iaik.pkcs.pkcs11.Util;
import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;

import java.util.HashSet;
import java.util.Hashtable;
import java.util.Set;

import static iaik.pkcs.pkcs11.wrapper.PKCS11Constants.*;

/**
 * This is the base-class for all types of attributes. In general, all PKCS#11
 * objects are just a collection of attributes. PKCS#11 specifies which
 * attributes each type of objects must have.
 * In some cases, attributes are optional (e.g. in RSAPrivateKey). In such a
 * case, this attribute will return false when the application calls
 * isPresent() on this attribute. This means, that the object does not
 * possess this attribute (maybe even though it should, but not all drivers
 * seem to implement the standard correctly). Handling attributes in this
 * fashion ensures that this library can work also with drivers that are
 * not fully compliant.
 * Moreover, certain attributes can be sensitive; i.e. their values cannot
 * be read, e.g. the private exponent of a RSA private key.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 */
public abstract class Attribute {

  public static final long CLASS                = CKA_CLASS;
  public static final long TOKEN                = CKA_TOKEN;
  public static final long PRIVATE              = CKA_PRIVATE;
  public static final long LABEL                = CKA_LABEL;
  public static final long APPLICATION          = CKA_APPLICATION;
  public static final long VALUE                = CKA_VALUE;
  public static final long OBJECT_ID            = CKA_OBJECT_ID;
  public static final long CERTIFICATE_TYPE     = CKA_CERTIFICATE_TYPE;
  public static final long ISSUER               = CKA_ISSUER;
  public static final long SERIAL_NUMBER        = CKA_SERIAL_NUMBER;
  public static final long URL                  = CKA_URL;
  public static final long HASH_OF_SUBJECT_PUBLIC_KEY
          = CKA_HASH_OF_SUBJECT_PUBLIC_KEY;
  public static final long HASH_OF_ISSUER_PUBLIC_KEY
          = CKA_HASH_OF_ISSUER_PUBLIC_KEY;
  public static final long JAVA_MIDP_SECURITY_DOMAIN
          = CKA_JAVA_MIDP_SECURITY_DOMAIN;
  public static final long AC_ISSUER            = CKA_AC_ISSUER;
  public static final long OWNER                = CKA_OWNER;
  public static final long ATTR_TYPES           = CKA_ATTR_TYPES;
  public static final long TRUSTED              = CKA_TRUSTED;
  public static final long KEY_TYPE             = CKA_KEY_TYPE;
  public static final long SUBJECT              = CKA_SUBJECT;
  public static final long ID                   = CKA_ID;
  public static final long CHECK_VALUE          = CKA_CHECK_VALUE;
  public static final long CERTIFICATE_CATEGORY = CKA_CERTIFICATE_CATEGORY;
  public static final long SENSITIVE            = CKA_SENSITIVE;
  public static final long ENCRYPT              = CKA_ENCRYPT;
  public static final long DECRYPT              = CKA_DECRYPT;
  public static final long WRAP                 = CKA_WRAP;
  public static final long WRAP_TEMPLATE        = CKA_WRAP_TEMPLATE;
  public static final long UNWRAP               = CKA_UNWRAP;
  public static final long UNWRAP_TEMPLATE      = CKA_UNWRAP_TEMPLATE;
  public static final long SIGN                 = CKA_SIGN;
  public static final long SIGN_RECOVER         = CKA_SIGN_RECOVER;
  public static final long VERIFY               = CKA_VERIFY;
  public static final long VERIFY_RECOVER       = CKA_VERIFY_RECOVER;
  public static final long DERIVE               = CKA_DERIVE;
  public static final long START_DATE           = CKA_START_DATE;
  public static final long END_DATE             = CKA_END_DATE;
  public static final long MECHANISM_TYPE       = CKA_MECHANISM_TYPE;
  public static final long MODULUS              = CKA_MODULUS;
  public static final long MODULUS_BITS         = CKA_MODULUS_BITS;
  public static final long PUBLIC_EXPONENT      = CKA_PUBLIC_EXPONENT;
  public static final long PRIVATE_EXPONENT     = CKA_PRIVATE_EXPONENT;
  public static final long PRIME_1              = CKA_PRIME_1;
  public static final long PRIME_2              = CKA_PRIME_2;
  public static final long EXPONENT_1           = CKA_EXPONENT_1;
  public static final long EXPONENT_2           = CKA_EXPONENT_2;
  public static final long COEFFICIENT          = CKA_COEFFICIENT;
  public static final long PRIME                = CKA_PRIME;
  public static final long SUBPRIME             = CKA_SUBPRIME;
  public static final long BASE                 = CKA_BASE;
  public static final long PRIME_BITS           = CKA_PRIME_BITS;
  public static final long SUB_PRIME_BITS       = CKA_SUB_PRIME_BITS;
  public static final long VALUE_BITS           = CKA_VALUE_BITS;
  public static final long VALUE_LEN            = CKA_VALUE_LEN;
  public static final long EXTRACTABLE          = CKA_EXTRACTABLE;
  public static final long LOCAL                = CKA_LOCAL;
  public static final long NEVER_EXTRACTABLE    = CKA_NEVER_EXTRACTABLE;
  public static final long WRAP_WITH_TRUSTED    = CKA_WRAP_WITH_TRUSTED;
  public static final long ALWAYS_SENSITIVE     = CKA_ALWAYS_SENSITIVE;
  public static final long ALWAYS_AUTHENTICATE  = CKA_ALWAYS_AUTHENTICATE;
  public static final long KEY_GEN_MECHANISM    = CKA_KEY_GEN_MECHANISM;
  public static final long ALLOWED_MECHANISMS   = CKA_ALLOWED_MECHANISMS;
  public static final long MODIFIABLE           = CKA_MODIFIABLE;
  public static final long EC_PARAMS            = CKA_EC_PARAMS;
  public static final long EC_POINT             = CKA_EC_POINT;
  @SuppressWarnings("deprecation")
  public static final long SECONDARY_AUTH       = CKA_SECONDARY_AUTH;
  @SuppressWarnings("deprecation")
  public static final long AUTH_PIN_FLAGS       = CKA_AUTH_PIN_FLAGS;
  public static final long HW_FEATURE_TYPE      = CKA_HW_FEATURE_TYPE;
  public static final long RESET_ON_INIT        = CKA_RESET_ON_INIT;
  public static final long HAS_RESET            = CKA_HAS_RESET;
  public static final long VENDOR_DEFINED       = CKA_VENDOR_DEFINED;
  public static final long PIXEL_X              = CKA_PIXEL_X;
  public static final long PIXEL_Y              = CKA_PIXEL_Y;
  public static final long RESOLUTION           = CKA_RESOLUTION;
  public static final long CHAR_ROWS            = CKA_CHAR_ROWS;
  public static final long CHAR_COLUMNS         = CKA_CHAR_COLUMNS;
  public static final long COLOR                = CKA_COLOR;
  public static final long BITS_PER_PIXEL       = CKA_BITS_PER_PIXEL;
  public static final long CHAR_SETS            = CKA_CHAR_SETS;
  public static final long ENCODING_METHODS     = CKA_ENCODING_METHODS;
  public static final long MIME_TYPES           = CKA_MIME_TYPES;

  protected static Hashtable<Long, String> attributeNames;
  protected static Hashtable<Long, Class<?>> attributeClasses;

  /**
   * True, if the object really possesses this attribute.
   */
  protected boolean present;

  /**
   * True, if this attribute is sensitive.
   */
  protected boolean sensitive;

  /**
   * The CK_ATTRIBUTE that is used to hold the PKCS#11 type of this attribute
   * and the value.
   */
  protected CK_ATTRIBUTE ckAttribute;

  /**
   * Empty constructor.
   * Attention! If you use this constructor, you must set ckAttribute to
   * ensure that the class invariant is not violated.
   */
  protected Attribute() { /* left empty intentionally */
  }

  /**
   * Constructor taking the PKCS#11 type of the attribute.
   *
   * @param type
   *          The PKCS#11 type of this attribute; e.g.
   *          PKCS11Constants.CKA_PRIVATE.
   */
  protected Attribute(long type) {
    present = false;
    sensitive = false;
    ckAttribute = new CK_ATTRIBUTE();
    ckAttribute.type = type;
  }

  /**
   * Get the name of the given attribute type.
   *
   * @param type
   *          The attribute type.
   * @return The name of the attribute type, or null if there is no such type.
   */
  protected static synchronized String getAttributeName(long type) {
    if (attributeNames == null) {
      attributeNames = new Hashtable<>(85);
      attributeNames.put(CLASS, "Class");
      attributeNames.put(TOKEN, "Token");
      attributeNames.put(PRIVATE, "Private");
      attributeNames.put(LABEL, "Label");
      attributeNames.put(APPLICATION, "Application");
      attributeNames.put(VALUE, "Value");
      attributeNames.put(OBJECT_ID, "PKCS11Object ID");
      attributeNames.put(CERTIFICATE_TYPE, "Certificate Type");
      attributeNames.put(ISSUER, "Issuer");
      attributeNames.put(SERIAL_NUMBER, "Serial Number");
      attributeNames.put(URL, "URL");
      attributeNames.put(HASH_OF_SUBJECT_PUBLIC_KEY,
          "Hash Of Subject Public Key");
      attributeNames.put(HASH_OF_ISSUER_PUBLIC_KEY,
          "Hash Of Issuer Public Key");
      attributeNames.put(JAVA_MIDP_SECURITY_DOMAIN,
          "Java MIDP Security Domain");
      attributeNames.put(AC_ISSUER, "AC Issuer");
      attributeNames.put(OWNER, "Owner");
      attributeNames.put(ATTR_TYPES, "Attribute Types");
      attributeNames.put(TRUSTED, "Trusted");
      attributeNames.put(KEY_TYPE, "Key Type");
      attributeNames.put(SUBJECT, "Subject");
      attributeNames.put(ID, "ID");
      attributeNames.put(CHECK_VALUE, "Check Value");
      attributeNames.put(CERTIFICATE_CATEGORY, "Certificate Category");
      attributeNames.put(SENSITIVE, "Sensitive");
      attributeNames.put(ENCRYPT, "Encrypt");
      attributeNames.put(DECRYPT, "Decrypt");
      attributeNames.put(WRAP, "Wrap");
      attributeNames.put(UNWRAP, "Unwrap");
      attributeNames.put(WRAP_TEMPLATE, "Wrap Template");
      attributeNames.put(UNWRAP_TEMPLATE, "Unwrap Template");
      attributeNames.put(SIGN, "Sign");
      attributeNames.put(SIGN_RECOVER, "Sign Recover");
      attributeNames.put(VERIFY, "Verify");
      attributeNames.put(VERIFY_RECOVER, "Verify Recover");
      attributeNames.put(DERIVE, "Derive");
      attributeNames.put(START_DATE, "Start Date");
      attributeNames.put(END_DATE, "End Date");
      attributeNames.put(MODULUS, "Modulus");
      attributeNames.put(MODULUS_BITS, "Modulus Bits");
      attributeNames.put(PUBLIC_EXPONENT, "Public Exponent");
      attributeNames.put(PRIVATE_EXPONENT, "Private Exponent");
      attributeNames.put(PRIME_1, "Prime 1");
      attributeNames.put(PRIME_2, "Prime 2");
      attributeNames.put(EXPONENT_1, "Exponent 1");
      attributeNames.put(EXPONENT_2, "Exponent 2");
      attributeNames.put(COEFFICIENT, "Coefficient");
      attributeNames.put(PRIME, "Prime");
      attributeNames.put(SUBPRIME, "Subprime");
      attributeNames.put(BASE, "Base");
      attributeNames.put(PRIME_BITS, "Prime Pits");
      attributeNames.put(SUB_PRIME_BITS, "Subprime Bits");
      attributeNames.put(VALUE_BITS, "Value Bits");
      attributeNames.put(VALUE_LEN, "Value Length");
      attributeNames.put(EXTRACTABLE, "Extractable");
      attributeNames.put(LOCAL, "Local");
      attributeNames.put(NEVER_EXTRACTABLE, "Never Extractable");
      attributeNames.put(WRAP_WITH_TRUSTED, "Wrap With Trusted");
      attributeNames.put(ALWAYS_SENSITIVE, "Always Sensitive");
      attributeNames.put(ALWAYS_AUTHENTICATE, "Always Authenticate");
      attributeNames.put(KEY_GEN_MECHANISM, "Key Generation Mechanism");
      attributeNames.put(ALLOWED_MECHANISMS, "Allowed Mechanisms");
      attributeNames.put(MODIFIABLE, "Modifiable");
      attributeNames.put(EC_PARAMS, "EC Parameters");
      attributeNames.put(EC_POINT, "EC Point");
      attributeNames.put(SECONDARY_AUTH, "Secondary Authentication");
      attributeNames.put(AUTH_PIN_FLAGS, "Authentication PIN Flags");
      attributeNames.put(HW_FEATURE_TYPE, "Hardware Feature Type");
      attributeNames.put(RESET_ON_INIT, "Reset on Initialization");
      attributeNames.put(HAS_RESET, "Has been reset");
      attributeNames.put(VENDOR_DEFINED, "Vendor Defined");
    }

    String name;

    if ((type & VENDOR_DEFINED) != 0L) {
      StringBuilder nameBuffer = new StringBuilder(36);
      nameBuffer.append("VENDOR_DEFINED [0x");
      nameBuffer.append(Long.toHexString(type));
      nameBuffer.append(']');
      name = nameBuffer.toString();
    } else {
      name = attributeNames.get(type);
      if (name == null) {
        StringBuilder nameBuffer = new StringBuilder(25);
        nameBuffer.append("[0x");
        nameBuffer.append(Long.toHexString(type));
        nameBuffer.append(']');
        name = nameBuffer.toString();
      }
    }

    return name;
  }

  /**
   * Get the class of the given attribute type.
   * Current existing Attribute classes are:
   *           AttributeArray
   *           BooleanAttribute
   *           ByteArrayAttribute
   *           CertificateTypeAttribute
   *           CharArrayAttribute
   *           DateAttribute
   *           HardwareFeatureTypeAttribute
   *           KeyTypeAttribute
   *           LongAttribute
   *           MechanismAttribute
   *           MechanismArrayAttribute
   *           ObjectClassAttribute
   * @param type
   *          The attribute type.
   * @return The class of the attribute type, or null if there is no such
   *         type.
   */
  protected static synchronized Class<?> getAttributeClass(long type) {
    if (attributeClasses == null) {
      Set<Long> boolSet = new HashSet<>();
      // CHECKSTYLE:SKIP
      Set<Long> longSet = new HashSet<>();
      // CHECKSTYLE:SKIP
      Set<Long> barrSet = new HashSet<>();
      // CHECKSTYLE:SKIP
      Set<Long> carrSet = new HashSet<>();

      attributeClasses = new Hashtable<>(85);
      attributeClasses.put(CLASS,
          ObjectClassAttribute.class); //CK_OBJECT_CLASS
      boolSet.add(TOKEN); //CK_BBOOL
      boolSet.add(PRIVATE);//CK_BBOOL
      carrSet.add(LABEL); //RFC2279 string
      carrSet.add(APPLICATION); //RFC2279 string
      barrSet.add(VALUE); //Byte Array
      barrSet.add(OBJECT_ID); //Byte Array
      attributeClasses.put(CERTIFICATE_TYPE,
          CertificateTypeAttribute.class); //CK_CERTIFICATE_TYPE
      barrSet.add(ISSUER); //Byte array
      barrSet.add(SERIAL_NUMBER); //Byte array
      carrSet.add(URL); //RFC2279 string
      barrSet.add(HASH_OF_SUBJECT_PUBLIC_KEY); //Byte array
      barrSet.add(HASH_OF_ISSUER_PUBLIC_KEY); //Byte array
      longSet.add(JAVA_MIDP_SECURITY_DOMAIN); //CK_ULONG
      barrSet.add(AC_ISSUER); //Byte array
      barrSet.add(OWNER); //Byte array
      barrSet.add(ATTR_TYPES); //Byte array
      boolSet.add(TRUSTED); //CK_BBOOL
      attributeClasses.put(KEY_TYPE, KeyTypeAttribute.class); //CK_KEY_TYPE
      barrSet.add(SUBJECT); //Byte array
      barrSet.add(ID); //Byte array
      barrSet.add(CHECK_VALUE); //Byte array
      longSet.add(CERTIFICATE_CATEGORY); //CK_ULONG
      boolSet.add(SENSITIVE); //CK_BBOOL
      boolSet.add(ENCRYPT); //CK_BBOOL
      boolSet.add(DECRYPT); //CK_BBOOL
      boolSet.add(WRAP); //CK_BBOOL
      boolSet.add(UNWRAP); //CK_BBOOL
      attributeClasses.put(WRAP_TEMPLATE,
          AttributeArray.class); //CK_ATTRIBUTE_PTR
      attributeClasses.put(Attribute.UNWRAP_TEMPLATE,
          AttributeArray.class); //CK_ATTRIBUTE_PTR
      boolSet.add(SIGN); //CK_BBOOL
      boolSet.add(SIGN_RECOVER); //CK_BBOOL
      boolSet.add(VERIFY); //CK_BBOOL
      boolSet.add(VERIFY_RECOVER); //CK_BBOOL
      boolSet.add(DERIVE); //CK_BBOOL
      attributeClasses.put(START_DATE, DateAttribute.class); //CK_DATE
      attributeClasses.put(END_DATE, DateAttribute.class); //CK_DATE
      barrSet.add(MODULUS); //Big integer
      attributeClasses.put(MODULUS_BITS, LongAttribute.class); //CK_ULONG
      barrSet.add(PUBLIC_EXPONENT); //Big integer
      barrSet.add(PRIVATE_EXPONENT); //Big integer
      barrSet.add(PRIME_1); //Big integer
      barrSet.add(PRIME_2); //Big integer
      barrSet.add(EXPONENT_1); //Big integer
      barrSet.add(EXPONENT_2); //Big integer
      barrSet.add(COEFFICIENT); //Big integer
      barrSet.add(PRIME); //Big integer
      barrSet.add(SUBPRIME); //Big integer
      barrSet.add(BASE); //Big integer
      longSet.add(PRIME_BITS); //CK_ULONG
      longSet.add(SUB_PRIME_BITS); //CK_ULONG
      longSet.add(VALUE_BITS); //CK_ULONG
      longSet.add(VALUE_LEN); //CK_ULONG
      boolSet.add(EXTRACTABLE); //CK_BBOOL
      boolSet.add(LOCAL); //CK_BBOOL
      boolSet.add(NEVER_EXTRACTABLE); //CK_BBOOL
      boolSet.add(WRAP_WITH_TRUSTED); //CK_BBOOL
      boolSet.add(ALWAYS_SENSITIVE); //CK_BBOOL
      boolSet.add(ALWAYS_AUTHENTICATE); //CK_BBOOL
      attributeClasses.put(KEY_GEN_MECHANISM,
          MechanismAttribute.class); //CK_MECHANISM_TYPE
      attributeClasses.put(ALLOWED_MECHANISMS,
          MechanismArrayAttribute.class); //CK_MECHANISM_TYPE_PTR
      boolSet.add(MODIFIABLE); //CK_BBOOL
      barrSet.add(EC_PARAMS); //Byte array
      barrSet.add(EC_POINT); //Byte array
      boolSet.add(SECONDARY_AUTH); //CK_BBOOL - deprecated
      longSet.add(AUTH_PIN_FLAGS); //CK_ULONG - deprecated
      attributeClasses.put(HW_FEATURE_TYPE,
          HardwareFeatureTypeAttribute.class); //CK_HW_FEATURE
      boolSet.add(RESET_ON_INIT); //CK_BBOOL
      boolSet.add(HAS_RESET); //CK_BBOOL

      for (Long m : boolSet) {
        attributeClasses.put(m, BooleanAttribute.class);
      }

      for (Long m : longSet) {
        attributeClasses.put(m, LongAttribute.class);
      }

      for (Long m : barrSet) {
        attributeClasses.put(m, ByteArrayAttribute.class);
      }

      for (Long m : carrSet) {
        attributeClasses.put(m, CharArrayAttribute.class);
      }
    }

    return attributeClasses.get(type);
  }

  /**
   * Set, if this attribute is really present in the associated object.
   * Does only make sense if used in combination with template objects.
   *
   * @param present
   *          True, if attribute is present.
   */
  public void setPresent(boolean present) {
    this.present = present;
  }

  /**
   * Set, if this attribute is sensitive in the associated object.
   * Does only make sense if used in combination with template objects.
   *
   * @param sensitive
   *          True, if attribute is sensitive.
   */
  public void setSensitive(boolean sensitive) {
    this.sensitive = sensitive;
  }

  /**
   * Redirects the request for setting the attribute value to the implementing
   * attribute class.
   *
   * @param value
   *          the new value
   * @throws ClassCastException
   *           the given value type is not valid for this very
   *           {@link Attribute}.
   * @throws UnsupportedOperationException
   *           the {@link OtherAttribute} implementation does not support
   *           setting a value directly.
   */
  public abstract void setValue(Object value);

  /**
   * Set the CK_ATTRIBUTE of this Attribute. Only for internal use.
   *
   * @param ckAttribute
   *          The new CK_ATTRIBUTE of this Attribute.
   */
  protected void setCkAttribute(CK_ATTRIBUTE ckAttribute) {
    this.ckAttribute = Util.requireNonNull("ckAttribute", ckAttribute);
  }

  /**
   * Check, if this attribute is really present in the associated object.
   *
   * @return True, if this attribute is really present in the associated
   *         object.
   */
  public boolean isPresent() {
    return present;
  }

  /**
   * Check, if this attribute is sensitive in the associated object.
   *
   * @return True, if this attribute is sensitive in the associated object.
   */
  public boolean isSensitive() {
    return sensitive;
  }

  /**
   * Get the CK_ATTRIBUTE object of this Attribute that contains the attribute
   * type and value .
   *
   * @return The CK_ATTRIBUTE of this Attribute.
   */
  protected CK_ATTRIBUTE getCkAttribute() {
    return ckAttribute;
  }

  /**
   * Get a string representation of the value of this attribute.
   *
   * @return A string representation of the value of this attribute.
   */
  protected String getValueString() {
    if ((ckAttribute != null) && (ckAttribute.pValue != null)) {
      return ckAttribute.pValue.toString();
    } else {
      return "<NULL_PTR>";
    }
  }

  /**
   * Get a string representation of this attribute. If the attribute is not
   * present or if it is sensitive, the output of this method shows just a
   * message telling this. This string does not contain the attribute's type
   * name.
   *
   * @return A string representation of the value of this attribute.
   */
  @Override
  public String toString() {
    return toString(false);
  }

  /**
   * Get a string representation of this attribute. If the attribute is not
   * present or if it is sensitive, the output of this method shows just
   * a message telling this.
   *
   * @param withName
   *          If true, the string contains the attribute type name and the
   *          value. If false, it just contains the value.
   * @return A string representation of this attribute.
   */
  public String toString(boolean withName) {
    StringBuilder sb = new StringBuilder(32);

    if (withName) {
      String typeName = getAttributeName(ckAttribute.type);
      sb.append(typeName).append(": ");
    }
    if (present) {
      if (sensitive) {
        sb.append("<Value is sensitive>");
      } else {
        sb.append(getValueString());
      }
    } else {
      sb.append("<Attribute not present>");
    }

    return sb.toString();
  }

  /**
   * Set the PKCS#11 type of this attribute.
   *
   * @param type
   *          The PKCS#11 type of this attribute.
   */
  protected void setType(long type) {
    ckAttribute.type = type;
  }

  /**
   * Get the PKCS#11 type of this attribute.
   *
   * @return The PKCS#11 type of this attribute.
   */
  protected Long getType() {
    return ckAttribute.type;
  }

  /**
   * True, if both attributes are not present or if both attributes are
   * present and all other member variables are equal. False, otherwise.
   *
   * @param otherObject
   *          The other object to compare to.
   * @return True, if both attributes are not present or if both attributes
   *         are present and all other member variables are equal. False,
   *         otherwise.
   */
  public boolean equals(Object otherObject) {
    if (this == otherObject) {
      return true;
    } else if (!(otherObject instanceof Attribute)) {
      return false;
    }

    Attribute other = (Attribute) otherObject;
    if (!this.present && !other.present) {
      return true;
    } else if (!(this.present && other.present)) {
      return false;
    } else if (this.sensitive != other.sensitive) {
      return false;
    }

    if (this.ckAttribute.type != other.ckAttribute.type) {
      return false;
    }

    return Util.objEquals(this.ckAttribute.pValue,
        other.ckAttribute.pValue);
  }

  /**
   * The overriding of this method should ensure that the objects of this
   * class work correctly in a hashtable.
   *
   * @return The hash code of this object.
   */
  @Override
  public int hashCode() {
    int valueHashCode = (ckAttribute.pValue != null)
        ? ckAttribute.pValue.hashCode() : 0;
    return ((int) ckAttribute.type) ^ valueHashCode;
  }

}
