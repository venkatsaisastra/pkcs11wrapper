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
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import iaik.pkcs.pkcs11.VendorCodeConverter;

/**
 * This is the base class for private (asymmetric) keys. Objects of this class
 * represent private keys as specified by PKCS#11 v2.11.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 */
public class PrivateKey extends Key {

  /**
   * The subject of this private key.
   */
  protected ByteArrayAttribute subject;

  /**
   * True, if this private key is sensitive.
   */
  protected BooleanAttribute sensitive;

  /**
   * True, if this private key supports secondary authentication.
   */
  protected BooleanAttribute secondaryAuth;

  /**
   * The authentication flags for secondary authentication. Only defined, if
   * the secondaryAuth is set.
   */
  protected LongAttribute authPinFlags;

  /**
   * True, if this private key can be used for encryption.
   */
  protected BooleanAttribute decrypt;

  /**
   * True, if this private key can be used for signing.
   */
  protected BooleanAttribute sign;

  /**
   * True, if this private key can be used for signing with recover.
   */
  protected BooleanAttribute signRecover;

  /**
   * True, if this private key can be used for unwrapping wrapped keys.
   */
  protected BooleanAttribute unwrap;

  /**
   * True, if this private key can not be extracted from the token.
   */
  protected BooleanAttribute extractable;

  /**
   * True, if this private key was always sensitive.
   */
  protected BooleanAttribute alwaysSensitive;

  /**
   * True, if this private key was never extractable.
   */
  protected BooleanAttribute neverExtractable;

  /**
   * True, if this private key can only be wrapped with a wrapping key
   * having set the attribute trusted to true.
   */
  protected BooleanAttribute wrapWithTrusted;

  /**
   * Template of the key, that can be unwrapped.
   */
  protected AttributeArray unwrapTemplate;

  /**
   * True, if the user has to supply the PIN for each use
   * (sign or decrypt) with the key.
   */
  protected BooleanAttribute alwaysAuthenticate;

  /**
   * Default Constructor.
   */
  public PrivateKey() {
    objectClass.setLongValue(ObjectClass.PRIVATE_KEY);
  }

  /**
   * Called by sub-classes to create an instance of a PKCS#11 private key.
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
  protected PrivateKey(Session session, long objectHandle)
      throws TokenException {
    super(session, objectHandle);
    objectClass.setLongValue(ObjectClass.PRIVATE_KEY);
  }

  /**
   * The getInstance method of the PKCS11Object class uses this method to
   * create an instance of a PKCS#11 private key. This method reads the key
   * type attribute and calls the getInstance method of the according
   * sub-class.
   * If the key type is a vendor defined it uses the
   * VendorDefinedKeyBuilder set by the application. If no private key
   * could be constructed, Returns null.
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

    KeyTypeAttribute keyTypeAttribute = new KeyTypeAttribute();
    getAttributeValue(session, objectHandle, keyTypeAttribute);

    Long keyType = keyTypeAttribute.getLongValue();

    PKCS11Object newObject = null;

    if (keyTypeAttribute.isPresent() && (keyType != null)) {
      if (keyType.equals(Key.KeyType.RSA)) {
        newObject = RSAPrivateKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.DSA)) {
        newObject = DSAPrivateKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.EC)
        | keyType.equals(Key.KeyType.EC_EDWARDS)
        | keyType.equals(Key.KeyType.EC_MONTGOMERY)) {
        newObject = ECPrivateKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.DH)) {
        newObject = DHPrivateKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.KEA)) {
        newObject = KEAPrivateKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.X9_42_DH)) {
        newObject = X942DHPrivateKey.getInstance(session, objectHandle);
      } else if ((keyType & KeyType.VENDOR_DEFINED) != 0L) {
        VendorCodeConverter converter = session.getModule().getVendorCodeConverter();
        if (converter != null) {
          long genericKeyType = converter.vendorToGenericCKK(keyType);
          if (genericKeyType == Key.KeyType.VENDOR_SM2) {
            newObject = ECPrivateKey.getInstance(session, objectHandle);
            // map also the key type
            ((Key) newObject).keyType.setLongValue(genericKeyType);
          }
        }
      }
    }

    if (newObject == null) {
      newObject = getUnknownPrivateKey(session, objectHandle);
    }

    return newObject;
  }

  /**
   * Try to create a key which has no or an unknown private key type
   * type attribute.
   * This implementation will try to use a vendor defined key
   * builder, if such has been set.
   * If this is impossible or fails, it will create just
   * a simple {@link iaik.pkcs.pkcs11.objects.PrivateKey PrivateKey }.
   *
   * @param session
   *          The session to use.
   * @param objectHandle
   *          The handle of the object
   * @return A new PKCS11Object.
   * @throws TokenException
   *           If no object could be created.
   */
  protected static PKCS11Object getUnknownPrivateKey(Session session,
      long objectHandle) throws TokenException {
    Util.requireNonNull("session", session);

    VendorDefinedKeyBuilder vendorKeyBuilder =
            session.getModule().getVendorDefinedKeyBuilder();
    PKCS11Object newObject;
    if (vendorKeyBuilder != null) {
      try {
        newObject = vendorKeyBuilder.build(session, objectHandle);
      } catch (PKCS11Exception ex) {
        // we can just treat it like some unknown type of private key
        newObject = new PrivateKey(session, objectHandle);
      }
    } else {
      // we can just treat it like some unknown type of private key
      newObject = new PrivateKey(session, objectHandle);
    }

    return newObject;
  }

  /**
   * Put all attributes of the given object into the attributes table of this
   * object. This method is only static to be able to access invoke the
   * implementation of this method for each class separately.
   *
   * @param object
   *          The object to handle.
   */
  protected static void putAttributesInTable(PrivateKey object) {
    Util.requireNonNull("object", object);
    object.attributeTable.put(Attribute.SUBJECT, object.subject);
    object.attributeTable.put(Attribute.SENSITIVE, object.sensitive);
    object.attributeTable.put(Attribute.SECONDARY_AUTH,
        object.secondaryAuth);
    object.attributeTable.put(Attribute.AUTH_PIN_FLAGS,
        object.authPinFlags);
    object.attributeTable.put(Attribute.DECRYPT, object.decrypt);
    object.attributeTable.put(Attribute.SIGN, object.sign);
    object.attributeTable.put(Attribute.SIGN_RECOVER, object.signRecover);
    object.attributeTable.put(Attribute.UNWRAP, object.unwrap);
    object.attributeTable.put(Attribute.EXTRACTABLE, object.extractable);
    object.attributeTable.put(Attribute.ALWAYS_SENSITIVE,
        object.alwaysSensitive);
    object.attributeTable.put(Attribute.NEVER_EXTRACTABLE,
        object.neverExtractable);
    object.attributeTable.put(Attribute.WRAP_WITH_TRUSTED,
        object.wrapWithTrusted);
    object.attributeTable.put(Attribute.UNWRAP_TEMPLATE,
        object.unwrapTemplate);
    object.attributeTable.put(Attribute.ALWAYS_AUTHENTICATE,
        object.alwaysAuthenticate);
  }

  /**
   * Allocates the attribute objects for this class and adds them to the
   * attribute table.
   */
  @Override
  protected void allocateAttributes() {
    super.allocateAttributes();

    subject = new ByteArrayAttribute(Attribute.SUBJECT);
    sensitive = new BooleanAttribute(Attribute.SENSITIVE);
    secondaryAuth = new BooleanAttribute(Attribute.SECONDARY_AUTH);
    authPinFlags = new LongAttribute(Attribute.AUTH_PIN_FLAGS);
    decrypt = new BooleanAttribute(Attribute.DECRYPT);
    sign = new BooleanAttribute(Attribute.SIGN);
    signRecover = new BooleanAttribute(Attribute.SIGN_RECOVER);
    unwrap = new BooleanAttribute(Attribute.UNWRAP);
    extractable = new BooleanAttribute(Attribute.EXTRACTABLE);
    alwaysSensitive = new BooleanAttribute(Attribute.ALWAYS_SENSITIVE);
    neverExtractable = new BooleanAttribute(Attribute.NEVER_EXTRACTABLE);
    wrapWithTrusted = new BooleanAttribute(Attribute.WRAP_WITH_TRUSTED);
    unwrapTemplate = new AttributeArray(Attribute.UNWRAP_TEMPLATE);
    alwaysAuthenticate = new BooleanAttribute(Attribute.ALWAYS_AUTHENTICATE);

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
    } else if (!(otherObject instanceof PrivateKey)) {
      return false;
    }

    PrivateKey other = (PrivateKey) otherObject;
    return super.equals(other)
        && this.subject.equals(other.subject)
        && this.sensitive.equals(other.sensitive)
        && this.secondaryAuth.equals(other.secondaryAuth)
        && this.authPinFlags.equals(other.authPinFlags)
        && this.decrypt.equals(other.decrypt)
        && this.sign.equals(other.sign)
        && this.signRecover.equals(other.signRecover)
        && this.unwrap.equals(other.unwrap)
        && this.extractable.equals(other.extractable)
        && this.alwaysSensitive.equals(other.alwaysSensitive)
        && this.neverExtractable.equals(other.neverExtractable)
        && this.wrapWithTrusted.equals(other.wrapWithTrusted)
        && this.unwrapTemplate.equals(other.unwrapTemplate)
        && this.alwaysAuthenticate.equals(other.alwaysAuthenticate);
  }

  /**
   * Gets the subject attribute of this key.
   *
   * @return The subject attribute.
   */
  public ByteArrayAttribute getSubject() {
    return subject;
  }

  /**
   * Gets the sensitive attribute of this key.
   *
   * @return The sensitive attribute.
   */
  public BooleanAttribute getSensitive() {
    return sensitive;
  }

  /**
   * Gets the secondary authentication attribute of this key.
   *
   * @return The secondary authentication attribute.
   */
  public BooleanAttribute getSecondaryAuth() {
    return secondaryAuth;
  }

  /**
   * Gets the authentication flags for secondary authentication of this key.
   *
   * @return The authentication flags for secondary authentication attribute.
   */
  public LongAttribute getAuthPinFlags() {
    return authPinFlags;
  }

  /**
   * Gets the decrypt attribute of this key.
   *
   * @return The decrypt attribute.
   */
  public BooleanAttribute getDecrypt() {
    return decrypt;
  }

  /**
   * Gets the sign attribute of this key.
   *
   * @return The sign attribute.
   */
  public BooleanAttribute getSign() {
    return sign;
  }

  /**
   * Gets the sign recover attribute of this key.
   *
   * @return The sign recover attribute.
   */
  public BooleanAttribute getSignRecover() {
    return signRecover;
  }

  /**
   * Gets the unwrap attribute of this key.
   *
   * @return The unwrap attribute.
   */
  public BooleanAttribute getUnwrap() {
    return unwrap;
  }

  /**
   * Gets the extractable attribute of this key.
   *
   * @return The extractable attribute.
   */
  public BooleanAttribute getExtractable() {
    return extractable;
  }

  /**
   * Gets the always sensitive attribute of this key.
   *
   * @return The always sensitive attribute.
   */
  public BooleanAttribute getAlwaysSensitive() {
    return alwaysSensitive;
  }

  /**
   * Gets the never extractable attribute of this key.
   *
   * @return The never extractable attribute.
   */
  public BooleanAttribute getNeverExtractable() {
    return neverExtractable;
  }

  /**
   * Gets the wrap with trusted attribute of this key.
   *
   * @return The wrap with trusted attribute.
   */
  public BooleanAttribute getWrapWithTrusted() {
    return wrapWithTrusted;
  }

  /**
   * Gets the unwrap template attribute of this key. This
   * attribute can only be used with PKCS#11 modules supporting
   * cryptoki version 2.20 or higher.
   *
   * @return The unwrap template attribute.
   */
  public AttributeArray getUnwrapTemplate() {
    return unwrapTemplate;
  }

  /**
   * Gets the always authenticate attribute of this key.
   *
   * @return The always authenticate attribute.
   */
  public BooleanAttribute getAlwaysAuthenticate() {
    return alwaysAuthenticate;
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
        subject, sensitive, secondaryAuth, authPinFlags, decrypt,
        sign, signRecover, unwrap, extractable, alwaysSensitive,
        neverExtractable, wrapWithTrusted, alwaysAuthenticate,
        unwrapTemplate });
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
    StringBuilder sb = new StringBuilder(super.toString());
    sb.append("\n  Subject (DER, hex): ").append(subject);
    sb.append("\n  Sensitive: ").append(sensitive);
    sb.append("\n  Secondary Authentication: ").append(secondaryAuth);
    sb.append("\n  Secondary Authentication PIN Flags: ");
    if (authPinFlags.isPresent() && !authPinFlags.isSensitive()
        && (authPinFlags.getLongValue() != null)) {
      long authFlagsValue = authPinFlags.getLongValue();

      sb.append("\n    User PIN-Count low: ").append((authFlagsValue
            & PKCS11Constants.CKF_USER_PIN_COUNT_LOW) != 0L);
      sb.append("\n    User PIN final Try: ").append((authFlagsValue
            & PKCS11Constants.CKF_USER_PIN_FINAL_TRY) != 0L);
      sb.append("\n    User PIN locked: ").append((authFlagsValue
            & PKCS11Constants.CKF_USER_PIN_LOCKED) != 0L);
      sb.append("\n    User PIN to be changed: ").append((authFlagsValue
            & PKCS11Constants.CKF_USER_PIN_TO_BE_CHANGED) != 0L);
    } else {
      sb.append(authPinFlags);
    }

    sb.append("\n  Decrypt: ").append(decrypt);
    sb.append("\n  Sign: ").append(sign);
    sb.append("\n  Sign Recover: ").append(signRecover);
    sb.append("\n  Unwrap: ").append(unwrap);
    sb.append("\n  Extractable: ").append(extractable);
    sb.append("\n  Always Sensitive: ").append(alwaysSensitive);
    sb.append("\n  Never Extractable: ").append(neverExtractable);
    sb.append("\n  Wrap With Trusted: ").append(wrapWithTrusted);
    sb.append("\n  Unwrap Template: ").append(unwrapTemplate);
    sb.append("\n  Always Authenticate: ").append(alwaysAuthenticate);

    return sb.toString();
  }

}
