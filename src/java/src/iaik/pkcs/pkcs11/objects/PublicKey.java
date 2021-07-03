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
 * This is the base class for public (asymmetric) keys. Objects of this class
 * represent public keys as specified by PKCS#11 v2.11.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 */
public class PublicKey extends Key {

  /**
   * The subject attribute of this public key.
   */
  protected ByteArrayAttribute subject;

  /**
   * True, if this public key can be used for encryption.
   */
  protected BooleanAttribute encrypt;

  /**
   * True, if this public key can be used for verification.
   */
  protected BooleanAttribute verify;

  /**
   * True, if this public key can be used for encryption with recovery.
   */
  protected BooleanAttribute verifyRecover;

  /**
   * True, if this public key can be used for wrapping other keys.
   */
  protected BooleanAttribute wrap;

  /**
   * True, if this public key can be used for wrapping other keys.
   */
  protected BooleanAttribute trusted;

  /**
   * Template of the key, that can be wrapped.
   */
  protected AttributeArray wrapTemplate;

  /**
   * Default Constructor.
   */
  public PublicKey() {
    super();
    objectClass.setLongValue(ObjectClass.PUBLIC_KEY);
  }

  /**
   * Called by sub-classes to create an instance of a PKCS#11 public key.
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
  protected PublicKey(Session session, long objectHandle)
      throws TokenException {
    super(session, objectHandle);
    objectClass.setLongValue(ObjectClass.PUBLIC_KEY);
  }

  /**
   * The getInstance method of the PKCS11Object class uses this method to
   * create an instance of a PKCS#11 public key. This method reads the key
   * type attribute and calls the getInstance method of the according
   * sub-class. If the key type is a vendor defined it uses the
   * VendorDefinedKeyBuilder set by the application. If no public key
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
        newObject = RSAPublicKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.DSA)) {
        newObject = DSAPublicKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.EC)
          | keyType.equals(Key.KeyType.EC_EDWARDS)
          | keyType.equals(Key.KeyType.EC_MONTGOMERY)) {
        newObject = ECPublicKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.DH)) {
        newObject = DHPublicKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.KEA)) {
        newObject = KEAPublicKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.X9_42_DH)) {
        newObject = X942DHPublicKey.getInstance(session, objectHandle);
      } else if ((keyType & KeyType.VENDOR_DEFINED) != 0L) {
        VendorCodeConverter converter = session.getModule().getVendorCodeConverter();
        if (converter != null) {
          long genericKeyType = converter.vendorToGenericCKK(keyType);
          if (genericKeyType == Key.KeyType.VENDOR_SM2) {
            newObject = ECPublicKey.getInstance(session, objectHandle);
            // map also the key type
            ((Key) newObject).keyType.setLongValue(genericKeyType);
          }
        }
      }
    }

    if (newObject == null) {
      newObject = getUnknownPublicKey(session, objectHandle);
    }

    return newObject;
  }

  /**
   * Try to create a key which has no or an unknown public key type attribute.
   * This implementation will try to use a vendor defined key builder, if such
   * has been set. If this is impossible or fails, it will create just a
   * simple {@link iaik.pkcs.pkcs11.objects.PublicKey PublicKey }.
   *
   * @param session
   *          The session to use.
   * @param objectHandle
   *          The handle of the object
   * @return A new PKCS11Object.
   * @throws TokenException
   *           If no object could be created.
   */
  protected static PKCS11Object getUnknownPublicKey(Session session,
      long objectHandle) throws TokenException {
    Util.requireNonNull("session", session);

    PKCS11Object newObject;
    if (Key.vendorKeyBuilder != null) {
      try {
        newObject = Key.vendorKeyBuilder.build(session, objectHandle);
      } catch (PKCS11Exception ex) {
        // we can just treat it like some unknown type of public key
        newObject = new PublicKey(session, objectHandle);
      }
    } else {
      // we can just treat it like some unknown type of public key
      newObject = new PublicKey(session, objectHandle);
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
  protected static void putAttributesInTable(PublicKey object) {
    Util.requireNonNull("object", object);
    object.attributeTable.put(Attribute.SUBJECT, object.subject);
    object.attributeTable.put(Attribute.ENCRYPT, object.encrypt);
    object.attributeTable.put(Attribute.VERIFY, object.verify);
    object.attributeTable.put(Attribute.VERIFY_RECOVER,
        object.verifyRecover);
    object.attributeTable.put(Attribute.WRAP, object.wrap);
    object.attributeTable.put(Attribute.TRUSTED, object.trusted);
    object.attributeTable.put(Attribute.WRAP_TEMPLATE,
        object.wrapTemplate);
  }

  /**
   * Allocates the attribute objects for this class and adds them to the
   * attribute table.
   */
  @Override
  protected void allocateAttributes() {
    super.allocateAttributes();

    subject = new ByteArrayAttribute(Attribute.SUBJECT);
    encrypt = new BooleanAttribute(Attribute.ENCRYPT);
    verify = new BooleanAttribute(Attribute.VERIFY);
    verifyRecover = new BooleanAttribute(Attribute.VERIFY_RECOVER);
    wrap = new BooleanAttribute(Attribute.WRAP);
    trusted = new BooleanAttribute(Attribute.TRUSTED);
    wrapTemplate = new AttributeArray(Attribute.WRAP_TEMPLATE);

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
    } else if (!(otherObject instanceof PublicKey)) {
      return false;
    }

    PublicKey other = (PublicKey) otherObject;
    return super.equals(other)
        && this.subject.equals(other.subject)
        && this.encrypt.equals(other.encrypt)
        && this.verify.equals(other.verify)
        && this.verifyRecover.equals(other.verifyRecover)
        && this.wrap.equals(other.wrap)
        && this.trusted.equals(other.trusted)
        && this.wrapTemplate.equals(other.wrapTemplate);
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
   * Gets the encrypt attribute of this key.
   *
   * @return The encrypt attribute.
   */
  public BooleanAttribute getEncrypt() {
    return encrypt;
  }

  /**
   * Gets the verify attribute of this key.
   *
   * @return The verify attribute.
   */
  public BooleanAttribute getVerify() {
    return verify;
  }

  /**
   * Gets the verify recover attribute of this key.
   *
   * @return The verify recover attribute.
   */
  public BooleanAttribute getVerifyRecover() {
    return verifyRecover;
  }

  /**
   * Gets the wrap attribute of this key.
   *
   * @return The wrap attribute.
   */
  public BooleanAttribute getWrap() {
    return wrap;
  }

  /**
   * Gets the trusted attribute of this key.
   *
   * @return The trusted attribute.
   */
  public BooleanAttribute getTrusted() {
    return trusted;
  }

  /**
   * Gets the wrap template attribute of this key. This
   * attribute can only be used with PKCS#11 modules supporting
   * cryptoki version 2.20 or higher.
   *
   * @return The wrap template attribute.
   */
  public AttributeArray getWrapTemplate() {
    return wrapTemplate;
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
        subject, encrypt, verify, verifyRecover, wrap, trusted, wrapTemplate });
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
        "\n  Subject (DER, hex): ", subject,
        "\n  Encrypt: ", encrypt,
        "\n  Verify: ", verify,
        "\n  Verify Recover: ", verifyRecover,
        "\n  Wrap: ", wrap,
        "\n  Trusted: ", trusted,
        "\n  Wrap Template: ", wrapTemplate);
  }

}
