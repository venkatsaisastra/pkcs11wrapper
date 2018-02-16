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
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;

/**
 * This is the base class for secret (symmetric) keys. Objects of this class
 * represent secret keys as specified by PKCS#11 v2.11.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (sensitive <> null)
 *             and (encrypt <> null)
 *             and (decrypt <> null)
 *             and (sign <> null)
 *             and (verify <> null)
 *             and (wrap <> null)
 *             and (unwrap <> null)
 *             and (extractable <> null)
 *             and (alwaysSensitive <> null)
 *             and (neverExtractable <> null)
 */
public class SecretKey extends Key {

    /**
     * True, if this key is sensitive.
     */
    protected BooleanAttribute sensitive;

    /**
     * True, if this key can be used for encryption.
     */
    protected BooleanAttribute encrypt;

    /**
     * True, if this key can be used for decryption.
     */
    protected BooleanAttribute decrypt;

    /**
     * True, if this key can be used for signing.
     */
    protected BooleanAttribute sign;

    /**
     * True, if this key can be used for verification.
     */
    protected BooleanAttribute verify;

    /**
     * True, if this key can be used for wrapping other keys.
     */
    protected BooleanAttribute wrap;

    /**
     * True, if this key can be used for unwrapping other keys.
     */
    protected BooleanAttribute unwrap;

    /**
     * True, if this key is extractable from the token.
     */
    protected BooleanAttribute extractable;

    /**
     * True, if this key was always sensitive.
     */
    protected BooleanAttribute alwaysSensitive;

    /**
     * True, if this key was never extractable.
     */
    protected BooleanAttribute neverExtractable;

    /**
     * Key checksum of this private key.
     */
    protected ByteArrayAttribute checkValue;

    /**
     * True, if this private key can only be wrapped with a wrapping key
     * having set the attribute trusted to true.
     */
    protected BooleanAttribute wrapWithTrusted;

    /**
     * True, if this public key can be used for wrapping other keys.
     */
    protected BooleanAttribute trusted;

    /**
     * Template of the key, that can be wrapped.
     */
    protected AttributeArray wrapTemplate;

    /**
     * Template of the key, that can be unwrapped.
     */
    protected AttributeArray unwrapTemplate;

    /**
     * Default Constructor.
     *
     * @preconditions
     * @postconditions
     */
    public SecretKey() {
        objectClass.setLongValue(ObjectClass.SECRET_KEY);
    }

    /**
     * Called by sub-classes to create an instance of a PKCS#11 secret key.
     *
     * @param session
     *          The session to use for reading attributes. This session must
     *          have the appropriate rights; i.e. it must be a user-session, if
     *          it is a private object.
     * @param objectHandle
     *          The object handle as given from the PKCS#111 module.
     * @exception TokenException
     *              If getting the attributes failed.
     * @preconditions (session <> null)
     * @postconditions
     */
    protected SecretKey(Session session, long objectHandle)
        throws TokenException {
        super(session, objectHandle);
        objectClass.setLongValue(ObjectClass.SECRET_KEY);
    }

    /**
     * The getInstance method of the PKCS11Object class uses this method to
     * create an instance of a PKCS#11 secret key. This method reads the key
     * type attribute and calls the getInstance method of the according
     * sub-class.
     * If the key type is a vendor defined it uses the
     * VendorDefinedKeyBuilder set by the application. If no secret key
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
     * @preconditions (session <> null)
     * @postconditions (result <> null)
     */
    public static PKCS11Object getInstance(Session session, long objectHandle)
        throws TokenException {
        Util.requireNonNull("session", session);

        KeyTypeAttribute keyTypeAttribute = new KeyTypeAttribute();
        getAttributeValue(session, objectHandle, keyTypeAttribute);

        Long keyType = keyTypeAttribute.getLongValue();

        PKCS11Object newObject;

        if (keyTypeAttribute.isPresent() && (keyType != null)) {
            newObject = ValuedSecretKey.getInstance(session, objectHandle,
                    keyType.longValue());
        } else {
            newObject = getUnknownSecretKey(session, objectHandle);
        }

        return newObject;
    }

    /**
     * Try to create a key which has no or an unkown secret key type
     * type attribute.
     * This implementation will try to use a vendor defined key
     * builder, if such has been set.
     * If this is impossible or fails, it will create just
     * a simple {@link iaik.pkcs.pkcs11.objects.SecretKey SecretKey }.
     *
     * @param session
     *          The session to use.
     * @param objectHandle
     *          The handle of the object
     * @return A new PKCS11Object.
     * @throws TokenException
     *           If no object could be created.
     * @preconditions (session <> null)
     * @postconditions (result <> null)
     */
    protected static PKCS11Object getUnknownSecretKey(Session session,
            long objectHandle)
        throws TokenException {
        Util.requireNonNull("session", session);

        PKCS11Object newObject;
        if (Key.vendorKeyBuilder != null) {
            try {
                newObject = Key.vendorKeyBuilder.build(session, objectHandle);
            } catch (PKCS11Exception ex) {
                // we can just treat it like some unknown type of secret key
                newObject = new SecretKey(session, objectHandle);
            }
        } else {
            // we can just treat it like some unknown type of secret key
            newObject = new SecretKey(session, objectHandle);
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
     * @preconditions (object <> null)
     * @postconditions
     */
    protected static void putAttributesInTable(SecretKey object) {
        Util.requireNonNull("object", object);
        object.attributeTable.put(Attribute.SENSITIVE, object.sensitive);
        object.attributeTable.put(Attribute.ENCRYPT, object.encrypt);
        object.attributeTable.put(Attribute.DECRYPT, object.decrypt);
        object.attributeTable.put(Attribute.SIGN, object.sign);
        object.attributeTable.put(Attribute.VERIFY, object.verify);
        object.attributeTable.put(Attribute.WRAP, object.wrap);
        object.attributeTable.put(Attribute.UNWRAP, object.unwrap);
        object.attributeTable.put(Attribute.EXTRACTABLE, object.extractable);
        object.attributeTable.put(Attribute.ALWAYS_SENSITIVE,
                object.alwaysSensitive);
        object.attributeTable.put(Attribute.NEVER_EXTRACTABLE,
                object.neverExtractable);
        object.attributeTable.put(Attribute.CHECK_VALUE, object.checkValue);
        object.attributeTable.put(Attribute.WRAP_WITH_TRUSTED,
                object.wrapWithTrusted);
        object.attributeTable.put(Attribute.TRUSTED, object.trusted);
        object.attributeTable.put(Attribute.WRAP_TEMPLATE,
                object.wrapTemplate);
        object.attributeTable.put(Attribute.UNWRAP_TEMPLATE,
                object.unwrapTemplate);
    }

    /**
     * Allocates the attribute objects for this class and adds them to the
     * attribute table.
     *
     * @preconditions
     * @postconditions
     */
    @Override
    protected void allocateAttributes() {
        super.allocateAttributes();

        sensitive = new BooleanAttribute(Attribute.SENSITIVE);
        encrypt = new BooleanAttribute(Attribute.ENCRYPT);
        decrypt = new BooleanAttribute(Attribute.DECRYPT);
        sign = new BooleanAttribute(Attribute.SIGN);
        verify = new BooleanAttribute(Attribute.VERIFY);
        wrap = new BooleanAttribute(Attribute.WRAP);
        unwrap = new BooleanAttribute(Attribute.UNWRAP);
        extractable = new BooleanAttribute(Attribute.EXTRACTABLE);
        alwaysSensitive = new BooleanAttribute(Attribute.ALWAYS_SENSITIVE);
        neverExtractable = new BooleanAttribute(Attribute.NEVER_EXTRACTABLE);
        checkValue = new ByteArrayAttribute(Attribute.CHECK_VALUE);
        wrapWithTrusted = new BooleanAttribute(Attribute.WRAP_WITH_TRUSTED);
        trusted = new BooleanAttribute(Attribute.TRUSTED);
        wrapTemplate = new AttributeArray(Attribute.WRAP_TEMPLATE);
        unwrapTemplate = new AttributeArray(Attribute.UNWRAP_TEMPLATE);

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
     * @preconditions
     * @postconditions
     */
    @Override
    public boolean equals(Object otherObject) {
        if (this == otherObject) {
            return true;
        } else if (!(otherObject instanceof SecretKey)) {
            return false;
        }

        SecretKey other = (SecretKey) otherObject;
        return super.equals(other)
                && this.sensitive.equals(other.sensitive)
                && this.encrypt.equals(other.encrypt)
                && this.decrypt.equals(other.decrypt)
                && this.sign.equals(other.sign)
                && this.verify.equals(other.verify)
                && this.wrap.equals(other.wrap)
                && this.unwrap.equals(other.unwrap)
                && this.extractable.equals(other.extractable)
                && this.alwaysSensitive.equals(other.alwaysSensitive)
                && this.neverExtractable.equals(other.neverExtractable)
                && this.checkValue.equals(other.checkValue)
                && this.wrapWithTrusted.equals(other.wrapWithTrusted)
                && this.trusted.equals(other.trusted)
                && this.wrapTemplate.equals(other.wrapTemplate)
                && this.unwrapTemplate.equals(other.unwrapTemplate);
    }

    /**
     * Gets the sensitive attribute of this key.
     *
     * @return The sensitive attribute.
     * @preconditions
     * @postconditions (result <> null)
     */
    public BooleanAttribute getSensitive() {
        return sensitive;
    }

    /**
     * Gets the encrypt attribute of this key.
     *
     * @return The encrypt attribute.
     * @preconditions
     * @postconditions (result <> null)
     */
    public BooleanAttribute getEncrypt() {
        return encrypt;
    }

    /**
     * Gets the verify attribute of this key.
     *
     * @return The verify attribute.
     * @preconditions
     * @postconditions (result <> null)
     */
    public BooleanAttribute getVerify() {
        return verify;
    }

    /**
     * Gets the decrypt attribute of this key.
     *
     * @return The decrypt attribute.
     * @preconditions
     * @postconditions (result <> null)
     */
    public BooleanAttribute getDecrypt() {
        return decrypt;
    }

    /**
     * Gets the sign attribute of this key.
     *
     * @return The sign attribute.
     * @preconditions
     * @postconditions (result <> null)
     */
    public BooleanAttribute getSign() {
        return sign;
    }

    /**
     * Gets the wrap attribute of this key.
     *
     * @return The wrap attribute.
     * @preconditions
     * @postconditions (result <> null)
     */
    public BooleanAttribute getWrap() {
        return wrap;
    }

    /**
     * Gets the unwrap attribute of this key.
     *
     * @return The unwrap attribute.
     * @preconditions
     * @postconditions (result <> null)
     */
    public BooleanAttribute getUnwrap() {
        return unwrap;
    }

    /**
     * Gets the extractable attribute of this key.
     *
     * @return The extractable attribute.
     * @preconditions
     * @postconditions (result <> null)
     */
    public BooleanAttribute getExtractable() {
        return extractable;
    }

    /**
     * Gets the always sensitive attribute of this key.
     *
     * @return The always sensitive attribute.
     * @preconditions
     * @postconditions (result <> null)
     */
    public BooleanAttribute getAlwaysSensitive() {
        return alwaysSensitive;
    }

    /**
     * Gets the never extractable attribute of this key.
     *
     * @return The never extractable attribute.
     * @preconditions
     * @postconditions (result <> null)
     */
    public BooleanAttribute getNeverExtractable() {
        return neverExtractable;
    }

    /**
     * Gets the check value attribute of this key.
     *
     * @return The check value attribute.
     * @preconditions
     * @postconditions (result <> null)
     */
    public ByteArrayAttribute getCheckValue() {
        return checkValue;
    }

    /**
     * Gets the wrap with trusted attribute of this key.
     *
     * @return The wrap with trusted attribute.
     * @preconditions
     * @postconditions (result <> null)
     */
    public BooleanAttribute getWrapWithTrusted() {
        return wrapWithTrusted;
    }

    /**
     * Gets the trusted attribute of this key.
     *
     * @return The trusted attribute.
     * @preconditions
     * @postconditions (result <> null)
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
     * @preconditions
     * @postconditions (result <> null)
     */
    public AttributeArray getWrapTemplate() {
        return wrapTemplate;
    }

    /**
     * Gets the unwrap template attribute of this key. This
     * attribute can only be used with PKCS#11 modules supporting
     * cryptoki version 2.20 or higher.
     *
     * @return The unwrap template attribute.
     * @preconditions
     * @postconditions (result <> null)
     */
    public AttributeArray getUnwrapTemplate() {
        return unwrapTemplate;
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
     * @preconditions (session <> null)
     * @postconditions
     */
    @Override
    public void readAttributes(Session session)
        throws TokenException {
        super.readAttributes(session);

        PKCS11Object.getAttributeValues(session, objectHandle, new Attribute[] {
            sensitive, encrypt, decrypt, sign, verify, wrap, unwrap,
            extractable, alwaysSensitive, neverExtractable, checkValue,
            wrapWithTrusted, trusted });
        PKCS11Object.getAttributeValue(session, objectHandle, wrapTemplate);
        PKCS11Object.getAttributeValue(session, objectHandle, unwrapTemplate);
    }

    /**
     * Returns a string representation of the current object. The
     * output is only for debugging purposes and should not be used for other
     * purposes.
     *
     * @return A string presentation of this object for debugging output.
     * @preconditions
     * @postconditions (result <> null)
     */
    @Override
    public String toString() {
        String superToString = super.toString();
        return Util.concatObjectsCap(superToString.length() + 200, superToString,
                "\n  Sensitive: ", sensitive,
                "\n  Encrypt: ", encrypt,
                "\n  Decrypt: ", decrypt,
                "\n  Sign: ", sign,
                "\n  Verify: ", verify,
                "\n  Wrap: ", wrap,
                "\n  Unwrap: ", unwrap,
                "\n  Extractable: ", extractable,
                "\n  Always Sensitive: ", alwaysSensitive,
                "\n  Never Extractable: ", neverExtractable,
                "\n  Check Value: ", checkValue,
                "\n  Wrap With Trusted: ", wrapWithTrusted,
                "\n  Trusted: ", trusted,
                "\n  Wrap Template: ", wrapTemplate,
                "\n  Unwrap Template: ", unwrapTemplate);
    }

}
