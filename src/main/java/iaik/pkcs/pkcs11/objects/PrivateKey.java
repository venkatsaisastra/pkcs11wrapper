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
import iaik.pkcs.pkcs11.wrapper.Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * This is the base class for private (asymmetric) keys. Objects of this class
 * represent private keys as specified by PKCS#11 v2.11.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (subject <> null)
 *             and (sensitive <> null)
 *             and (secondaryAuth <> null)
 *             and (authPinFlags <> null)
 *             and (decrypt <> null)
 *             and (sign <> null)
 *             and (signRecover <> null)
 *             and (unwrap <> null)
 *             and (extractable <> null)
 *             and (alwaysSensitive <> null)
 *             and (neverExtractable <> null)
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
     *
     * @preconditions
     * @postconditions
     */
    public PrivateKey() {
        super();
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
     * @preconditions (session <> null)
     * @postconditions
     */
    protected PrivateKey(Session session, long objectHandle)
        throws TokenException {
        super(session, objectHandle);
        objectClass.setLongValue(ObjectClass.PRIVATE_KEY);
    }

    /**
     * The getInstance method of the Object class uses this method to create
     * an instance of a PKCS#11 private key. This method reads the key
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
     * @preconditions (session <> null)
     * @postconditions (result <> null)
     */
    public static Object getInstance(Session session, long objectHandle)
        throws TokenException {
        Util.requireNonNull("session", session);

        KeyTypeAttribute keyTypeAttribute = new KeyTypeAttribute();
        getAttributeValue(session, objectHandle, keyTypeAttribute);

        Long keyType = keyTypeAttribute.getLongValue();

        Object newObject;

        if (keyTypeAttribute.isPresent() && (keyType != null)) {
            if (keyType.equals(Key.KeyType.RSA)) {
                newObject = RSAPrivateKey.getInstance(session, objectHandle);
            } else if (keyType.equals(Key.KeyType.DSA)) {
                newObject = DSAPrivateKey.getInstance(session, objectHandle);
            } else if (keyType.equals(Key.KeyType.EC)) {
                newObject = ECDSAPrivateKey.getInstance(session, objectHandle);
            } else if (keyType.equals(Key.KeyType.DH)) {
                newObject = DHPrivateKey.getInstance(session, objectHandle);
            } else if (keyType.equals(Key.KeyType.KEA)) {
                newObject = KEAPrivateKey.getInstance(session, objectHandle);
            } else if (keyType.equals(Key.KeyType.X9_42_DH)) {
                newObject = X942DHPrivateKey.getInstance(session, objectHandle);
            } else if (keyType.equals(Key.KeyType.VENDOR_SM2)) {
                newObject = SM2PrivateKey.getInstance(session, objectHandle);
            } else if ((keyType.longValue()
                            & KeyType.VENDOR_DEFINED.longValue()) != 0L) {
                newObject = getUnknownPrivateKey(session, objectHandle);
            } else {
                newObject = getUnknownPrivateKey(session, objectHandle);
            }
        } else {
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
     * @return A new Object.
     * @throws TokenException
     *           If no object could be created.
     * @preconditions (session <> null)
     * @postconditions (result <> null)
     */
    @SuppressWarnings("restriction")
    protected static Object getUnknownPrivateKey(Session session,
            long objectHandle)
        throws TokenException {
        Util.requireNonNull("session", session);

        Object newObject;
        if (Key.vendorKeyBuilder != null) {
            try {
                newObject = Key.vendorKeyBuilder.build(session, objectHandle);
            } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
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
     * implementation of this method for each class separately (see use in
     * clone()).
     *
     * @param object
     *          The object to handle.
     * @preconditions (object <> null)
     * @postconditions
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
     *
     * @preconditions
     * @postconditions
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
        alwaysAuthenticate
            = new BooleanAttribute(Attribute.ALWAYS_AUTHENTICATE);

        putAttributesInTable(this);
    }

    /**
     * Create a (deep) clone of this object.
     *
     * @return A clone of this object.
     * @preconditions
     * @postconditions (result <> null)
     *                 and (result instanceof PrivateKey)
     *                 and (result.equals(this))
     */
    @Override
    public java.lang.Object clone() {
        PrivateKey clone = (PrivateKey) super.clone();

        clone.subject = (ByteArrayAttribute) this.subject.clone();
        clone.sensitive = (BooleanAttribute) this.sensitive.clone();
        clone.secondaryAuth = (BooleanAttribute) this.secondaryAuth.clone();
        clone.authPinFlags = (LongAttribute) this.authPinFlags.clone();
        clone.decrypt = (BooleanAttribute) this.decrypt.clone();
        clone.sign = (BooleanAttribute) this.sign.clone();
        clone.signRecover = (BooleanAttribute) this.signRecover.clone();
        clone.unwrap = (BooleanAttribute) this.unwrap.clone();
        clone.extractable = (BooleanAttribute) this.extractable.clone();
        clone.alwaysSensitive
            = (BooleanAttribute) this.alwaysSensitive.clone();
        clone.neverExtractable
            = (BooleanAttribute) this.neverExtractable.clone();
        clone.wrapWithTrusted
            = (BooleanAttribute) this.wrapWithTrusted.clone();
        clone.unwrapTemplate = (AttributeArray) this.unwrapTemplate.clone();
        clone.alwaysAuthenticate
            = (BooleanAttribute) this.alwaysAuthenticate.clone();

        // put all cloned attributes into the new table
        putAttributesInTable(clone);

        return clone;
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
    public boolean equals(java.lang.Object otherObject) {
        if (this == otherObject) {
            return true;
        }

        if (!(otherObject instanceof PrivateKey)) {
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
     * @preconditions
     * @postconditions (result <> null)
     */
    public ByteArrayAttribute getSubject() {
        return subject;
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
     * Gets the secondary authentication attribute of this key.
     *
     * @return The secondary authentication attribute.
     * @preconditions
     * @postconditions (result <> null)
     */
    public BooleanAttribute getSecondaryAuth() {
        return secondaryAuth;
    }

    /**
     * Gets the authentication flags for secondary authentication of this key.
     *
     * @return The authentication flags for secondary authentication attribute.
     * @preconditions
     * @postconditions (result <> null)
     */
    public LongAttribute getAuthPinFlags() {
        return authPinFlags;
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
     * Gets the sign recover attribute of this key.
     *
     * @return The sign recover attribute.
     * @preconditions
     * @postconditions (result <> null)
     */
    public BooleanAttribute getSignRecover() {
        return signRecover;
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
     * Gets the always authenticate attribute of this key.
     *
     * @return The always authenticate attribute.
     * @preconditions
     * @postconditions (result <> null)
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
     * @preconditions (session <> null)
     * @postconditions
     */
    @Override
    public void readAttributes(Session session)
        throws TokenException {
        super.readAttributes(session);

        Object.getAttributeValues(session, objectHandle, new Attribute[] {
            subject, sensitive, secondaryAuth, authPinFlags, decrypt,
            sign, signRecover, unwrap, extractable, alwaysSensitive,
            neverExtractable, wrapWithTrusted, alwaysAuthenticate });
        Object.getAttributeValue(session, objectHandle, unwrapTemplate);
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
        StringBuilder buffer = new StringBuilder(1024);

        buffer.append(super.toString());

        buffer.append(Constants.NEWLINE_INDENT);
        buffer.append("Subject (DER, hex): ");
        buffer.append(subject.toString());

        buffer.append(Constants.NEWLINE_INDENT);
        buffer.append("Sensitive: ");
        buffer.append(sensitive.toString());

        buffer.append(Constants.NEWLINE_INDENT);
        buffer.append("Secondary Authentication: ");
        buffer.append(secondaryAuth.toString());

        buffer.append(Constants.NEWLINE_INDENT);
        buffer.append("Secondary Authentication PIN Flags: ");
        if (authPinFlags.isPresent() && !authPinFlags.isSensitive()
            && (authPinFlags.getLongValue() != null)) {
            long authFlagsValue = authPinFlags.getLongValue().longValue();

            final String prefix = Constants.NEWLINE_INDENT + Constants.INDENT;
            buffer.append(prefix);
            buffer.append("User PIN-Count low: ");
            buffer.append((authFlagsValue
                        & PKCS11Constants.CKF_USER_PIN_COUNT_LOW) != 0L);

            buffer.append(prefix);
            buffer.append("User PIN final Try: ");
            buffer.append((authFlagsValue
                        & PKCS11Constants.CKF_USER_PIN_FINAL_TRY) != 0L);

            buffer.append(prefix);
            buffer.append("User PIN locked: ");
            buffer.append((authFlagsValue
                        & PKCS11Constants.CKF_USER_PIN_LOCKED) != 0L);

            buffer.append(prefix);
            buffer.append("User PIN to be changed: ");
            buffer.append((authFlagsValue
                        & PKCS11Constants.CKF_USER_PIN_TO_BE_CHANGED) != 0L);
        } else {
            buffer.append(authPinFlags.toString());
        }

        buffer.append(Constants.NEWLINE_INDENT);
        buffer.append("Decrypt: ");
        buffer.append(decrypt.toString());

        buffer.append(Constants.NEWLINE_INDENT);
        buffer.append("Sign: ");
        buffer.append(sign.toString());

        buffer.append(Constants.NEWLINE_INDENT);
        buffer.append("Sign Recover: ");
        buffer.append(signRecover.toString());

        buffer.append(Constants.NEWLINE_INDENT);
        buffer.append("Unwrap: ");
        buffer.append(unwrap.toString());

        buffer.append(Constants.NEWLINE_INDENT);
        buffer.append("Extractable: ");
        buffer.append(extractable.toString());

        buffer.append(Constants.NEWLINE_INDENT);
        buffer.append("Always Sensitive: ");
        buffer.append(alwaysSensitive.toString());

        buffer.append(Constants.NEWLINE_INDENT);
        buffer.append("Never Extractable: ");
        buffer.append(neverExtractable.toString());

        buffer.append(Constants.NEWLINE_INDENT);
        buffer.append("Wrap With Trusted: ");
        buffer.append(wrapWithTrusted.toString());

        buffer.append(Constants.NEWLINE_INDENT);
        buffer.append("Unwrap Template: ");
        buffer.append(unwrapTemplate.toString());

        buffer.append(Constants.NEWLINE_INDENT);
        buffer.append("Always Authenticate: ");
        buffer.append(alwaysAuthenticate.toString());

        return buffer.toString();
    }

}
