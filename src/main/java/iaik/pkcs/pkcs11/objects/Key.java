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

import java.util.Hashtable;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.Util;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import iaik.pkcs.pkcs11.wrapper.PKCS11VendorConstants;

/**
 * An object of this class represents a key as defined by PKCS#11 2.11.
 * A key is of a specific type: RSA, DSA, DH, ECDSA, EC, X9_42_DH, KEA,
 * GENERIC_SECRET, RC2, RC4, DES, DES2, DES3, CAST, CAST3, CAST5, CAST128,
 * RC5, IDEA, SKIPJACK, BATON, JUNIPER, CDMF, AES or VENDOR_DEFINED.
 * If an application needs to use vendor-defined keys,  it must set a
 * VendorDefinedKeyeBuilder using the setVendorDefinedKeyBuilder method.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (keyType <> null)
 *             and (id <> null)
 *             and (startDate <> null)
 *             and (endDate <> null)
 *             and (derive <> null)
 *             and (local <> null)
 *             and (keyGenMechanism <> null)
 */
public class Key extends Storage {

    /**
     * This interface defines the available key types as defined by PKCS#11
     * v2.11:
     * RSA, DSA, DH, ECDSA, KEA, GENERIC_SECRET, RC2, RC4, DES, DES2, DES3,
     * CAST, CAST3, CAST5, CAST128, RC5, IDEA, SKIPJACK, BATON, JUNIPER, CDMF,
     * AES, EC, X9_42_DH or VENDOR_DEFINED.
     *
     * @author Karl Scheibelhofer
     * @version 1.0
     * @invariants
     */
    public interface KeyType {

        /**
         * The identifier for a RSA key.
         */
        public static final Long RSA = new Long(PKCS11Constants.CKK_RSA);

        /**
         * The identifier for a DSA key.
         */
        public static final Long DSA = new Long(PKCS11Constants.CKK_DSA);

        /**
         * The identifier for a Diffi-Hellman key.
         */
        public static final Long DH = new Long(PKCS11Constants.CKK_DH);

        /**
         * The identifier for a EC key.
         */
        public static final Long EC = new Long(PKCS11Constants.CKK_EC);

        /**
         * The identifier for a EC key.
         */
        public static final Long X9_42_DH
            = new Long(PKCS11Constants.CKK_X9_42_DH);

        /**
         * The identifier for a KEA key.
         */
        public static final Long KEA = new Long(PKCS11Constants.CKK_KEA);

        /**
         * The identifier for a generic secret key.
         */
        public static final Long GENERIC_SECRET
            = new Long(PKCS11Constants.CKK_GENERIC_SECRET);

        /**
         * The identifier for a RC2 key.
         */
        public static final Long RC2 = new Long(PKCS11Constants.CKK_RC2);

        /**
         * The identifier for a RC4 key.
         */
        public static final Long RC4 = new Long(PKCS11Constants.CKK_RC4);

        /**
         * The identifier for a DES key.
         */
        public static final Long DES = new Long(PKCS11Constants.CKK_DES);

        /**
         * The identifier for a double-length DES key.
         */
        public static final Long DES2 = new Long(PKCS11Constants.CKK_DES2);

        /**
         * The identifier for a trible-length DES key (Trible-DES).
         */
        public static final Long DES3 = new Long(PKCS11Constants.CKK_DES3);

        /**
         * The identifier for a CAST key.
         */
        public static final Long CAST = new Long(PKCS11Constants.CKK_CAST);

        /**
         * The identifier for a CAST3 key.
         */
        public static final Long CAST3 = new Long(PKCS11Constants.CKK_CAST3);

        /**
         * The identifier for a CAST128 key.
         */
        public static final Long CAST128
            = new Long(PKCS11Constants.CKK_CAST128);

        /**
         * The identifier for a RC5 key.
         */
        public static final Long RC5 = new Long(PKCS11Constants.CKK_RC5);

        /**
         * The identifier for a IDEA key.
         */
        public static final Long IDEA = new Long(PKCS11Constants.CKK_IDEA);

        /**
         * The identifier for a SKIPJACK key.
         */
        public static final Long SKIPJACK
            = new Long(PKCS11Constants.CKK_SKIPJACK);

        /**
         * The identifier for a BATON key.
         */
        public static final Long BATON = new Long(PKCS11Constants.CKK_BATON);

        /**
         * The identifier for a JUNIPER key.
         */
        public static final Long JUNIPER
            = new Long(PKCS11Constants.CKK_JUNIPER);

        /**
         * The identifier for a CDMF key.
         */
        public static final Long CDMF = new Long(PKCS11Constants.CKK_CDMF);

        /**
         * The identifier for a AES key.
         */
        public static final Long AES = new Long(PKCS11Constants.CKK_AES);

        /**
         * The identifier for a Blowfish key.
         */
        public static final Long BLOWFISH
            = new Long(PKCS11Constants.CKK_BLOWFISH);

        /**
         * The identifier for a Twofish key.
         */
        public static final Long TWOFISH
            = new Long(PKCS11Constants.CKK_TWOFISH);
        
        /**
         * The identifier for a SM2 key.
         */
        public static final Long VENDOR_SM2
            = new Long(PKCS11VendorConstants.CKK_VENDOR_SM2);
        
        /**
         * The identifier for a SM4 key.
         */
        public static final Long VENDOR_SM4
            = new Long(PKCS11VendorConstants.CKK_VENDOR_SM4);
        
        /**
         * The identifier for a VENDOR_DEFINED key. Any Long object with a
         * value bigger than this one is also a valid vendor-defined key
         * type identifier.
         */
        public static final Long VENDOR_DEFINED
            = new Long(PKCS11Constants.CKK_VENDOR_DEFINED);

    }

    /**
     * If an application uses vendor defined keys, it must implement this
     * interface and install such an object handler using
     * setVendorDefinedKeyBuilder.
     *
     * @author Karl Scheibelhofer
     * @version 1.0
     * @invariants
     */
    public interface VendorDefinedKeyBuilder {

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
         * @exception PKCS11Exception
         *              If getting the attributes failed.
         * @preconditions (session <> null)
         * @postconditions (result <> null)
         */
        public PKCS11Object build(Session session, long objectHandle)
            throws PKCS11Exception;

    }

    /**
     * The currently set vendor defined key builder, or null.
     */
    protected static VendorDefinedKeyBuilder vendorKeyBuilder;

    /**
     * A table holding string representations for all known key types. Table key
     * is the key type as Long object.
     */
    protected static Hashtable<Long, String> keyTypeNames;

    /**
     * The type of this key. Its value is one of KeyType, or one that has a
     * bigger value than VENDOR_DEFINED.
     */
    protected KeyTypeAttribute keyType;

    /**
     * The identifier (ID) of this key.
     */
    protected ByteArrayAttribute id;

    /**
     * The start date of this key's validity.
     */
    protected DateAttribute startDate;

    /**
     * The end date of this key's validity.
     */
    protected DateAttribute endDate;

    /**
     * True, if other keys can be derived from this key.
     */
    protected BooleanAttribute derive;

    /**
     * True, if this key was created (generated or copied from a different key)
     * on the token.
     */
    protected BooleanAttribute local;

    /**
     * The mechanism used to generate the key material.
     */
    protected MechanismAttribute keyGenMechanism;

    /**
     * The list of mechanism that can be used with this key.
     */
    protected MechanismArrayAttribute allowedMechanisms;

    /**
     * The default constructor. An application use this constructor to
     * instantiate a key that serves as a template. It may also be useful for
     * working with vendor-defined keys.
     *
     * @preconditions
     * @postconditions
     */
    public Key() {
    }

    /**
     * Called by sub-classes to create an instance of a PKCS#11 key.
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
    protected Key(Session session, long objectHandle)
        throws TokenException {
        super(session, objectHandle);
    }

    /**
     * Set a vendor-defined key builder that should be called to create an
     * instance of an vendor-defined PKCS#11 key; i.e. an instance of a
     * vendor defined sub-class of this class.
     *
     * @param builder
     *          The vendor-defined key builder. Null to clear any previously
     *          installed vendor-defined builder.
     * @preconditions
     * @postconditions
     */
    public static void setVendorDefinedKeyBuilder(
            VendorDefinedKeyBuilder builder) {
        vendorKeyBuilder = builder;
    }

    /**
     * Get the currently set vendor-defined key builder.
     *
     * @return The currently set vendor-defined key builder or null if
     *         none is set.
     * @preconditions
     * @postconditions
     */
    public static VendorDefinedKeyBuilder getVendorDefinedKeyBuilder() {
        return vendorKeyBuilder;
    }

    /**
     * Get the given key type as string.
     *
     * @param keyType
     *          The key type to get as string.
     * @return A string denoting the key type; e.g. "RSA".
     * @preconditions (keyType <> null)
     * @postconditions (result <> null)
     */
    public static String getKeyTypeName(Long keyType) {
        Util.requireNonNull("keyType", keyType);

        if (keyTypeNames == null) {
            // setup key type names table
            keyTypeNames = new Hashtable<>(24);
            keyTypeNames.put(KeyType.RSA, "RSA");
            keyTypeNames.put(KeyType.DSA, "DSA");
            keyTypeNames.put(KeyType.DH, "DH");
            keyTypeNames.put(KeyType.EC, "EC");
            keyTypeNames.put(KeyType.X9_42_DH, "X9_42_DH");
            keyTypeNames.put(KeyType.KEA, "KEA");
            keyTypeNames.put(KeyType.GENERIC_SECRET, "GENERIC_SECRET");
            keyTypeNames.put(KeyType.RC2, "RC2");
            keyTypeNames.put(KeyType.RC4, "RC4");
            keyTypeNames.put(KeyType.DES, "DES");
            keyTypeNames.put(KeyType.DES2, "DES2");
            keyTypeNames.put(KeyType.DES3, "DES3");
            keyTypeNames.put(KeyType.CAST, "CAST");
            keyTypeNames.put(KeyType.CAST3, "CAST3");
            keyTypeNames.put(KeyType.CAST128, "CAST128");
            keyTypeNames.put(KeyType.RC5, "RC5");
            keyTypeNames.put(KeyType.IDEA, "IDEA");
            keyTypeNames.put(KeyType.SKIPJACK, "SKIPJACK");
            keyTypeNames.put(KeyType.BATON, "BATON");
            keyTypeNames.put(KeyType.JUNIPER, "JUNIPER");
            keyTypeNames.put(KeyType.CDMF, "CDMF");
            keyTypeNames.put(KeyType.AES, "AES");
            keyTypeNames.put(KeyType.BLOWFISH, "BLOWFISH");
            keyTypeNames.put(KeyType.TWOFISH, "TWOFISH");
            keyTypeNames.put(KeyType.VENDOR_SM2, "SM2");
            keyTypeNames.put(KeyType.VENDOR_SM4, "SM4");
        }

        String keyTypeName = (String) keyTypeNames.get(keyType);
        if (keyTypeName == null) {
            if ((keyType.longValue()
                    & PKCS11Constants.CKK_VENDOR_DEFINED) != 0L) {
                keyTypeName = "Vendor Defined";
            } else {
                keyTypeName = "<unknown>";
            }
        }

        return keyTypeName;
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
    protected static void putAttributesInTable(Key object) {
        Util.requireNonNull("object", object);
        object.attributeTable.put(Attribute.KEY_TYPE, object.keyType);
        object.attributeTable.put(Attribute.ID, object.id);
        object.attributeTable.put(Attribute.START_DATE, object.startDate);
        object.attributeTable.put(Attribute.END_DATE, object.endDate);
        object.attributeTable.put(Attribute.DERIVE, object.derive);
        object.attributeTable.put(Attribute.LOCAL, object.local);
        object.attributeTable.put(Attribute.KEY_GEN_MECHANISM,
                object.keyGenMechanism);
        object.attributeTable.put(Attribute.ALLOWED_MECHANISMS,
                object.allowedMechanisms);
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

        keyType = new KeyTypeAttribute();
        id = new ByteArrayAttribute(Attribute.ID);
        startDate = new DateAttribute(Attribute.START_DATE);
        endDate = new DateAttribute(Attribute.END_DATE);
        derive = new BooleanAttribute(Attribute.DERIVE);
        local = new BooleanAttribute(Attribute.LOCAL);
        keyGenMechanism = new MechanismAttribute(
                Attribute.KEY_GEN_MECHANISM);
        allowedMechanisms = new MechanismArrayAttribute(
                Attribute.ALLOWED_MECHANISMS);

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
        } else if (!(otherObject instanceof Key)) {
            return false;
        }

        Key other = (Key) otherObject;
        return super.equals(other)
                && this.keyType.equals(other.keyType)
                && this.id.equals(other.id)
                && this.startDate.equals(other.startDate)
                && this.endDate.equals(other.endDate)
                && this.derive.equals(other.derive)
                && this.local.equals(other.local)
                && this.keyGenMechanism.equals(other.keyGenMechanism)
                && this.allowedMechanisms.equals(other.allowedMechanisms);
    }

    /**
     * Gets the key type attribute of the PKCS#11 key. Its value must
     * be one of those defined in the KeyType interface or one with an
     * value bigger than KeyType.VENDOR_DEFINED.
     *
     * @return The key type identifier.
     * @preconditions
     * @postconditions (result <> null)
     */
    public LongAttribute getKeyType() {
        return keyType;
    }

    /**
     * Gets the ID attribute of this key.
     *
     * @return The key identifier attribute.
     * @preconditions
     * @postconditions (result <> null)
     */
    public ByteArrayAttribute getId() {
        return id;
    }

    /**
     * Gets the start date attribute of the validity of this key.
     *
     * @return The start date of validity.
     * @preconditions
     * @postconditions (result <> null)
     */
    public DateAttribute getStartDate() {
        return startDate;
    }

    /**
     * Gets the end date attribute of the validity of this key.
     *
     * @return The end date of validity.
     * @preconditions
     * @postconditions (result <> null)
     */
    public DateAttribute getEndDate() {
        return endDate;
    }

    /**
     * Check, if other keys can be derived from this key.
     *
     * @return Its value is true, if other keys can be derived from this key.
     * @preconditions
     * @postconditions (result <> null)
     */
    public BooleanAttribute getDerive() {
        return derive;
    }

    /**
     * Check, if this key is a local key; i.e. was generated on the token or
     * created via copy from a different key on the token.
     *
     * @return Its value is true, if the key was created on the token.
     * @preconditions
     * @postconditions (result <> null)
     */
    public BooleanAttribute getLocal() {
        return local;
    }

    /**
     * Get the mechanism used to generate the key material for this key.
     *
     * @return The mechanism attribute used to generate the key material for
     *         this key.
     * @preconditions
     * @postconditions (result <> null)
     */
    public MechanismAttribute getKeyGenMechanism() {
        return keyGenMechanism;
    }

    /**
     * Get the list of mechanisms that are allowed to use with this key. This
     * attribute can only be used with PKCS#11 modules supporting
     * cryptoki version 2.20 or higher.
     *
     * @return The list of mechanisms that are allowed to use with this key.
     * @preconditions
     * @postconditions (result <> null)
     */
    public MechanismArrayAttribute getAllowedMechanisms() {
        return allowedMechanisms;
    }

    /**
     * The overriding of this method should ensure that the objects of this
     * class work correctly in a hashtable.
     *
     * @return The hash code of this object.
     * @preconditions
     * @postconditions
     */
    @Override
    public int hashCode() {
        return keyType.hashCode() ^ id.hashCode();
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
            id, startDate, endDate, derive, local, keyGenMechanism });
        PKCS11Object.getAttributeValue(session, objectHandle,
                allowedMechanisms);
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
        return Util.concatObjectsCap(superToString.length() + 100, superToString,
                "\n  Key Type: ", ((keyType != null) ? keyType.toString() : "<unavailable>"),
                "\n  ID: ", id,
                "\n  Start Date: ", startDate,
                "\n  End Date: ", endDate,
                "\n  Derive: ", derive,
                "\n  Local: ", local,
                "\n  Key Generation Mechanism: ", keyGenMechanism,
                "\n  Allowed Mechanisms: ", allowedMechanisms);
    }

}
