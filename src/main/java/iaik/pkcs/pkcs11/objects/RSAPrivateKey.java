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
 * Objects of this class represent RSA private keys as specified by PKCS#11
 * v2.11.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (modulus <> null)
 *             and (publicExponent <> null)
 *             and (privateExponent <> null)
 *             and (prime1 <> null)
 *             and (prime2 <> null)
 *             and (exponent1 <> null)
 *             and (exponent2 <> null)
 *             and (coefficient <> null)
 */
// CHECKSTYLE:SKIP
public class RSAPrivateKey extends PrivateKey {

    /**
     * The modulus (n) of this RSA key.
     */
    protected ByteArrayAttribute modulus;

    /**
     * The public exponent (e) of this RSA key.
     */
    protected ByteArrayAttribute publicExponent;

    /**
     * The private exponent (d) of this RSA key.
     */
    protected ByteArrayAttribute privateExponent;

    /**
     * The first prime factor (p) of this RSA key, for use with CRT.
     */
    protected ByteArrayAttribute prime1;

    /**
     * The second prime factor (q) of this RSA key, for use with CRT.
     */
    protected ByteArrayAttribute prime2;

    /**
     * The first exponent (d mod (p-1)) of this RSA key, for use with CRT.
     */
    protected ByteArrayAttribute exponent1;

    /**
     * The second exponent (d mod (q-1)) of this RSA key, for use with CRT.
     */
    protected ByteArrayAttribute exponent2;

    /**
     * The coefficient (1/q mod (p)) of this RSA key, for use with CRT.
     */
    protected ByteArrayAttribute coefficient;

    /**
     * Default Constructor.
     *
     * @preconditions
     * @postconditions
     */
    public RSAPrivateKey() {
        super();
        keyType.setLongValue(KeyType.RSA);
    }

    /**
     * Called by getInstance to create an instance of a PKCS#11 RSA private key.
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
    protected RSAPrivateKey(Session session, long objectHandle)
        throws TokenException {
        super(session, objectHandle);
        keyType.setLongValue(KeyType.RSA);
    }

    /**
     * The getInstance method of the PrivateKey class uses this method to create
     * an instance of a PKCS#11 RSA private key.
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
        return new RSAPrivateKey(session, objectHandle);
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
    protected static void putAttributesInTable(RSAPrivateKey object) {
        Util.requireNonNull("object", object);
        object.attributeTable.put(Attribute.MODULUS, object.modulus);
        object.attributeTable.put(Attribute.PUBLIC_EXPONENT,
                object.publicExponent);
        object.attributeTable.put(Attribute.PRIVATE_EXPONENT,
                object.privateExponent);
        object.attributeTable.put(Attribute.PRIME_1, object.prime1);
        object.attributeTable.put(Attribute.PRIME_2, object.prime2);
        object.attributeTable.put(Attribute.EXPONENT_1, object.exponent1);
        object.attributeTable.put(Attribute.EXPONENT_2, object.exponent2);
        object.attributeTable.put(Attribute.COEFFICIENT, object.coefficient);
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

        modulus = new ByteArrayAttribute(Attribute.MODULUS);
        publicExponent = new ByteArrayAttribute(Attribute.PUBLIC_EXPONENT);
        privateExponent = new ByteArrayAttribute(Attribute.PRIVATE_EXPONENT);
        prime1 = new ByteArrayAttribute(Attribute.PRIME_1);
        prime2 = new ByteArrayAttribute(Attribute.PRIME_2);
        exponent1 = new ByteArrayAttribute(Attribute.EXPONENT_1);
        exponent2 = new ByteArrayAttribute(Attribute.EXPONENT_2);
        coefficient = new ByteArrayAttribute(Attribute.COEFFICIENT);

        putAttributesInTable(this);
    }

    /**
     * Create a (deep) clone of this object.
     *
     * @return A clone of this object.
     * @preconditions
     * @postconditions (result <> null)
     *                 and (result instanceof RSAPrivateKey)
     *                 and (result.equals(this))
     */
    @Override
    public Object clone() {
        RSAPrivateKey clone = (RSAPrivateKey) super.clone();

        clone.modulus = (ByteArrayAttribute) this.modulus.clone();
        clone.publicExponent
            = (ByteArrayAttribute) this.publicExponent.clone();
        clone.privateExponent
            = (ByteArrayAttribute) this.privateExponent.clone();
        clone.prime1 = (ByteArrayAttribute) this.prime1.clone();
        clone.prime2 = (ByteArrayAttribute) this.prime2.clone();
        clone.exponent1 = (ByteArrayAttribute) this.exponent1.clone();
        clone.exponent2 = (ByteArrayAttribute) this.exponent2.clone();
        clone.coefficient = (ByteArrayAttribute) this.coefficient.clone();

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
    public boolean equals(Object otherObject) {
        if (this == otherObject) {
            return true;
        }

        if (!(otherObject instanceof RSAPrivateKey)) {
            return false;
        }

        RSAPrivateKey other = (RSAPrivateKey) otherObject;
        return super.equals(other)
                && this.modulus.equals(other.modulus)
                && this.publicExponent.equals(other.publicExponent)
                && this.privateExponent.equals(other.privateExponent)
                && this.prime1.equals(other.prime1)
                && this.prime2.equals(other.prime2)
                && this.exponent1.equals(other.exponent1)
                && this.exponent2.equals(other.exponent2)
                && this.coefficient.equals(other.coefficient);
    }

    /**
     * Gets the modulus attribute of this RSA key.
     *
     * @return The modulus attribute.
     * @preconditions
     * @postconditions (result <> null)
     */
    public ByteArrayAttribute getModulus() {
        return modulus;
    }

    /**
     * Gets the public exponent attribute of this RSA key.
     *
     * @return The public exponent attribute.
     * @preconditions
     * @postconditions (result <> null)
     */
    public ByteArrayAttribute getPublicExponent() {
        return publicExponent;
    }

    /**
     * Gets the private exponent attribute of this RSA key.
     *
     * @return The private exponent attribute.
     * @preconditions
     * @postconditions (result <> null)
     */
    public ByteArrayAttribute getPrivateExponent() {
        return privateExponent;
    }

    /**
     * Gets the first prime attribute of this RSA key.
     *
     * @return The first prime attribute.
     * @preconditions
     * @postconditions (result <> null)
     */
    public ByteArrayAttribute getPrime1() {
        return prime1;
    }

    /**
     * Gets the second prime attribute of this RSA key.
     *
     * @return The second prime attribute.
     * @preconditions
     * @postconditions (result <> null)
     */
    public ByteArrayAttribute getPrime2() {
        return prime2;
    }

    /**
     * Gets the first exponent (d mod (p-1)) attribute of this RSA key.
     *
     * @return The first exponent (d mod (p-1)) attribute.
     * @preconditions
     * @postconditions (result <> null)
     */
    public ByteArrayAttribute getExponent1() {
        return exponent1;
    }

    /**
     * Gets the second exponent (d mod (q-1)) attribute of this RSA key.
     *
     * @return The second exponent (d mod (q-1)) attribute.
     * @preconditions
     * @postconditions (result <> null)
     */
    public ByteArrayAttribute getExponent2() {
        return exponent2;
    }

    /**
     * Gets the coefficient (1/q mod (p)) attribute of this RSA key.
     *
     * @return The coefficient (1/q mod (p)) attribute.
     * @preconditions
     * @postconditions (result <> null)
     */
    public ByteArrayAttribute getCoefficient() {
        return coefficient;
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
            modulus, publicExponent });
        PKCS11Object.getAttributeValues(session, objectHandle, new Attribute[] {
            privateExponent, prime1, prime2, exponent1, exponent2,
            coefficient });
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
        StringBuilder sb = new StringBuilder(super.toString());
        sb.append("\n  Modulus (hex): ").append(modulus);
        sb.append("\n  Public Exponent (hex): ").append(publicExponent);
        sb.append("\n  Private Exponent (hex): ").append(privateExponent);
        sb.append("\n  Prime 1 (hex): ").append(prime1);
        sb.append("\n  Prime 2 (hex): ").append(prime2);
        sb.append("\n  Exponent 1 (hex): ").append(exponent1);
        sb.append("\n  Exponent 2 (hex): ").append(exponent2);
        sb.append("\n  Coefficient (hex): ").append(coefficient);
        return sb.toString();
    }

}
