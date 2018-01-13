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
 * Objects of this class represent DH private keys as specified by PKCS#11
 * v2.11.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (prime <> null)
 *             and (base <> null)
 *             and (value <> null)
 *             and (valueBits <> null)
 */
// CHECKSTYLE:SKIP
public class DHPrivateKey extends PrivateKey {

    /**
     * The prime (p) of this DH key.
     */
    protected ByteArrayAttribute prime;

    /**
     * The base (g) of this DH key.
     */
    protected ByteArrayAttribute base;

    /**
     * The private value (x) of this DH key.
     */
    protected ByteArrayAttribute value;

    /**
     * The length of the value (x) of this DH key in bits.
     */
    protected LongAttribute valueBits;

    /**
     * Default Constructor.
     *
     * @preconditions
     * @postconditions
     */
    public DHPrivateKey() {
        keyType.setLongValue(KeyType.DH);
    }

    /**
     * Called by getInstance to create an instance of a PKCS#11 DH private key.
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
    protected DHPrivateKey(Session session, long objectHandle)
        throws TokenException {
        super(session, objectHandle);
        keyType.setLongValue(KeyType.DH);
    }

    /**
     * The getInstance method of the PrivateKey class uses this method to create
     * an instance of a PKCS#11 DH private key.
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
        return new DHPrivateKey(session, objectHandle);
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
    protected static void putAttributesInTable(DHPrivateKey object) {
        Util.requireNonNull("object", object);
        object.attributeTable.put(Attribute.PRIME, object.prime);
        object.attributeTable.put(Attribute.BASE, object.base);
        object.attributeTable.put(Attribute.VALUE, object.value);
        object.attributeTable.put(Attribute.VALUE_BITS, object.valueBits);
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

        prime = new ByteArrayAttribute(Attribute.PRIME);
        base = new ByteArrayAttribute(Attribute.BASE);
        value = new ByteArrayAttribute(Attribute.VALUE);
        valueBits = new LongAttribute(Attribute.VALUE_BITS);

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
        } else if (!(otherObject instanceof DHPrivateKey)) {
            return false;
        }

        DHPrivateKey other = (DHPrivateKey) otherObject;
        return super.equals(other)
                && this.prime.equals(other.prime)
                && this.base.equals(other.base)
                && this.value.equals(other.value)
                && this.valueBits.equals(other.valueBits);
    }

    /**
     * Gets the prime attribute of this DH key.
     *
     * @return The prime attribute.
     * @preconditions
     * @postconditions (result <> null)
     */
    public ByteArrayAttribute getPrime() {
        return prime;
    }

    /**
     * Gets the base attribute of this DH key.
     *
     * @return The base attribute.
     * @preconditions
     * @postconditions (result <> null)
     */
    public ByteArrayAttribute getBase() {
        return base;
    }

    /**
     * Gets the value attribute of this DH key.
     *
     * @return The value attribute.
     * @preconditions
     * @postconditions (result <> null)
     */
    public ByteArrayAttribute getValue() {
        return value;
    }

    /**
     * Gets the value length attribute of this DH key (in bits).
     *
     * @return The value length attribute.
     * @preconditions
     * @postconditions (result <> null)
     */
    public LongAttribute getValueBits() {
        return valueBits;
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
            prime, base, valueBits });
        PKCS11Object.getAttributeValue(session, objectHandle, value);
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
        sb.append("\n  Prime (hex): ").append(prime);
        sb.append("\n  Base (hex): ").append(base);
        sb.append("\n  Value (hex): ").append(value);
        sb.append("\n  Value Bits (dec): ").append(valueBits.toString(10));
        return sb.toString();
    }

}
