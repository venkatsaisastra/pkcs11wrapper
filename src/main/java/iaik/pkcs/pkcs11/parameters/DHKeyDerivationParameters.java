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

package iaik.pkcs.pkcs11.parameters;

import java.util.Arrays;

import iaik.pkcs.pkcs11.TokenRuntimeException;
import iaik.pkcs.pkcs11.Util;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * This abstract class encapsulates parameters for the DH mechanisms
 * Mechanism.ECDH1_DERIVE, Mechanism.ECDH1_COFACTOR_DERIVE,
 * Mechanism.ECMQV_DERIVE, Mechanism.X9_42_DH_DERIVE ,
 * Mechanism.X9_42_DH_HYBRID_DERIVE and Mechanism.X9_42_MQV_DERIVE.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (keyDerivationFunction
 *                      == KeyDerivationFunctionType.NULL)
 *              or (keyDerivationFunction
 *                      == KeyDerivationFunctionType.SHA1_KDF)
 *              or (keyDerivationFunction
 *                      == KeyDerivationFunctionType.SHA1_KDF_ASN1)
 *              or (keyDerivationFunction
 *                      == KeyDerivationFunctionType.SHA1_KDF_CONCATENATE))
 *             and (publicData <> null)
 */
// CHECKSTYLE:SKIP
abstract public class DHKeyDerivationParameters implements Parameters {

    /**
     * This interface defines the available key derivation function types as
     * defined by PKCS#11: CKD_NULL, CKD_SHA1_KDF, CKD_SHA1_KDF_ASN1,
     * CKD_SHA1_KDF_CONCATENATE.
     *
     * @author Karl Scheibelhofer
     * @version 1.0
     * @invariants
     */
    public interface KeyDerivationFunctionType {

        /**
         * The identifier for CKD_NULL.
         */
        public static final long NULL = PKCS11Constants.CKD_NULL;

        /**
         * The identifier for CKD_SHA1_KDF.
         */
        public static final long SHA1_KDF = PKCS11Constants.CKD_SHA1_KDF;

        /**
         * The identifier for CKD_SHA1_KDF_ASN1.
         */
        public static final long SHA1_KDF_ASN1
            = PKCS11Constants.CKD_SHA1_KDF_ASN1;

        /**
         * The identifier for CKD_SHA1_KDF_CONCATENATE.
         */
        public static final long SHA1_KDF_CONCATENATE
            = PKCS11Constants.CKD_SHA1_KDF_CONCATENATE;

    }

    /**
     * The key derivation function used on the shared secret value.
     */
    protected long kdf;

    /**
     * The other partie's public key value.
     */
    protected byte[] publicData;

    /**
     * Create a new DHKeyDerivationParameters object with the given attributes.
     *
     * @param kdf
     *          The key derivation function used on the shared secret value.
     *          One of the values defined in KeyDerivationFunctionType.
     * @param publicData
     *          The other partie's public key value.
     * @preconditions ((kdf == KeyDerivationFunctionType.NULL)
     *              or (kdf == KeyDerivationFunctionType.SHA1_KDF)
     *              or (kdf == KeyDerivationFunctionType.SHA1_KDF_ASN1)
     *              or (kdf == KeyDerivationFunctionType.SHA1_KDF_CONCATENATE))
     *              and (publicData <> null)
     * @postconditions
     */
    protected DHKeyDerivationParameters(long kdf,
            byte[] publicData) {
        if ((kdf != KeyDerivationFunctionType.NULL)
            && (kdf != KeyDerivationFunctionType.SHA1_KDF)
            && (kdf != KeyDerivationFunctionType.SHA1_KDF_ASN1)
            && (kdf != KeyDerivationFunctionType.SHA1_KDF_CONCATENATE)) {
            throw new IllegalArgumentException(
                "Illegal value for argument\"kdf\": " + Long.toHexString(kdf));
        }

        this.publicData = Util.requireNonNull("publicData", publicData);
        this.kdf = kdf;
    }

    /**
     * Create a (deep) clone of this object.
     *
     * @return A clone of this object.
     * @preconditions
     * @postconditions (result <> null)
     *                 and (result instanceof DHKeyDerivationParameters)
     *                 and (result.equals(this))
     */
    @Override
    public Object clone() {
        DHKeyDerivationParameters clone;

        try {
            clone = (DHKeyDerivationParameters) super.clone();

            clone.publicData = (byte[]) this.publicData.clone();
        } catch (CloneNotSupportedException ex) {
            // this must not happen, because this class is cloneable
            throw new TokenRuntimeException(
                    "An unexpected clone exception occurred.", ex);
        }

        return clone;
    }

    /**
     * Get the key derivation function used on the shared secret value.
     *
     * @return The key derivation function used on the shared secret value.
     *         One of the values defined in KeyDerivationFunctionType.
     * @preconditions
     * @postconditions
     */
    public long getKeyDerivationFunction() {
        return kdf;
    }

    /**
     * Get the other partie's public key value.
     *
     * @return The other partie's public key value.
     * @preconditions
     * @postconditions (result <> null)
     */
    public byte[] getPublicData() {
        return publicData;
    }

    /**
     * Set the key derivation function used on the shared secret value.
     *
     * @param kdf
     *          The key derivation function used on the shared secret value.
     *          One of the values defined in KeyDerivationFunctionType.
     * @preconditions (kdf  == KeyDerivationFunctionType.NULL)
     *             or (kdf == KeyDerivationFunctionType.SHA1_KDF))
     *             or (kdf == KeyDerivationFunctionType.SHA1_KDF_ASN1))
     *             or (kdf == KeyDerivationFunctionType.SHA1_KDF_CONCATENATE))
     * @postconditions
     */
    public void setKeyDerivationFunction(long kdf) {
        if ((kdf != KeyDerivationFunctionType.NULL)
            && (kdf != KeyDerivationFunctionType.SHA1_KDF)
            && (kdf != KeyDerivationFunctionType.SHA1_KDF_ASN1)
            && (kdf != KeyDerivationFunctionType.SHA1_KDF_CONCATENATE)) {
            throw new IllegalArgumentException(
                "Illegal value for argument\"kdf\": " + Long.toHexString(kdf));
        }
        this.kdf = kdf;
    }

    /**
     * Set the other partie's public key value.
     *
     * @param publicData
     *          The other partie's public key value.
     * @preconditions (publicData <> null)
     * @postconditions
     */
    public void setPublicData(byte[] publicData) {
        this.publicData = Util.requireNonNull("publicData", publicData);
    }

    /**
     * Returns the string representation of this object. Do not parse data from
     * this string, it is for debugging only.
     *
     * @return A string representation of this object.
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("  Key Derivation Function: ");
        if (kdf == KeyDerivationFunctionType.NULL) {
            sb.append("NULL");
        } else if (kdf == KeyDerivationFunctionType.SHA1_KDF) {
            sb.append("SHA1_KDF");
        } else if (kdf == KeyDerivationFunctionType.SHA1_KDF_ASN1) {
            sb.append("SHA1_KDF_ASN1");
        } else if (kdf == KeyDerivationFunctionType.SHA1_KDF_CONCATENATE) {
            sb.append("SHA1_KDF_CONCATENATE");
        } else {
            sb.append("<unknown>");
        }

        sb.append("\n  Public Data: ")
            .append(Functions.toHexString(publicData));

        return sb.toString();
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

        if (!(otherObject instanceof DHKeyDerivationParameters)) {
            return false;
        }

        DHKeyDerivationParameters other
                = (DHKeyDerivationParameters) otherObject;
        return (this.kdf == other.kdf)
                && Arrays.equals(this.publicData, other.publicData);
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
        return ((int) kdf) ^ Functions.hashCode(publicData);
    }

}
