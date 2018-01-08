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

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.TokenRuntimeException;
import iaik.pkcs.pkcs11.Util;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * This abstract class encapsulates parameters for the RSA PKCS mechanisms
 * Mechanism.RSA_PKCS_OAEP and Mechanism.RSA_PKCS_PSS.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (hashAlgorithm <> null)
 *             and (maskGenerationFunction
 *                  == MessageGenerationFunctionType.Sha1)
 */
// CHECKSTYLE:SKIP
abstract public class RSAPkcsParameters implements Parameters {

    /**
     * This interface defines the available message generation function types as
     * defined by PKCS#11: CKG_MGF1_SHA1, CKG_MGF1_SHA256, CKG_MGF1_SHA384
     * and CKG_MGF1_SHA512.
     *
     * @author Karl Scheibelhofer
     * @version 1.0
     * @invariants
     */
    public interface MessageGenerationFunctionType {

        /**
         * The identifier for CKG_MGF1_SHA1.
         */
        public static final long SHA1 = PKCS11Constants.CKG_MGF1_SHA1;

        /**
         * The identifier for CKG_MGF1_SHA224.
         */
        public static final long SHA224 = PKCS11Constants.CKG_MGF1_SHA224;

        /**
         * The identifier for CKG_MGF1_SHA256.
         */
        public static final long SHA256 = PKCS11Constants.CKG_MGF1_SHA256;

        /**
         * The identifier for CKG_MGF1_SHA384.
         */
        public static final long SHA384 = PKCS11Constants.CKG_MGF1_SHA384;

        /**
         * The identifier for CKG_MGF1_SHA512.
         */
        public static final long SHA512 = PKCS11Constants.CKG_MGF1_SHA512;

        /**
         * The identifier for CKG_MGF1_SHA3_224.
         */
        public static final long SHA3_224 = PKCS11Constants.CKG_MGF1_SHA3_224;

        /**
         * The identifier for CKG_MGF1_SHA3_256.
         */
        public static final long SHA3_256 = PKCS11Constants.CKG_MGF1_SHA3_256;

        /**
         * The identifier for CKG_MGF1_SHA3_384.
         */
        public static final long SHA3_384 = PKCS11Constants.CKG_MGF1_SHA3_384;

        /**
         * The identifier for CKG_MGF1_SHA3_512.
         */
        public static final long SHA3_512 = PKCS11Constants.CKG_MGF1_SHA3_512;

    }

    /**
     * The message digest algorithm used to calculate the digest of the encoding
     * parameter.
     */
    protected Mechanism hashAlg;

    /**
     * The mask to apply to the encoded block.
     */
    protected long mgf;

    /**
     * Create a new RSAPkcsarameters object with the given attributes.
     *
     * @param hashAlg
     *          The message digest algorithm used to calculate the digest of the
     *          encoding parameter.
     * @param mgf
     *          The mask to apply to the encoded block. One of the constants
     *          defined in the MessageGenerationFunctionType interface.
     * @preconditions (hashAlgorithm <> null)
     *                and (maskGenerationFunction
     *                      == MessageGenerationFunctionType.Sha1)
     * @postconditions
     */
    protected RSAPkcsParameters(Mechanism hashAlg,
            long mgf) {
        if ((mgf != MessageGenerationFunctionType.SHA1)
            && (mgf != MessageGenerationFunctionType.SHA224)
            && (mgf != MessageGenerationFunctionType.SHA256)
            && (mgf != MessageGenerationFunctionType.SHA384)
            && (mgf != MessageGenerationFunctionType.SHA512)
            && (mgf != MessageGenerationFunctionType.SHA3_224)
            && (mgf != MessageGenerationFunctionType.SHA3_256)
            && (mgf != MessageGenerationFunctionType.SHA3_384)
            && (mgf != MessageGenerationFunctionType.SHA3_512)) {
            throw new IllegalArgumentException(
                "Illegal value for argument\"mgf\": " + Long.toHexString(mgf));
        }
        this.hashAlg = Util.requireNonNull("hashAlg", hashAlg);
        this.mgf = mgf;
    }

    /**
     * Create a (deep) clone of this object.
     *
     * @return A clone of this object.
     * @preconditions
     * @postconditions (result <> null)
     *                 and (result instanceof RSAPkcsParameters)
     *                 and (result.equals(this))
     */
    @Override
    public java.lang.Object clone() {
        RSAPkcsParameters clone;

        try {
            clone = (RSAPkcsParameters) super.clone();

            clone.hashAlg = (Mechanism) this.hashAlg.clone();
        } catch (CloneNotSupportedException ex) {
            // this must not happen, because this class is cloneable
            throw new TokenRuntimeException(
                    "An unexpected clone exception occurred.", ex);
        }

        return clone;
    }

    /**
     * Get the message digest algorithm used to calculate the digest of the
     * encoding parameter.
     *
     * @return The message digest algorithm used to calculate the digest of the
     *         encoding parameter.
     * @preconditions
     * @postconditions (result <> null)
     */
    public Mechanism getHashAlgorithm() {
        return hashAlg;
    }

    /**
     * Get the mask to apply to the encoded block.
     *
     * @return The mask to apply to the encoded block.
     * @preconditions
     * @postconditions
     */
    public long getMaskGenerationFunction() {
        return mgf;
    }

    /**
     * Set the message digest algorithm used to calculate the digest of the
     * encoding parameter.
     *
     * @param hashAlgorithm
     *          The message digest algorithm used to calculate the digest of the
     *          encoding parameter.
     * @preconditions (hashAlgorithm <> null)
     * @postconditions
     */
    public void setHashAlgorithm(Mechanism hashAlg) {
        this.hashAlg = Util.requireNonNull("hashAlg", hashAlg);
    }

    /**
     * Set the mask function to apply to the encoded block. One of the constants
     * defined in the MessageGenerationFunctionType interface.
     *
     * @param mgf
     *          The mask to apply to the encoded block.
     * @preconditions (mgf
     *                  == MessageGenerationFunctionType.Sha1)
     * @postconditions
     */
    public void setMaskGenerationFunction(long mgf) {
        if ((mgf != MessageGenerationFunctionType.SHA1)
            && (mgf != MessageGenerationFunctionType.SHA256)
            && (mgf != MessageGenerationFunctionType.SHA384)
            && (mgf
                    != MessageGenerationFunctionType.SHA512)) {
            throw new IllegalArgumentException(
                "Illegal value for argument\"mgf\": " + Long.toHexString(mgf));
        }
        this.mgf = mgf;
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
        sb.append("  Hash Algorithm: ").append(hashAlg.toString());

        sb.append("\n  Mask Generation Function: ");
        if (mgf == MessageGenerationFunctionType.SHA1) {
            sb.append("SHA-1");
        } else if (mgf == MessageGenerationFunctionType.SHA224) {
            sb.append("SHA-224");
        } else if (mgf == MessageGenerationFunctionType.SHA256) {
            sb.append("SHA-256");
        } else if (mgf == MessageGenerationFunctionType.SHA384) {
            sb.append("SHA-384");
        } else if (mgf == MessageGenerationFunctionType.SHA512) {
            sb.append("SHA-512");
        } else if (mgf == MessageGenerationFunctionType.SHA3_224) {
            sb.append("SHA3-224");
        } else if (mgf == MessageGenerationFunctionType.SHA3_256) {
            sb.append("SHA3-256");
        } else if (mgf == MessageGenerationFunctionType.SHA3_384) {
            sb.append("SHA3-384");
        } else if (mgf == MessageGenerationFunctionType.SHA3_512) {
            sb.append("SHA3-512");
        } else {
            sb.append("<unknown>");
        }

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
    public boolean equals(java.lang.Object otherObject) {
        if (this == otherObject) {
            return true;
        }

        if (!(otherObject instanceof RSAPkcsParameters)) {
            return false;
        }

        RSAPkcsParameters other = (RSAPkcsParameters) otherObject;
        return this.hashAlg.equals(other.hashAlg)
                && (this.mgf == other.mgf);
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
        return hashAlg.hashCode() ^ ((int) mgf);
    }

}
