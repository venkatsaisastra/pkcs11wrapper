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
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY  WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package iaik.pkcs.pkcs11.params;

import iaik.pkcs.pkcs11.Mechanism;
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
abstract public class RSAPkcsParams implements Params {

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
  protected RSAPkcsParams(Mechanism hashAlg, long mgf) {
    if ((mgf != PKCS11Constants.CKG_MGF1_SHA1)
        && (mgf != PKCS11Constants.CKG_MGF1_SHA224)
        && (mgf != PKCS11Constants.CKG_MGF1_SHA256)
        && (mgf != PKCS11Constants.CKG_MGF1_SHA384)
        && (mgf != PKCS11Constants.CKG_MGF1_SHA512)
        && (mgf != PKCS11Constants.CKG_MGF1_SHA3_224)
        && (mgf != PKCS11Constants.CKG_MGF1_SHA3_256)
        && (mgf != PKCS11Constants.CKG_MGF1_SHA3_384)
        && (mgf != PKCS11Constants.CKG_MGF1_SHA3_512)) {
      throw new IllegalArgumentException(
        "Illegal value for argument\"mgf\": " + Long.toHexString(mgf));
    }
    this.hashAlg = Util.requireNonNull("hashAlg", hashAlg);
    this.mgf = mgf;
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
   * @postconditions
   */
  public void setMaskGenerationFunction(long mgf) {
    if ((mgf != PKCS11Constants.CKG_MGF1_SHA1)
        && (mgf != PKCS11Constants.CKG_MGF1_SHA256)
        && (mgf != PKCS11Constants.CKG_MGF1_SHA384)
        && (mgf != PKCS11Constants.CKG_MGF1_SHA512)
        && (mgf != PKCS11Constants.CKG_MGF1_SHA3_224)
        && (mgf != PKCS11Constants.CKG_MGF1_SHA3_256)
        && (mgf != PKCS11Constants.CKG_MGF1_SHA3_384)
        && (mgf != PKCS11Constants.CKG_MGF1_SHA3_512)) {
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
    String mgfStr;
    if (mgf == PKCS11Constants.CKG_MGF1_SHA1) {
      mgfStr = "SHA-1";
    } else if (mgf == PKCS11Constants.CKG_MGF1_SHA224) {
      mgfStr = "SHA-224";
    } else if (mgf == PKCS11Constants.CKG_MGF1_SHA256) {
      mgfStr = "SHA-256";
    } else if (mgf == PKCS11Constants.CKG_MGF1_SHA384) {
      mgfStr = "SHA-384";
    } else if (mgf == PKCS11Constants.CKG_MGF1_SHA512) {
      mgfStr = "SHA-512";
    } else if (mgf == PKCS11Constants.CKG_MGF1_SHA3_224) {
      mgfStr = "SHA3-224";
    } else if (mgf == PKCS11Constants.CKG_MGF1_SHA3_256) {
      mgfStr = "SHA3-256";
    } else if (mgf == PKCS11Constants.CKG_MGF1_SHA3_384) {
      mgfStr = "SHA3-384";
    } else if (mgf == PKCS11Constants.CKG_MGF1_SHA3_512) {
      mgfStr = "SHA3-512";
    } else {
      mgfStr = "<unknown>";
    }

    return Util.concat("  Hash Algorithm: ", hashAlg.toString(),
        "\n  Mask Generation Function: ", mgfStr);
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
    } else if (!(otherObject instanceof RSAPkcsParams)) {
      return false;
    }

    RSAPkcsParams other = (RSAPkcsParams) otherObject;
    return this.hashAlg.equals(other.hashAlg) && (this.mgf == other.mgf);
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
