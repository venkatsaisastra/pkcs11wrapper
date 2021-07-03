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

import iaik.pkcs.pkcs11.Util;
import sun.security.pkcs11.wrapper.CK_PBE_PARAMS;

import java.util.Arrays;

/**
 * This class encapsulates parameters for the Mechanism.PBA_* and
 * Mechanism.PBA_SHA1_WITH_SHA1_HMAC mechanisms.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 */
// CHECKSTYLE:SKIP
public class PBEParameters implements Parameters {

  /**
   * The 8-byte initialization vector (IV), if an IV is required.
   */
  protected char[] iv;

  /**
   * The password to be used in the PBE key generation.
   */
  protected char[] password;

  /**
   * The salt to be used in the PBE key generation.
   */
  protected char[] salt;

  /**
   * The number of iterations required for the generation.
   */
  protected long iterations;

  /**
   * Create a new PBEDeriveParameters object with the given attributes.
   *
   * @param iv
   *          The 8-byte initialization vector (IV), if an IV is required.
   * @param password
   *          The password to be used in the PBE key generation.
   * @param salt
   *          The salt to be used in the PBE key generation.
   * @param iterations
   *          The number of iterations required for the generation.
   */
  public PBEParameters(char[] iv, char[] password, char[] salt,
      long iterations) {
    if ((iv != null) && (iv.length != 8)) {
      throw new IllegalArgumentException(
        "Argument \"iv\" must be null or must have"
        + " length 8, if it is not null.");
    }
    this.iv = iv;
    this.password = Util.requireNonNull("password", password);
    this.salt = Util.requireNonNull("salt", salt);
    this.iterations = iterations;
  }

  /**
   * Get this parameters object as an object of the CK_PBE_PARAMS class.
   *
   * @return This object as a CK_PBE_PARAMS object.
   */
  @Override
  public CK_PBE_PARAMS getPKCS11ParamsObject() {
    CK_PBE_PARAMS params = new CK_PBE_PARAMS();

    params.pInitVector = iv;
    params.pPassword = password;
    params.pSalt = salt;
    params.ulIteration = iterations;

    return params;
  }

  /**
   * Get the 8-byte initialization vector (IV), if an IV is required.
   *
   * @return The 8-byte initialization vector (IV), if an IV is required.
   */
  public char[] getInitializationVector() {
    return iv;
  }

  /**
   * Get the password to be used in the PBE key generation.
   *
   * @return The password to be used in the PBE key generation.
   */
  public char[] getPassword() {
    return password;
  }

  /**
   * Get the salt to be used in the PBE key generation.
   *
   * @return The salt to be used in the PBE key generation.
   */
  public char[] getSalt() {
    return salt;
  }

  /**
   * Get the number of iterations required for the generation.
   *
   * @return The number of iterations required for the generation.
   */
  public long getIterations() {
    return iterations;
  }

  /**
   * Set the 8-byte initialization vector (IV), if an IV is required.
   *
   * @param iv
   *          The 8-byte initialization vector (IV), if an IV is required.
   */
  public void setInitializationVector(char[] iv) {
    if ((iv != null) && (iv.length != 8)) {
      throw new IllegalArgumentException("Argument \"iv\" must be null"
          + " or must have length 8, if it is not null.");
    }
    this.iv = iv;
  }

  /**
   * Set the password to be used in the PBE key generation.
   *
   * @param password
   *          The password to be used in the PBE key generation.
   */
  public void setPassword(char[] password) {
    this.password = Util.requireNonNull("password", password);
  }

  /**
   * Set the salt to be used in the PBE key generation.
   *
   * @param salt
   *          The salt to be used in the PBE key generation.
   */
  public void setSalt(char[] salt) {
    this.salt = Util.requireNonNull("salt", salt);
  }

  /**
   * Set the number of iterations required for the generation.
   *
   * @param iterations
   *          The number of iterations required for the generation.
   */
  public void setIterations(long iterations) {
    this.iterations = iterations;
  }

  /**
   * Returns the string representation of this object. Do not parse data from
   * this string, it is for debugging only.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    return Util.concatObjects("  IV: ", ((iv != null) ? new String(iv) : null),
        "\n  Password: ", ((password != null) ? new String(password) : null),
        "\n  Salt: ", ((salt != null) ? new String(salt) : null),
        "\n  Iterations (dec): ", iterations);
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
    } else if (!(otherObject instanceof PBEParameters)) {
      return false;
    }

    PBEParameters other = (PBEParameters) otherObject;
    return Arrays.equals(this.iv, other.iv)
         && Arrays.equals(this.password, other.password)
         && Arrays.equals(this.salt, other.salt)
         && (this.iterations == other.iterations);
  }

  /**
   * The overriding of this method should ensure that the objects of this
   * class work correctly in a hashtable.
   *
   * @return The hash code of this object.
   */
  @Override
  public int hashCode() {
    return Util.hashCode(iv) ^ Util.hashCode(password)
        ^ Util.hashCode(salt) ^ ((int) iterations);
  }

}
