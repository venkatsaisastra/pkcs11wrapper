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

package iaik.pkcs.pkcs11.objects;

import iaik.pkcs.pkcs11.Util;

/**
 * This class does not correspond to any PKCS#11 object. It is only a pair of
 * a private key and a public key.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (publicKey <> null)
 *             and (privateKey <> null)
 */
public class KeyPair implements Cloneable {

  /**
   * The public key of this key-pair.
   */
  private PublicKey publicKey;

  /**
   * The private key of this key-pair.
   */
  private PrivateKey privateKey;

  /**
   * Constructor that takes a public and a private key. None can be null.
   *
   * @param publicKey
   *          The public key of the key-pair.
   * @param privateKey
   *          The private key of the key-pair.
   * @preconditions (publicKey <> null)
   *                and (privateKey <> null)
   * @postconditions
   */
  public KeyPair(PublicKey publicKey, PrivateKey privateKey) {
    this.publicKey = Util.requireNonNull("publicKey", publicKey);
    this.privateKey = Util.requireNonNull("privateKey", privateKey);
  }

  /**
   * Get the public key part of this key-pair.
   *
   * @return The public key part of this key-pair.
   * @preconditions
   * @postconditions (result <> null)
   */
  public PublicKey getPublicKey() {
    return publicKey;
  }

  /**
   * Set the public key part of this key-pair.
   *
   * @param publicKey
   *          The public key part of this key-pair.
   * @preconditions (publicKey <> null)
   * @postconditions
   */
  public void setPublicKey(PublicKey publicKey) {
    this.publicKey = Util.requireNonNull("publicKey", publicKey);
  }

  /**
   * Get the private key part of this key-pair.
   *
   * @return The private key part of this key-pair.
   * @preconditions
   * @postconditions (result <> null)
   */
  public PrivateKey getPrivateKey() {
    return privateKey;
  }

  /**
   * Set the private key part of this key-pair.
   *
   * @param privateKey
   *          he private key part of this key-pair.
   * @preconditions (privateKey <> null)
   * @postconditions
   */
  public void setPrivateKey(PrivateKey privateKey) {
    this.privateKey = Util.requireNonNull("privateKey", privateKey);
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
    StringBuilder sb = new StringBuilder(128);
    sb.append("  ").append(publicKey);
    sb.append("\n   ").append(privateKey);
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

    if (!(otherObject instanceof KeyPair)) {
      return false;
    }

    KeyPair other = (KeyPair) otherObject;
    return this.publicKey.equals(other.publicKey)
        && this.privateKey.equals(other.privateKey);
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
    return publicKey.hashCode() ^ privateKey.hashCode();
  }

}
