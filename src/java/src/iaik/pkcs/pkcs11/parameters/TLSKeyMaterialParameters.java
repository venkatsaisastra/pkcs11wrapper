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

/**
 * This class encapsulates parameters for the Mechanism.SSL3_KEY_AND_MAC_DERIVE
 * mechanism.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 */
// CHECKSTYLE:SKIP
public abstract class TLSKeyMaterialParameters implements Parameters {

  /**
   * The length (in bits) of the MACing keys agreed upon during the protocol
   * handshake phase.
   */
  protected long macSizeInBits;

  /**
   * The length (in bits) of the secret keys agreed upon during the protocol
   * handshake phase.
   */
  protected long keySizeInBits;

  /**
   * The length (in bits) of the IV agreed upon during the protocol handshake
   * phase. If no IV is required, the length should be set to 0.
   */
  protected long ivSizeInBits;

  /**
   * Indicates whether the keys have to be derived for an export version of
   * the protocol.
   */
  protected boolean export;

  /**
   * The client's and server's random data information.
   */
  protected SSL3RandomDataParameters randomInfo;

  /**
   * Receives the handles for the keys generated and the IVs.
   */
  protected SSL3KeyMaterialOutParameters returnedKeyMaterial;

  /**
   * Create a new SSL3KeyMaterialParameters object with the given
   * parameters.
   *
   * @param macSizeInBits
   *          The length (in bits) of the MACing keys agreed upon during the
   *          protocol handshake phase.
   * @param keySizeInBits
   *          The length (in bits) of the secret keys agreed upon during the
   *          protocol handshake phase.
   * @param ivSizeInBits
   *          The length (in bits) of the IV agreed upon during the protocol
   *          handshake phase. If no IV is required, the length should be set
   *          to 0.
   * @param export
   *          Indicates whether the keys have to be derived for an export
   *          version of the protocol.
   * @param randomInfo
   *          The client's and server's random data information.
   * @param returnedKeyMaterial
   *          Receives the handles for the keys generated and the IVs.
   */
  public TLSKeyMaterialParameters(long macSizeInBits, long keySizeInBits,
      long ivSizeInBits, boolean export, SSL3RandomDataParameters randomInfo,
      SSL3KeyMaterialOutParameters returnedKeyMaterial) {
    this.macSizeInBits = macSizeInBits;
    this.keySizeInBits = keySizeInBits;
    this.ivSizeInBits = ivSizeInBits;
    this.export = export;
    this.randomInfo = Util.requireNonNull("randomInfo", randomInfo);
    this.returnedKeyMaterial = Util.requireNonNull("returnedKeyMaterial",
        returnedKeyMaterial);
  }

  /**
   * Get the length (in bits) of the MACing keys agreed upon during the
   * protocol handshake phase.
   *
   * @return The length (in bits) of the MACing keys agreed upon during the
   *         protocol handshake phase.
   */
  public long getMacSizeInBits() {
    return macSizeInBits;
  }

  /**
   * Get the length (in bits) of the secret keys agreed upon during the
   * protocol handshake phase.
   *
   * @return The length (in bits) of the secret keys agreed upon during the
   *         protocol handshake phase.
   */
  public long getKeySizeInBits() {
    return keySizeInBits;
  }

  /**
   * Get the length (in bits) of the IV agreed upon during the protocol
   * handshake phase. If no IV is required, the length should be set to 0
   *
   * @return The length (in bits) of the IV agreed upon during the protocol
   *         handshake phase. If no IV is required, the length should be set
   *         to 0.
   */
  // CHECKSTYLE:SKIP
  public long getIVSizeInBits() {
    return ivSizeInBits;
  }

  /**
   * Check whether the keys have to be derived for an export version of the
   * protocol.
   *
   * @return True, if the keys have to be derived for an export version of the
   *         protocol; false, otherwise.
   */
  public boolean isExport() {
    return export;
  }

  /**
   * Get the client's and server's random data information.
   *
   * @return The client's and server's random data information.
   */
  public SSL3RandomDataParameters getRandomInfo() {
    return randomInfo;
  }

  /**
   * Get the object that receives the handles for the keys generated and the
   * IVs.
   *
   * @return The object that receives the handles for the keys generated and
   *         the IVs.
   */
  public SSL3KeyMaterialOutParameters getReturnedKeyMaterial() {
    return returnedKeyMaterial;
  }

  /**
   * Set the length (in bits) of the MACing keys agreed upon during the
   * protocol handshake phase.
   *
   * @param macSizeInBits
   *          The length (in bits) of the MACing keys agreed upon during the
   *          protocol handshake phase.
   */
  public void setMacSizeInBits(long macSizeInBits) {
    this.macSizeInBits = macSizeInBits;
  }

  /**
   * Set the length (in bits) of the secret keys agreed upon during the
   * protocol handshake phase.
   *
   * @param keySizeInBits
   *          The length (in bits) of the secret keys agreed upon during the
   *          protocol handshake phase.
   */
  public void setKeySizeInBits(long keySizeInBits) {
    this.keySizeInBits = keySizeInBits;
  }

  /**
   * Set the length (in bits) of the IV agreed upon during the protocol
   * handshake phase. If no IV is required, the length should be set to 0.
   *
   * @param ivSizeInBits
   *          The length (in bits) of the IV agreed upon during the protocol
   *          handshake phase. If no IV is required, the length should be set
   *          to 0.
   */
  // CHECKSTYLE:SKIP
  public void setIVSizeInBits(long ivSizeInBits) {
    this.ivSizeInBits = ivSizeInBits;
  }

  /**
   * Set whether the keys have to be derived for an export version of the
   * protocol.
   *
   * @param export
   *          True, if the keys have to be derived for an export version of
   *          the protocol; false, otherwise.
   */
  public void setExport(boolean export) {
    this.export = export;
  }

  /**
   * Set the client's and server's random data information.
   *
   * @param randomInfo
   *          The client's and server's random data information.
   */
  public void setRandomInfo(SSL3RandomDataParameters randomInfo) {
    this.randomInfo = Util.requireNonNull("randomInfo", randomInfo);
  }

  /**
   * Set the object that receives the handles for the keys generated and the
   * IVs.
   *
   * @param returnedKeyMaterial
   *          The object that receives the handles for the keys generated and
   *          the IVs.
   */
  public void setReturnedKeyMaterial(
      SSL3KeyMaterialOutParameters returnedKeyMaterial) {
    this.returnedKeyMaterial = Util.requireNonNull("returnedKeyMaterial",
        returnedKeyMaterial);
  }

  /**
   * Returns the string representation of this object. Do not parse data from
   * this string, it is for debugging only.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    return Util.concatObjects("  MAC Size in Bits (dec): ", macSizeInBits,
        "\n  Key Size in Bits (dec): ", keySizeInBits,
        "\n  IV Size in Bits (dec): ", ivSizeInBits,
        "\n  For Export Version: ", export,
        "\n  Client's and Server'S Random Information (hex):\n", randomInfo,
        "\n  Handles of the generated Keys and IVs: ", returnedKeyMaterial);
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
    } else if (!(otherObject instanceof TLSKeyMaterialParameters)) {
      return false;
    }

    TLSKeyMaterialParameters other = (TLSKeyMaterialParameters) otherObject;
    return (this.macSizeInBits == other.macSizeInBits)
        && (this.keySizeInBits == other.keySizeInBits)
        && (this.ivSizeInBits == other.ivSizeInBits)
        && (this.export == other.export)
        && this.randomInfo.equals(other.randomInfo)
        && this.returnedKeyMaterial.equals(other.returnedKeyMaterial);
  }

  /**
   * The overriding of this method should ensure that the objects of this
   * class work correctly in a hashtable.
   *
   * @return The hash code of this object.
   */
  @Override
  public int hashCode() {
    return ((int) macSizeInBits) ^ ((int) keySizeInBits)
      ^ ((int) ivSizeInBits) ^ randomInfo.hashCode()
      ^ returnedKeyMaterial.hashCode();
  }

}
