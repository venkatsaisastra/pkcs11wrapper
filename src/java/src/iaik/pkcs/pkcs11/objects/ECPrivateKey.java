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

import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.Util;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * Objects of this class represent ECDSA private keys as specified by PKCS#11
 * v2.11.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 *
 */
// CHECKSTYLE:SKIP
public class ECPrivateKey extends PrivateKey {

  /**
   * The DER-encoding of an X9.62 ECParameters value of this ECDSA key.
   */
  protected ByteArrayAttribute ecdsaParams;

  /**
   * The X9.62 private value (d) of this ECDSA key.
   */
  protected ByteArrayAttribute value;

  /**
   * Default Constructor.
   */
  public ECPrivateKey() {
    this(KeyType.EC);
  }

  /**
   * Default Constructor with the specification of keyType
   *
   * @param keyType
   *        key type
   */
  public ECPrivateKey(long keyType) {
    this.keyType.setLongValue(keyType);
  }

  public static ECPrivateKey newSM2PrivateKey(Module module) {
    long keyType = PKCS11Constants.CKK_VENDOR_SM2;
    if (module.getVendorCodeConverter() != null) {
      keyType = module.getVendorCodeConverter().genericToVendorCKK(keyType);
    }
    return new ECPrivateKey(keyType);
  }

  /**
   * Called by getInstance to create an instance of a PKCS#11 ECDSA private
   * key.
   *
   * @param session
   *          The session to use for reading attributes. This session must
   *          have the appropriate rights; i.e. it must be a user-session, if
   *          it is a private object.
   * @param objectHandle
   *          The object handle as given from the PKCS#111 module.
   * @exception TokenException
   *              If getting the attributes failed.
   */
  protected ECPrivateKey(Session session, long objectHandle)
      throws TokenException {
    super(session, objectHandle);
  }

  /**
   * The getInstance method of the PrivateKey class uses this method to create
   * an instance of a PKCS#11 ECDSA private key.
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
   */
  public static PKCS11Object getInstance(Session session, long objectHandle)
      throws TokenException {
    return new ECPrivateKey(session, objectHandle);
  }

  /**
   * Put all attributes of the given object into the attributes table of this
   * object. This method is only static to be able to access invoke the
   * implementation of this method for each class separately.
   *
   * @param object
   *          The object to handle.
   */
  protected static void putAttributesInTable(ECPrivateKey object) {
    Util.requireNonNull("object", object);
    object.attributeTable.put(Attribute.KEY_TYPE, object.keyType);
    object.attributeTable.put(Attribute.EC_PARAMS, object.ecdsaParams);
    object.attributeTable.put(Attribute.VALUE, object.value);
  }

  /**
   * Allocates the attribute objects for this class and adds them to the
   * attribute table.
   */
  @Override
  protected void allocateAttributes() {
    super.allocateAttributes();

    ecdsaParams = new ByteArrayAttribute(Attribute.EC_PARAMS);
    value = new ByteArrayAttribute(Attribute.VALUE);

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
   */
  @Override
  public boolean equals(Object otherObject) {
    if (this == otherObject) {
      return true;
    } else if (!(otherObject instanceof ECPrivateKey)) {
      return false;
    }

    ECPrivateKey other = (ECPrivateKey) otherObject;
    return super.equals(other)
        && this.ecdsaParams.equals(other.ecdsaParams)
        && this.value.equals(other.value);
  }

  /**
   * Gets the ECDSA parameters attribute of this ECDSA key.
   *
   * @return The ECDSA parameters attribute.
   */
  public ByteArrayAttribute getEcdsaParams() {
    return ecdsaParams;
  }

  /**
   * Gets the value attribute of this ECDSA key.
   *
   * @return The value attribute.
   */
  public ByteArrayAttribute getValue() {
    return value;
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
   */
  @Override
  public void readAttributes(Session session) throws TokenException {
    super.readAttributes(session);

    PKCS11Object.getAttributeValues(session, objectHandle, new Attribute[] {
        ecdsaParams, value });
  }

  /**
   * Returns a string representation of the current object. The
   * output is only for debugging purposes and should not be used for other
   * purposes.
   *
   * @return A string presentation of this object for debugging output.
   */
  @Override
  public String toString() {
    String superToString = super.toString();
    return Util.concatObjectsCap(superToString.length() + 100, superToString,
        "\n  ECDSA Params (DER, hex): ", ecdsaParams,
        "\n  Private Value d (hex): ", value);
  }

}
