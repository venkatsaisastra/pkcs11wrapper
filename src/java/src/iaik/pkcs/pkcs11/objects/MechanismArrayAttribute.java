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

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Util;

import java.util.Arrays;

/**
 * Objects of this class represent a mechanism array attribute of a PKCS#11
 * object as specified by PKCS#11. This attribute is available since
 * cryptoki version 2.20.
 *
 * @author Birgit Haas
 * @version 1.0
 */
public class MechanismArrayAttribute extends Attribute {

  /**
   * Constructor taking the PKCS#11 type of the attribute.
   *
   * @param type
   *          The PKCS#11 type of this attribute; e.g.
   *          PKCS11Constants.CKA_VALUE.
   */
  public MechanismArrayAttribute(Long type) {
    super(type);
  }

  /**
   * Set the attributes of this mechanism attribute array by specifying a
   * Mechanism[]. Null, is also valid.
   * A call to this method sets the present flag to true.
   *
   * @param value
   *          The MechanismArrayAttribute value to set. May be null.
   */
  public void setMechanismAttributeArrayValue(Mechanism[] value) {

    long[] values = null;
    if (value != null) {
      values = new long[value.length];
      for (int i = 0; i < value.length; i++) {
        values[i] = value[i].getMechanismCode();
      }
    }
    ckAttribute.pValue = values;
    present = true;
  }

  /**
   * Get the mechanism attribute array value of this attribute as Mechanism[].
   * Null, is also possible.
   *
   * @return The mechanism attribute array value of this attribute or null.
   */
  public Mechanism[] getMechanismAttributeArrayValue() {
    Mechanism[] mechanisms = null;
    if (ckAttribute.pValue != null) {
      long[] values = (long[]) ckAttribute.pValue;
      if (values.length > 0) {
        mechanisms = new Mechanism[values.length];
        for (int i = 0; i < values.length; i++) {
          mechanisms[i] = new Mechanism(values[i]);
        }
      }
    }
    return mechanisms;
  }

  /**
   * Get a string representation of the value of this attribute.
   *
   * @return A string representation of the value of this attribute.
   */
  @Override
  protected String getValueString() {
    StringBuilder sb = new StringBuilder(1024);
    Mechanism[] allowedMechanisms = getMechanismAttributeArrayValue();
    if (allowedMechanisms != null && allowedMechanisms.length > 0) {
      for (Mechanism allowedMechanism : allowedMechanisms) {
        sb.append("\n      ").append(allowedMechanism.getName());
      }
      return sb.toString();
    } else {
      return "<NULL_PTR>";
    }
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
    } else if (!(otherObject instanceof MechanismArrayAttribute)) {
      return false;
    }

    MechanismArrayAttribute other = (MechanismArrayAttribute) otherObject;
    if (!this.present && !other.present) {
      return true;
    } else if (!(this.present && other.present)) {
      return false;
    } else if (this.sensitive != other.sensitive) {
      return false;
    }

    return Arrays.equals((long[]) this.ckAttribute.pValue,
        (long[]) other.ckAttribute.pValue);
  }

  /**
   * The overriding of this method should ensure that the objects of this
   * class work correctly in a hashtable.
   *
   * @return The hash code of this object.
   */
  @Override
  public int hashCode() {
    return (ckAttribute.pValue != null)
        ? Util.hashCode((long[]) ckAttribute.pValue) : 0;
  }

  @Override
  public void setValue(Object value) {
    setMechanismAttributeArrayValue((Mechanism[]) value);
  }

}
