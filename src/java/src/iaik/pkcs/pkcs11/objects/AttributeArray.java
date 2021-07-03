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

import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * Objects of this class represent a attribute array of a PKCS#11 object
 * as specified by PKCS#11. This attribute is available since
 * cryptoki version 2.20.
 *
 *
 * @author Birgit Haas
 * @version 1.0
 */
public class AttributeArray extends Attribute {

  /**
   * The attributes of this attribute array in their object class
   * representation. Needed for printing and comparing this attribute array.
   */
  protected PKCS11Object template;

  /**
   * Constructor taking the PKCS#11 type of the attribute.
   *
   * @param type
   *          The PKCS#11 type of this attribute; e.g.
   *          PKCS11Constants.CKA_VALUE.
   */
  public AttributeArray(Long type) {
    super(type);
  }

  /**
   * Set the attributes of this attribute array by specifying a
   * GenericTemplate. Null, is also valid.
   * A call to this method sets the present flag to true.
   *
   * @param value
   *          The AttributeArray value to set. May be null.
   */
  public void setAttributeArrayValue(PKCS11Object value) {
    template = value;

    List<CK_ATTRIBUTE> attributeList = new ArrayList<>();
    Enumeration<Attribute> attributeEnumeration
        = template.attributeTable.elements();
    while (attributeEnumeration.hasMoreElements()) {
      Attribute attribute = attributeEnumeration.nextElement();
      if (attribute.present) {
        attributeList.add(attribute.getCkAttribute());
      }
    }
    ckAttribute.pValue = attributeList.toArray(new CK_ATTRIBUTE[0]);
    present = true;
  }

  /**
   * Get the attribute array value of this attribute. Null, is also possible.
   *
   * @return The attribute array value of this attribute or null.
   */
  public PKCS11Object getAttributeArrayValue() {
    if (template != null) {
      return template;
    }

    if (!(ckAttribute.pValue != null
        && ((CK_ATTRIBUTE[]) ckAttribute.pValue).length > 0)) {
      return null;
    }

    CK_ATTRIBUTE[] attributesArray = (CK_ATTRIBUTE[]) ckAttribute.pValue;
    GenericTemplate template = new GenericTemplate();
    for (CK_ATTRIBUTE ck_attribute : attributesArray) {
      Long type = ck_attribute.type;
      Class<?> implementation = Attribute.getAttributeClass(type);
      Attribute attribute;
      if (implementation == null) {
        attribute = new OtherAttribute();
        attribute.setType(type);
        attribute.setCkAttribute(ck_attribute);
      } else {
        try {
          attribute = (Attribute)
                  implementation.getDeclaredConstructor(Attribute.class)
                          .newInstance();
          attribute.setCkAttribute(ck_attribute);
          attribute.setPresent(true);
          template.addAttribute(attribute);
        } catch (Exception ex) {
          System.err.println("Error when trying to create a "
                  + implementation + " instance for " + type
                  + ": " + ex.getMessage());
        }
      }
    }
    return template;
  }

  /**
   * Get a string representation of the value of this attribute.
   *
   * @return A string representation of the value of this attribute.
   */
  protected String getValueString() {
    if (template == null) {
      template = getAttributeArrayValue();
    }

    return (template == null)
      ? "<NULL_PTR>"
      : template.toString(true, true, "      ");
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
    } else if (!(otherObject instanceof AttributeArray)) {
      return false;
    }

    AttributeArray other = (AttributeArray) otherObject;

    if (this.template == null) {
      this.template = this.getAttributeArrayValue();
    }

    if (other.template == null) {
      other.template = other.getAttributeArrayValue();
    }

    if (!this.present && !other.present) {
      return true;
    } else if (!(this.present && other.present)) {
      return false;
    } else if (this.sensitive != other.sensitive) {
      return false;
    }

    return this.template.equals(other.template);
  }

  /**
   * The overriding of this method should ensure that the objects of this
   * class work correctly in a hashtable.
   *
   * @return The hash code of this object.
   */
  @Override
  public int hashCode() {
    if (template == null) {
      template = getAttributeArrayValue();
    }
    return template.hashCode();
  }

  @Override
  public void setValue(Object value) throws UnsupportedOperationException {
    setAttributeArrayValue((PKCS11Object) value);
  }

}
