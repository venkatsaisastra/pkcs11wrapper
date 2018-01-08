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

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;

/**
 * Objects of this class represent a attribute array of a PKCS#11 object
 * as specified by PKCS#11. This attribute is available since
 * cryptoki version 2.20.
 *
 *
 * @author <a href="mailto:Birgit.Haas@iaik.tugraz.at"> Birgit Haas </a>
 * @version 1.0
 * @invariants
 */
@SuppressWarnings("restriction")
public class AttributeArray extends Attribute {

    /**
     * The attributes of this attribute array in their object class
     * representation. Needed for printing and comparing this attribute array.
     */
    protected PKCS11Object template;

    /**
     * Default constructor - only for internal use.
     */
    AttributeArray() {
        super();
    }

    /**
     * Constructor taking the PKCS#11 type of the attribute.
     *
     * @param type
     *          The PKCS#11 type of this attribute; e.g.
     *          PKCS11Constants.CKA_VALUE.
     * @preconditions (type <> null)
     * @postconditions
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
     * @preconditions
     * @postconditions
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
        ckAttribute.pValue = (CK_ATTRIBUTE[])
                attributeList.toArray(new CK_ATTRIBUTE[0]);
        present = true;
    }

    /**
     * Get the attribute array value of this attribute. Null, is also possible.
     *
     * @return The attribute array value of this attribute or null.
     * @preconditions
     * @postconditions
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
        for (int i = 0; i < attributesArray.length; i++) {
            Long type = new Long(attributesArray[i].type);
            Class<?> implementation
                    = (Class<?>) Attribute.getAttributeClass(type);
            Attribute attribute;
            if (implementation == null) {
                attribute = new OtherAttribute();
                attribute.setType(type);
                attribute.setCkAttribute(attributesArray[i]);
            } else {
                try {
                    attribute = (Attribute) implementation.newInstance();
                    attribute.setCkAttribute(attributesArray[i]);
                    attribute.setPresent(true);
                    template.addAttribute(attribute);
                } catch (Exception ex) {
                    System.err.println(
                        "Error when trying to create a " + implementation
                        + " instance for " + type + ": " + ex.getMessage());
                    System.err.flush();
                    continue;
                }
            }
        }
        return template;
    }

    /**
     * Get a string representation of the value of this attribute.
     *
     * @return A string representation of the value of this attribute.
     * @preconditions
     * @postconditions (result <> null)
     */
    protected String getValueString() {
        String valueString = "";
        if (template == null) {
            template = getAttributeArrayValue();
        }

        if (template == null) {
            valueString = "<NULL_PTR>";
        } else {
            valueString += template.toString(true, true, "      ");
        }
        return valueString;
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

        if (!(otherObject instanceof AttributeArray)) {
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
        }

        if (!(this.present && other.present)) {
            return false;
        }

        if (this.sensitive != other.sensitive) {
            return false;
        }

        return this.template.equals(other.template);
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
        if (template == null) {
            template = getAttributeArrayValue();
        }
        return template.hashCode();
    }

    /**
     * Create a (deep) clone of this object.
     * The attributes in the CK_ATTRIBUTE[] need not be cloned, as they can't be
     * set separately.
     *
     * @return A clone of this object.
     * @preconditions
     * @postconditions (result <> null)
     *                 and (result instanceof AttributeArray)
     *                 and (result.equals(this))
     */
    @Override
    public Object clone() {
        AttributeArray clone;

        clone = (AttributeArray) super.clone();
        if (template == null) {
            template = getAttributeArrayValue();
        }
        if (template != null) {
            clone.template = (GenericTemplate) this.template.clone();
        }
        return clone;
    }

    @Override
    public void setValue(Object value)
        throws UnsupportedOperationException {
        setAttributeArrayValue((PKCS11Object) value);
    }

}
