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

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.Util;

/**
 * Objects of this class represent PKCS#11 objects of type storage as defined
 * in PKCSC#11 2.11, but is compatible to version 2.01.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (token <> null)
 *             and (private <> null)
 *             and (modifiable <> null)
 *             and (label <> null)
 */
public class Storage extends PKCS11Object {

  /**
   * True, if object is a token object (not a session object).
   */
  protected BooleanAttribute token;

  /**
   * True, if this is a private object.
   */
  // CHECKSTYLE:SKIP
  protected BooleanAttribute private_;

  /**
   * True, if this object is modifiable.
   */
  protected BooleanAttribute modifiable;

  /**
   * The label of this object.
   */
  protected CharArrayAttribute label;

  /**
   * The default constructor. An application use this constructor to
   * instantiate an object that serves as a template. It may also be useful
   * for working with vendor-defined objects.
   *
   * @preconditions
   * @postconditions
   */
  public Storage() {
  }

  /**
   * Constructor taking the reference to the PKCS#11 module for accessing the
   * object's attributes, the session handle to use for reading the attribute
   * values and the object handle. This constructor read all attributes that
   * a storage object must contain.
   *
   * @param session
   *          The session to use for reading attributes. This session must
   *          have the appropriate rights; i.e. it must be a user-session, if
   *          it is a private object.
   * @param objectHandle
   *          The object handle as given from the PKCS#111 module.
   * @exception TokenException
   *              If getting the attributes failed.
   * @preconditions (session <> null)
   * @postconditions
   */
  protected Storage(Session session, long objectHandle)
      throws TokenException {
    super(session, objectHandle);
  }

  /**
   * Put all attributes of the given object into the attributes table of this
   * object. This method is only static to be able to access invoke the
   * implementation of this method for each class separately.
   *
   * @param object
   *          The object to handle.
   * @preconditions (object <> null)
   * @postconditions
   */
  protected static void putAttributesInTable(Storage object) {
    Util.requireNonNull("object", object);
    object.attributeTable.put(Attribute.TOKEN, object.token);
    object.attributeTable.put(Attribute.PRIVATE, object.private_);
    object.attributeTable.put(Attribute.MODIFIABLE, object.modifiable);
    object.attributeTable.put(Attribute.LABEL, object.label);
  }

  /**
   * Allocates the attribute objects for this class and adds them to the
   * attribute table.
   *
   * @preconditions
   * @postconditions
   */
  @Override
  protected void allocateAttributes() {
    super.allocateAttributes();

    token = new BooleanAttribute(Attribute.TOKEN);
    private_ = new BooleanAttribute(Attribute.PRIVATE);
    modifiable = new BooleanAttribute(Attribute.MODIFIABLE);
    label = new CharArrayAttribute(Attribute.LABEL);

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
   * @preconditions
   * @postconditions
   */
  @Override
  public boolean equals(Object otherObject) {
    if (this == otherObject) {
      return true;
    } else if (!(otherObject instanceof Storage)) {
      return false;
    }

    Storage other = (Storage) otherObject;
    return super.equals(other)
        && this.token.equals(other.token)
        && this.private_.equals(other.private_)
        && this.modifiable.equals(other.modifiable)
        && this.label.equals(other.label);
  }

  /**
   * Check, if this is a token object.
   *
   * @return Its value is true, if this is an token object.
   * @preconditions
   * @postconditions (result <> null)
   */
  public BooleanAttribute getToken() {
    return token;
  }

  /**
   * Check, if this is a private object.
   *
   * @return Its value is true, if this is a private object.
   * @preconditions
   * @postconditions (result <> null)
   */
  public BooleanAttribute getPrivate() {
    return private_;
  }

  /**
   * Check, if this is a modifiable object.
   *
   * @return Its value is true, if this is a modifiable object.
   * @preconditions
   * @postconditions (result <> null)
   */
  public BooleanAttribute getModifiable() {
    return modifiable;
  }

  /**
   * Get the label attribute of this object.
   *
   * @return Contains the label as a char array.
   * @preconditions
   * @postconditions (result <> null)
   */
  public CharArrayAttribute getLabel() {
    return label;
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
   * @preconditions (session <> null)
   * @postconditions
   */
  @Override
  public void readAttributes(Session session) throws TokenException {
    super.readAttributes(session);

    PKCS11Object.getAttributeValues(session, objectHandle, new Attribute[] {
        token, private_, modifiable, label});
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
    String superToString = super.toString();
    return Util.concatObjectsCap(superToString.length() + 100, superToString,
        "\n  Token: ", token,
        "\n  Private: ", private_,
        "\n  Modifiable: ", modifiable,
        "\n  Label: ", label);
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
    return token.hashCode() ^ private_.hashCode() ^ modifiable.hashCode()
      ^ label.hashCode();
  }

}
