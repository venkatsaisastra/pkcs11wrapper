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

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.UnsupportedAttributeException;
import iaik.pkcs.pkcs11.Util;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.PKCS11;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

/**
 * An object of this class represents an object as defined by PKCS#11.
 * An object is of a specific class: DATA, CERTIFICATE, PUBLIC_KEY, PRIVATE_KEY,
 * SECRET_KEY, HW_FEATURE, DOMAIN_PARAMETERS or VENDOR_DEFINED.
 * If an application needs to use vendor-defined objects, it must set a
 * VendorDefinedObjectBuilder using the setVendorDefinedObjectBuilder method.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 */
// CHECKSTYLE:SKIP
public class PKCS11Object {

  /**
   * This interface defines the available object classes as defined by
   * PKCS#11:
   * DATA, CERTIFICATE, PUBLIC_KEY, PRIVATE_KEY, SECRET_KEY, HW_FEATURE,
   * DOMAIN_PARAMETERS or VENDOR_DEFINED.
   *
   * @author Karl Scheibelhofer
   * @version 1.0
   */
  public interface ObjectClass {

    /**
     * The identifier for a data object or any sub-class of it.
     */
    public static final Long DATA = Long.valueOf(PKCS11Constants.CKO_DATA);

    /**
     * The identifier for a certificate object or any sub-class of it.
     */
    public static final Long CERTIFICATE =
        Long.valueOf(PKCS11Constants.CKO_CERTIFICATE);

    /**
     * The identifier for a public key object or any sub-class of it.
     */
    public static final Long PUBLIC_KEY =
        Long.valueOf(PKCS11Constants.CKO_PUBLIC_KEY);

    /**
     * The identifier for a private key object or any sub-class of it.
     */
    public static final Long PRIVATE_KEY =
        Long.valueOf(PKCS11Constants.CKO_PRIVATE_KEY);

    /**
     * The identifier for a secret key object or any sub-class of it.
     */
    public static final Long SECRET_KEY =
        Long.valueOf(PKCS11Constants.CKO_SECRET_KEY);

    /**
     * The identifier for a hardware feature object or any sub-class of it.
     */
    public static final Long HW_FEATURE =
        Long.valueOf(PKCS11Constants.CKO_HW_FEATURE);

    /**
     * The identifier for a domain parameters object or any sub-class of it.
     */
    public static final Long DOMAIN_PARAMETERS =
        Long.valueOf(PKCS11Constants.CKO_DOMAIN_PARAMETERS);

    /**
     * The identifier for a mechanism object or any sub-class of it.
     */
    public static final Long MECHANISM =
        Long.valueOf(PKCS11Constants.CKO_MECHANISM);

    /**
     * The identifier for a vendor-defined object. Any Long object with a
     * value bigger than this one is also a valid vendor-defined object
     * class identifier.
     */
    public static final Long VENDOR_DEFINED =
        Long.valueOf(PKCS11Constants.CKO_VENDOR_DEFINED);

  }

  /**
   * If an application uses vendor defined objects, it must implement this
   * interface and install such an object handler using
   * setVendorDefinedObjectBuilder.
   *
   * @author Karl Scheibelhofer
   * @version 1.0
   */
  public interface VendorDefinedObjectBuilder {

    /**
     * This method should instantiate an PKCS11Object of this class or of
     * any sub-class. It can use the given handles and PKCS#11 module to
     * retrieve attributes of the PKCS#11 object from the token.
     *
     * @param session
     *          The session to use for reading attributes. This session must
     *          have the appropriate rights; i.e. it must be a user-session,
     *          if it is a private object.
     * @param objectHandle
     *          The object handle as given from the PKCS#111 module.
     * @return The object representing the PKCS#11 object.
     *         The returned object can be casted to the
     *         according sub-class.
     * @exception PKCS11Exception
     *              If getting the attributes failed.
     */
    public PKCS11Object build(Session session, long objectHandle)
        throws PKCS11Exception;

  }

  /**
   * The currently set vendor defined object builder, or null.
   */
  protected static VendorDefinedObjectBuilder vendorObjectBuilder;

  /**
   * A table holding string representations for all known key types. Table key
   * is the key type as Long object.
   */
  protected static Hashtable<Long, String> objectClassNames;

  /**
   * Contains all attribute objects an object possesses. No matter if an
   * attribute is set present or not, it is part of this collection.
   * The key of this table is the attribute type as Long.
   */
  protected Hashtable<Long, Attribute> attributeTable;

  /**
   * The class type of this object. One of ObjectClass, or one that has a
   * bigger value than VENDOR_DEFINED.
   */
  protected ObjectClassAttribute objectClass;

  /**
   * The object handle as given from the PKCS#11 driver.
   */
  protected long objectHandle = -1;

  /**
   * The default constructor. An application use this constructor to
   * instantiate an object that serves as a template. It may also be useful
   * for working with vendor-defined objects.
   */
  public PKCS11Object() {
    attributeTable = new Hashtable<>(32);
    allocateAttributes();
  }

  /**
   * The subclasses that are used to create objects by reading the attributes
   * from the token should call this super-constructor first.
   * The getInstance method also uses this constructor, if it can not
   * determine the class type of the object or if the type class is a vendor
   * defined one.
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
  protected PKCS11Object(Session session, long objectHandle)
      throws TokenException {
    this.attributeTable = new Hashtable<>(32);
    allocateAttributes();
    this.objectHandle = objectHandle;
    readAttributes(session);
  }

  /**
   * The object creation mechanism of ObjectAccess uses this method to create
   * an instance of an PKCS#11 object. This method reads the object class
   * attribute and calls the getInstance method of the according sub-class. If
   * the object class is a vendor defined it uses the
   * VendorDefinedObjectBuilder set by the application. If no object could be
   * constructed, Returns null.
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
    Util.requireNonNull("session", session);

    ObjectClassAttribute objectClassAttribute = new ObjectClassAttribute();
    getAttributeValue(session, objectHandle, objectClassAttribute);

    Long objectClass = objectClassAttribute.getLongValue();

    PKCS11Object newObject;

    if (objectClassAttribute.isPresent() && (objectClass != null)) {
      if (objectClass.equals(ObjectClass.PRIVATE_KEY)) {
        newObject = PrivateKey.getInstance(session, objectHandle);
      } else if (objectClass.equals(ObjectClass.PUBLIC_KEY)) {
        newObject = PublicKey.getInstance(session, objectHandle);
      } else if (objectClass.equals(ObjectClass.CERTIFICATE)) {
        newObject = Certificate.getInstance(session, objectHandle);
      } else if (objectClass.equals(ObjectClass.SECRET_KEY)) {
        newObject = SecretKey.getInstance(session, objectHandle);
      } else if (objectClass.equals(ObjectClass.DATA)) {
        newObject = Data.getInstance(session, objectHandle);
      } else if (objectClass.equals(ObjectClass.DOMAIN_PARAMETERS)) {
        newObject = DomainParameters.getInstance(session, objectHandle);
      } else if (objectClass.equals(ObjectClass.MECHANISM)) {
        newObject = Mechanism.getInstance(session, objectHandle);
      } else if (objectClass.equals(ObjectClass.HW_FEATURE)) {
        newObject = HardwareFeature.getInstance(session, objectHandle);
      } else if ((objectClass.longValue()
              & ObjectClass.VENDOR_DEFINED.longValue()) != 0L) {
        newObject = getUnknownObject(session, objectHandle);
      } else {
        newObject = getUnknownObject(session, objectHandle);
      }
    } else {
      newObject = getUnknownObject(session, objectHandle);
    }

    return newObject;
  }

  /**
   * Try to create an object which has no or an unknown object class
   * attribute. This implementation will try to use a vendor defined object
   * builder, if such has been set. If this is impossible or fails, it will
   * create just a simple
   * {@link iaik.pkcs.pkcs11.objects.PKCS11Object PKCS11Object }.
   *
   * @param session
   *          The session to use.
   * @param objectHandle
   *          The handle of the object
   * @return A new PKCS11Object.
   * @throws TokenException
   *           If no object could be created.
   */
  protected static PKCS11Object getUnknownObject(Session session,
      long objectHandle) throws TokenException {
    Util.requireNonNull("session", session);

    PKCS11Object newObject;
    if (vendorObjectBuilder != null) {
      try {
        newObject = vendorObjectBuilder.build(session, objectHandle);
      } catch (PKCS11Exception ex) {
        // we can just treat it like some unknown type of object
        newObject = new PKCS11Object(session, objectHandle);
      }
    } else {
      // we can just treat it like some unknown type of object
      newObject = new PKCS11Object(session, objectHandle);
    }

    return newObject;
  }

  /**
   * Set a vendor-defined object builder that should be called to create an
   * instance of an vendor-defined PKCS#11 object; i.e. an instance of a
   * vendor defined sub-class of this class.
   *
   * @param builder
   *          The vendor-defined object builder. Null to clear any previously
   *          installed vendor-defined builder.
   */
  public static void setVendorDefinedObjectBuilder(
      VendorDefinedObjectBuilder builder) {
    vendorObjectBuilder = builder;
  }

  /**
   * Get the given object class as string.
   *
   * @param objectClass
   *          The object class to get as string.
   * @return A string denoting the object class; e.g. "Private Key".
   */
  public static String getObjectClassName(Long objectClass) {
    Util.requireNonNull("objectClass", objectClass);

    String objectClassName;
    if ((objectClass.longValue()
        & PKCS11Constants.CKO_VENDOR_DEFINED) != 0L) {
      objectClassName = "Vendor Defined";
    } else {
      if (objectClassNames == null) {
        // setup object class names table
        objectClassNames = new Hashtable<>(7);
        objectClassNames.put(ObjectClass.DATA, "Data");
        objectClassNames.put(ObjectClass.CERTIFICATE, "Certificate");
        objectClassNames.put(ObjectClass.PUBLIC_KEY, "Public Key");
        objectClassNames.put(ObjectClass.PRIVATE_KEY, "Private Key");
        objectClassNames.put(ObjectClass.SECRET_KEY, "Secret Key");
        objectClassNames.put(ObjectClass.HW_FEATURE,
            "Hardware Feature");
        objectClassNames.put(ObjectClass.DOMAIN_PARAMETERS,
            "Domain Parameters");
      }

      objectClassName = (String) objectClassNames.get(objectClass);
      if (objectClassName == null) {
        objectClassName = "<unknown>";
      }
    }

    return objectClassName;
  }

  /**
   * Get the currently set vendor-defined object builder.
   *
   * @return The currently set vendor-defined object builder or null if none
   *         is set.
   */
  public static VendorDefinedObjectBuilder getVendorDefinedObjectBuilder() {
    return vendorObjectBuilder;
  }

  /**
   * Put all attributes of the given object into the attributes table of this
   * object. This method is only static to be able to access invoke the
   * implementation of this method for each class separately.
   *
   * @param object
   *          The object to handle.
   */
  protected static void putAttributesInTable(PKCS11Object object) {
    Util.requireNonNull("object", object);
    object.attributeTable.put(Attribute.CLASS, object.objectClass);
  }

  /**
   * Allocates the attribute objects for this class and adds them to the
   * attribute table.
   */
  protected void allocateAttributes() {
    objectClass = new ObjectClassAttribute();

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
    } else if (!(otherObject instanceof PKCS11Object)) {
      return false;
    }

    PKCS11Object other = (PKCS11Object) otherObject;
    return (this.objectHandle == other.objectHandle)
        && this.objectClass.equals(other.objectClass);
  }

  /**
   * Return the table that contains all attributes of this object.
   * The key to this table is the attribute type as Long object.
   *
   * @return The table of all attributes of this object. Key is the attribute
   *         type as Long. This table is unmodifiable.
   */
  @SuppressWarnings("unchecked")
  public Hashtable<Long, Attribute> getAttributeTable() {
    return (Hashtable<Long, Attribute>) attributeTable.clone();
  }

  /**
   * Allows for putting attributes into the table without knowing the
   * {@link Attribute} at compile-time.
   *
   * @param attribute
   *        the attribute identifier as a {@link long} value
   * @param value
   *        the value
   * @throws UnsupportedAttributeException
   *         the specified attribute identifier is not available for this
   *         {@link PKCS11Object} instance.
   * @throws ClassCastException
   *         the given value type is not valid for this {@link Attribute}
   *         instance.
   */
  public void putAttribute(long attribute, Object value)
      throws UnsupportedAttributeException {
    Object myAttribute = getAttribute(attribute);
    if (null == myAttribute) {
      throw new UnsupportedAttributeException(
          "Unsupported attribute 0x" + Long.toHexString(attribute)
          + " for " + this.getClass().getName());
    }

    ((Attribute) myAttribute).setValue(value);
  }

  /**
   * Gets the attribute.
   *
   * @param attribute
   *        the attribute identifier as a {@link long} value
   * @return the attribute
   */
  public Attribute getAttribute(long attribute) {
    return (Attribute) attributeTable.get(Long.valueOf(attribute));
  }

  /**
   * Removes the attribute.
   *
   * @param attribute
   *        the attribute identifier as a {@link long} value
   */
  public void removeAttribute(long attribute) {
    getAttribute(attribute).setPresent(false);
  }

  /**
   * Gets the object handle of the underlying PKCS#11 object on the token.
   *
   * @return The object handle of the corresponding PKCS#11 object.
   */
  public long getObjectHandle() {
    return objectHandle;
  }

  /**
   * Sets the object handle of the underlying PKCS#11 object on the token.
   * An application will rarely need to call this method itself during normal
   * operation.
   *
   * @param objectHandle
   *          The object handle of the corresponding PKCS#11 object.
   */
  public void setObjectHandle(long objectHandle) {
    this.objectHandle = objectHandle;
  }

  /**
   * Gets the object class attribute of the PKCS#11 object. Its value must be
   * one of those defined in the ObjectClass interface or one with an value
   * bigger than ObjectClass.VENDOR_DEFINED.
   *
   * @return The object class attribute.
   */
  public LongAttribute getObjectClass() {
    return objectClass;
  }

  /**
   * Returns the PKCS#11 attributes of this object. The collection
   * contains CK_ATTRIBUTE objects, one for each present attribute of this
   * object; e.g. for each attribute that has a set value (which might be
   * sensitive).
   *
   * <p>The array representation of this collection can be used directly as
   * input for the PKCS#11 wrapper. The Session class uses this method for
   * various object operations.
   *
   * @return An collection of CK_ATTRIBUTE objects.
   */
  public Vector<CK_ATTRIBUTE> getSetAttributes() {
    Vector<CK_ATTRIBUTE> attributeCollection =
        new Vector<>(attributeTable.size());

    Enumeration<Attribute> attributeEnumeration =
        attributeTable.elements();
    while (attributeEnumeration.hasMoreElements()) {
      Attribute attribute = attributeEnumeration.nextElement();
      if (attribute.isPresent()) {
        CK_ATTRIBUTE ckAttribute = attribute.getCkAttribute();
        attributeCollection.addElement(ckAttribute);
      }
    }

    return attributeCollection;
  }

  /**
   * Returns the PKCS#11 attributes of an object. The array
   * contains CK_ATTRIBUTE objects, one for each set attribute of this object;
   * e.g. for each attribute that is not null.
   * The array can be used directly as input for the PKCS#11 wrapper. The
   * Session class uses this method for various object operations.
   *
   * @param object
   *          The iaik.pkcs.pkcs11.object.Object object to get the attributes
   *          from.
   * @return An array of CK_ATTRIBUTE objects. null, if the given object is
   *         null.
   * @exception PKCS11Exception
   *              If setting the attribute values.
   */
  public static CK_ATTRIBUTE[] getSetAttributes(PKCS11Object object)
      throws PKCS11Exception {
    Vector<CK_ATTRIBUTE> setAttributes = (object != null)
        ? object.getSetAttributes() : null;
    CK_ATTRIBUTE[] ckAttributes = (setAttributes != null)
        ? Util.convertAttributesVectorToArray(setAttributes) : null;

    return ckAttributes;
  }

  /**
   * The overriding of this method should ensure that the objects of this
   * class work correctly in a hashtable.
   *
   * @return The hash code of this object.
   */
  @Override
  public int hashCode() {
    return objectClass.hashCode() ^ ((int) objectHandle);
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
  public void readAttributes(Session session)
      throws TokenException {
    Util.requireNonNull("session", session);
    // no attributes that we need to read, subclasses set the CLASS
    // attribute
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
    StringBuilder sb = new StringBuilder(32);
    sb.append("  PKCS11Object Class: ");
    if (objectClass != null) {
      sb.append(objectClass.toString());
    } else {
      sb.append("<unavailable>");
    }

    return sb.toString();
  }

  /**
   * Returns a string representation of the current object. Some
   * parameters can be set to manipulate the output. The output is only for
   * debugging purposes and should not be used for other purposes.
   *
   * @param newline
   *        true if the output should start in a new line
   * @param withName
   *        true if the type of the attribute should be returned too
   * @param indent
   *        the indent to be used
   * @return A string presentation of this object for debugging output.
   */
  public String toString(boolean newline, boolean withName, String indent) {
    StringBuilder sb = new StringBuilder(1024);

    Enumeration<Attribute> attributesEnumeration = attributeTable.elements();
    boolean firstAttribute = !newline;
    while (attributesEnumeration.hasMoreElements()) {
      Attribute attribute = attributesEnumeration.nextElement();
      if (attribute.isPresent()) {
        if (!firstAttribute) {
          sb.append("\n");
        }
        sb.append(indent);
        sb.append(attribute.toString(withName));
        firstAttribute = false;
      }
    }

    return sb.toString();
  }

  /**
   * This method reads the attribute specified by <code>attribute</code> from
   * the token using the given <code>session</code>.
   * The object from which to read the attribute is specified using the
   * <code>objectHandle</code>. The <code>attribute</code> will contain
   * the results.
   * If the attempt to read the attribute returns
   * <code>CKR_ATTRIBUTE_TYPE_INVALID</code>, this will be indicated by
   * setting {@link Attribute#setPresent(boolean)} to <code>false</code>.
   * It CKR_ATTRIBUTE_SENSITIVE is returned, the attribute object is
   * marked as present
   * (by calling {@link Attribute#setPresent(boolean)} with
   * <code>true</code>), and in addition as sensitive by calling
   * {@link Attribute#setSensitive(boolean)} with <code>true</code>.
   *
   * @param session
   *          The session to use for reading the attribute.
   * @param objectHandle
   *          The handle of the object which contains the attribute.
   * @param attribute
   *          The object specifying the attribute type
   *          (see {@link Attribute#getType()}) and receiving the attribute
   *          value (see {@link Attribute#setCkAttribute(CK_ATTRIBUTE)}).
   * @exception PKCS11Exception
   *              If getting the attribute failed.
   */
  protected static void getAttributeValue(Session session, long objectHandle,
      Attribute attribute) throws PKCS11Exception {
    Util.requireNonNull("session", session);

    PKCS11 pkcs11Module = session.getModule().getPKCS11Module();
    long sessionHandle = session.getSessionHandle();
    long attributeCode = attribute.getCkAttribute().type;

    try {
      CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[1];
      attributeTemplateList[0] = new CK_ATTRIBUTE();
      attributeTemplateList[0].type = attributeCode;
      pkcs11Module.C_GetAttributeValue(sessionHandle, objectHandle,
          attributeTemplateList);
      attribute.setCkAttribute(attributeTemplateList[0]);
      attribute.setPresent(true);
      attribute.setSensitive(false);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      if (ex.getErrorCode()
          == PKCS11Constants.CKR_ATTRIBUTE_TYPE_INVALID) {
        // this means, that some requested attributes are missing, but
        // we can ignore this and proceed; e.g. a v2.01 module won't
        // have the object ID attribute
        attribute.setPresent(false);
      } else if (ex.getErrorCode()
          == PKCS11Constants.CKR_ATTRIBUTE_SENSITIVE) {
        // this means, that some requested attributes are missing, but
        // we can ignore this and proceed; e.g. a v2.01 module won't
        // have the object ID attribute
        attribute.setPresent(true);
        attribute.setSensitive(true);
      } else {
        // there was a different error that we should propagate
        throw new PKCS11Exception(ex);
      }
    }
  }

  /**
   * This method reads the attributes in a similar way as
   * {@link #getAttributeValue}, but a complete array at once. This can lead
   * to performance improvements. If reading all attributes at once fails, it
   * tries to read each attributes individually.
   *
   * @param session
   *          The session to use for reading the attributes.
   * @param objectHandle
   *          The handle of the object which contains the attributes.
   * @param attributes
   *          The objects specifying the attribute types
   *          (see {@link Attribute#getType()}) and receiving the attribute
   *          values (see {@link Attribute#setCkAttribute(CK_ATTRIBUTE)}).
   * @exception PKCS11Exception
   *              If getting the attributes failed.
   */
  protected static void getAttributeValues(Session session, long objectHandle,
      Attribute[] attributes) throws PKCS11Exception {
    Util.requireNonNull("session", session);
    Util.requireNonNull("attributes", attributes);

    PKCS11 pkcs11Module = session.getModule().getPKCS11Module();
    long sessionHandle = session.getSessionHandle();

    try {
      CK_ATTRIBUTE[] attributeTemplateList
        = new CK_ATTRIBUTE[attributes.length];
      for (int i = 0; i < attributes.length; i++) {
        CK_ATTRIBUTE attribute = new CK_ATTRIBUTE();
        attribute.type = attributes[i].getCkAttribute().type;
        attributeTemplateList[i] = attribute;
      }
      pkcs11Module.C_GetAttributeValue(sessionHandle, objectHandle,
            attributeTemplateList);
      for (int i = 0; i < attributes.length; i++) {
        attributes[i].setCkAttribute(attributeTemplateList[i]);
        attributes[i].setPresent(true);
        attributes[i].setSensitive(false);
      }
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      // try to read values separately
      for (int i = 0; i < attributes.length; i++) {
        getAttributeValue(session, objectHandle, attributes[i]);
      }
    }
  }

}
