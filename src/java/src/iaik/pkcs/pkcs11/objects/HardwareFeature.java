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
import iaik.pkcs.pkcs11.Util;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;

/**
 * This is the base class for hardware feature classes. Objects of this class
 * represent hardware features as specified by PKCS#11 v2.20.
 * A hardware feature is of a specific type: MONOTONIC_COUNTER, CLOCK,
 * CKH_USER_INTERFAC or VENDOR_DEFINED.
 * If an application needs to use vendor-defined hardware
 * features, it must set a VendorDefinedHardwareFeatureBuilder using the
 * setVendorDefinedHardwareFeatureBuilder method.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (hardwareFeatureType <> null)
 */
public class HardwareFeature extends PKCS11Object {

  /**
   * This interface defines the available hardware feature types as defined by
   * PKCS#11 2.20: MONOTONIC_COUNTER, CLOCK, CKH_USER_INTERFAC or
   * VENDOR_DEFINED.
   *
   * @author Karl Scheibelhofer
   * @version 1.0
   * @invariants
   */
  public interface FeatureType {

    /**
     * The identifier for a monotonic counter.
     */
    public static final Long MONOTONIC_COUNTER =
        Long.valueOf(PKCS11Constants.CKH_MONOTONIC_COUNTER);

    /**
     * The identifier for a clock.
     */
    public static final Long CLOCK = Long.valueOf(PKCS11Constants.CKH_CLOCK);

    /**
     * The identifier for a user interface.
     */
    public static final Long USER_INTERFACE =
        Long.valueOf(PKCS11Constants.CKH_USER_INTERFACE);

    /**
     * The identifier for a VENDOR_DEFINED hardware feature. Any Long object
     * with a value bigger than this one is also a valid vendor-defined
     * hardware feature type identifier.
     */
    public static final Long VENDOR_DEFINED =
        Long.valueOf(PKCS11Constants.CKH_VENDOR_DEFINED);

  }

  /**
   * If an application uses vendor defined hardware features, it must
   * implement this interface and install such an object handler using
   * setVendorDefinedHardwareFeatureBuilder.
   *
   * @author Karl Scheibelhofer
   * @version 1.0
   * @invariants
   */
  public interface VendorDefinedHardwareFeatureBuilder {

    /**
     * This method should instantiate an PKCS11Object of this class or of
     * any sub-class. It can use the given handles and PKCS#11 module to
     * retrieve attributes of the PKCS#11 object from the token.
     *
     * @param session
   *              The session to use for reading attributes. This session must
     *          have the appropriate rights; i.e. it must be a user-session,
     *          if it is a private object.
     * @param objectHandle
   *              The object handle as given from the PKCS#111 module.
     * @return The object representing the PKCS#11 object.
     *         The returned object can be casted to the
     *         according sub-class.
     * @exception PKCS11Exception
     *              If getting the attributes failed.
     * @preconditions (session <> null)
     * @postconditions (result <> null)
     */
    public PKCS11Object build(Session session, long objectHandle)
        throws sun.security.pkcs11.wrapper.PKCS11Exception;

  }

  /**
   * The currently set vendor defined hardware feature builder, or null.
   */
  protected static VendorDefinedHardwareFeatureBuilder
      vendorHardwareFeatureBuilder;

  /**
   * The type of this hardware feature. Its value is one of FeatureType, or
   * one that has a bigger value than VENDOR_DEFINED.
   */
  protected HardwareFeatureTypeAttribute hardwareFeatureType;

  /**
   * The default constructor. An application use this constructor to
   * instantiate a hardware feature that serves as a template. It may also be
   * useful for working with vendor-defined hardware features.
   *
   * @preconditions
   * @postconditions
   */
  public HardwareFeature() {
    objectClass.setLongValue(ObjectClass.HW_FEATURE);
  }

  /**
   * Called by getInstance to create an instance of a PKCS#11 hardware
   * feature.
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
  protected HardwareFeature(Session session, long objectHandle)
      throws TokenException {
    super(session, objectHandle);
    objectClass.setLongValue(ObjectClass.HW_FEATURE);
  }

  /**
   * Get the given hardware feature type as string.
   *
   * @param hardwareFeatureType
   *          The hardware feature type to get as string.
   * @return A string denoting the object hardware feature type; e.g. "Clock".
   * @preconditions (hardwareFeatureType <> null)
   * @postconditions (result <> null)
   */
  public static String getHardwareFeatureTypeName(Long hardwareFeatureType) {
    Util.requireNonNull("hardwareFeatureType", hardwareFeatureType);
    String hardwareFeatureTypeName;

    if (hardwareFeatureType.equals(FeatureType.MONOTONIC_COUNTER)) {
      hardwareFeatureTypeName = "Monotonic Counter";
    } else if (hardwareFeatureType.equals(FeatureType.CLOCK)) {
      hardwareFeatureTypeName = "Clock";
    } else if (hardwareFeatureType.equals(FeatureType.USER_INTERFACE)) {
      hardwareFeatureTypeName = "User Interface";
    } else if ((hardwareFeatureType.longValue()
            & FeatureType.VENDOR_DEFINED.longValue()) != 0L) {
      hardwareFeatureTypeName = "Vendor Defined";
    } else {
      hardwareFeatureTypeName = "<unknown>";
    }

    return hardwareFeatureTypeName;
  }

  /**
   * Called by sub-classes to create an instance of a PKCS#11 hardware
   * feature. This method reads the hardware feature type attribute and calls
   * the getInstance method of the according sub-class.
   * If the hardware feature type is a vendor defined it uses the
   * VendorDefinedHardwareFeatureBuilder set by the application. If no
   * hardware feature could be constructed, Returns null.
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
   * @preconditions (session <> null)
   * @postconditions (result <> null)
   */
  public static PKCS11Object getInstance(Session session, long objectHandle)
      throws TokenException {
    Util.requireNonNull("session", session);

    HardwareFeatureTypeAttribute hardwareFeatureTypeAttribute =
        new HardwareFeatureTypeAttribute();
    getAttributeValue(session, objectHandle, hardwareFeatureTypeAttribute);

    Long hardwareFeatureType = hardwareFeatureTypeAttribute.getLongValue();

    PKCS11Object newObject;

    if (hardwareFeatureTypeAttribute.isPresent()
        && (hardwareFeatureType != null)) {
      if (hardwareFeatureType.equals(FeatureType.MONOTONIC_COUNTER)) {
        newObject = MonotonicCounter.getInstance(session, objectHandle);
      } else if (hardwareFeatureType.equals(FeatureType.CLOCK)) {
        newObject = Clock.getInstance(session, objectHandle);
      } else if (hardwareFeatureType.equals(FeatureType.USER_INTERFACE)) {
        // TODO: add user interface object
        // newObject = UserInterface.getInstance(session, objectHandle);
        newObject = getUnknownHardwareFeature(session, objectHandle);
      } else if ((hardwareFeatureType.longValue()
              & FeatureType.VENDOR_DEFINED.longValue()) != 0L) {
        newObject = getUnknownHardwareFeature(session, objectHandle);
      } else {
        newObject = getUnknownHardwareFeature(session, objectHandle);
      }
    } else {
      newObject = getUnknownHardwareFeature(session, objectHandle);
    }

    return newObject;
  }

  /**
   * Try to create a hardware feature which has no or an unknown hardware
   * feature type attribute.
   * This implementation will try to use a vendor defined hardware feature
   * builder, if such has been set.
   * If this is impossible or fails, it will create just a simple
   * {@link iaik.pkcs.pkcs11.objects.HardwareFeature HardwareFeature}.
   *
   * @param session
   *          The session to use.
   * @param objectHandle
   *          The handle of the object
   * @return A new PKCS11Object.
   * @throws TokenException
   *           If no object could be created.
   * @preconditions (session <> null)
   * @postconditions (result <> null)
   */
  protected static PKCS11Object getUnknownHardwareFeature(Session session,
      long objectHandle) throws TokenException {
    Util.requireNonNull("session", session);

    PKCS11Object newObject;
    if (vendorHardwareFeatureBuilder != null) {
      try {
        newObject = vendorHardwareFeatureBuilder.build(session,
            objectHandle);
      } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
        // we can just treat it like some unknown type of hardware
        // feature
        newObject = new HardwareFeature(session, objectHandle);
      }
    } else {
      // we can just treat it like some unknown type of hardware feature
      newObject = new HardwareFeature(session, objectHandle);
    }

    return newObject;
  }

  /**
   * Set a vendor-defined hardware feature builder that should be called to
   * create an* instance of an vendor-defined PKCS#11 hardware feature; i.e.
   * an instance of a vendor defined sub-class of this class.
   *
   * @param builder
   *          The vendor-defined hardware feature builder. Null to clear any
   *          previously installed vendor-defined builder.
   * @preconditions
   * @postconditions
   */
  public static void setVendorDefinedHardwareFeatureBuilder(
      VendorDefinedHardwareFeatureBuilder builder) {
    vendorHardwareFeatureBuilder = builder;
  }

  /**
   * Get the currently set vendor-defined hardware feature builder.
   *
   * @return The currently set vendor-defined hardware feature builder or null
   *         if none is set.
   * @preconditions
   * @postconditions
   */
  public static VendorDefinedHardwareFeatureBuilder
      getVendorDefinedHardwareFeatureBuilder() {
    return vendorHardwareFeatureBuilder;
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
  protected static void putAttributesInTable(HardwareFeature object) {
    Util.requireNonNull("object", object);

    object.attributeTable.put(Attribute.HW_FEATURE_TYPE,
        object.hardwareFeatureType);
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

    hardwareFeatureType = new HardwareFeatureTypeAttribute();

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
    } else if (!(otherObject instanceof HardwareFeature)) {
      return false;
    }

    HardwareFeature other = (HardwareFeature) otherObject;
    return super.equals(other)
        && this.hardwareFeatureType.equals(other.hardwareFeatureType);
  }

  /**
   * Gets the hardware feature type attribute of the PKCS#11 key. Its value
   * must be one of those defined in the FeatureType interface or one with an
   * value bigger than FeatureType.VENDOR_DEFINED.
   *
   * @return The hardware feature type identifier.
   * @preconditions
   * @postconditions (result <> null)
   */
  public LongAttribute getHardwareFeatureType() {
    return hardwareFeatureType;
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
    return hardwareFeatureType.hashCode();
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
      "\n  Hardware Feature Type: ", ((hardwareFeatureType != null)
          ? hardwareFeatureType.toString() : "<unavailable>"));
  }

}
