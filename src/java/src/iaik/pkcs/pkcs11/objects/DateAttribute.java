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

import iaik.pkcs.pkcs11.Util;
import sun.security.pkcs11.wrapper.CK_DATE;

import java.util.Arrays;
import java.util.Date;

/**
 * Objects of this class represent a date attribute of an PKCS#11 object
 * as specified by PKCS#11.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 */
public class DateAttribute extends Attribute {

  /**
   * Constructor taking the PKCS#11 type of the attribute.
   *
   * @param type
   *          The PKCS#11 type of this attribute; e.g.
   *          PKCS11Constants.CKA_START_DATE.
   */
  public DateAttribute(long type) {
    super(type);
  }

  /**
   * Set the date value of this attribute. Null, is also valid.
   * A call to this method sets the present flag to true.
   *
   * @param value
   *          The date value to set. May be null.
   */
  public void setDateValue(Date value) {
    ckAttribute.pValue = Util.convertToCkDate(value);
    present = true;
  }

  /**
   * Get the date value of this attribute. Null, is also possible.
   *
   * @return The date value of this attribute or null.
   */
  public Date getDateValue() {
    return Util.convertToDate((CK_DATE) ckAttribute.pValue);
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
    } else if (!(otherObject instanceof DateAttribute)) {
      return false;
    }

    DateAttribute other = (DateAttribute) otherObject;
    if (!this.present && !other.present) {
      return true;
    } else if (!(this.present && other.present)) {
      return false;
    } else if (this.sensitive != other.sensitive) {
      return false;
    } else if (this.ckAttribute.type != other.ckAttribute.type) {
      return false;
    }

    return equals((CK_DATE) this.ckAttribute.pValue,
        (CK_DATE) other.ckAttribute.pValue);
  }

  /**
   * The overriding of this method should ensure that the objects of this
   * class work correctly in a hashtable.
   *
   * @return The hash code of this object.
   */
  @Override
  public int hashCode() {
    if ((ckAttribute.pValue == null)) {
      return (int) ckAttribute.type;
    }

    return ((int) ckAttribute.type) ^ hashCode((CK_DATE) ckAttribute.pValue);
  }

  @Override
  public void setValue(Object value) {
    setDateValue((Date) value);
  }

  /**
   * Check the given dates for equality. This method considers both dates as
   * equal, if both are <code>null</code> or both contain exactly the same
   * char values.
   *
   * @param date1
   *          The first date.
   * @param date2
   *          The second date.
   * @return True, if both dates are <code>null</code> or both contain the
   *         same char values. False, otherwise.
   */
  private static boolean equals(CK_DATE date1, CK_DATE date2) {
    boolean equal;

    if (date1 == date2) {
      equal = true;
    } else if ((date1 != null) && (date2 != null)) {
      equal = Arrays.equals(date1.year, date2.year)
          && Arrays.equals(date1.month, date2.month)
          && Arrays.equals(date1.day, date2.day);
    } else {
      equal = false;
    }

    return equal;
  }

  /**
   * Calculate a hash code for the given date object.
   *
   * @param date
   *          The date object.
   * @return A hash code for the given date.
   */
  private static int hashCode(CK_DATE date) {
    int hash = 0;

    if (date != null) {
      if (date.year.length == 4) {
        hash ^= (0xFFFF & date.year[0]) << 16;
        hash ^= 0xFFFF & date.year[1];
        hash ^= (0xFFFF & date.year[2]) << 16;
        hash ^= 0xFFFF & date.year[3];
      }
      if (date.month.length == 2) {
        hash ^= (0xFFFF & date.month[0]) << 16;
        hash ^= 0xFFFF & date.month[1];
      }
      if (date.day.length == 2) {
        hash ^= (0xFFFF & date.day[0]) << 16;
        hash ^= 0xFFFF & date.day[1];
      }
    }

    return hash;
  }

}
