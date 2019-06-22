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

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import iaik.pkcs.pkcs11.Util;

/**
 * CK_TLS_MAC_PARAMS from PKCS#11 v2.40.
 */
public class TLSMacParameters implements Parameters {

  public static final String CLASS_CK_PARAMS =
      "sun.security.pkcs11.wrapper.CK_TLS_MAC_PARAMS";

  private static final Constructor<?> constructor;

  /**
   * <B>PKCS#11:</B>
   * <PRE>
   *   CK_MECHANISM_TYPE prfMechanism;
   * </PRE>
   */
  public long prfMechanism;

  /**
   * <B>PKCS#11:</B>
   * <PRE>
   *   CK_ULONG ulMacLength;
   * </PRE>
   */
  public long macLength;

  /**
   * <B>PKCS#11:</B>
   * <PRE>
   *   CK_ULONG ulServerOrClient;
   * </PRE>
   */
  public long serverOrClient;

  static {
    constructor = Util.getConstructor(CLASS_CK_PARAMS,
        long.class, long.class, long.class);
  }

  public TLSMacParameters(long prfMechanism,
          long macLength, long serverOrClient) {
    if (constructor == null) {
      throw new IllegalStateException(
          CLASS_CK_PARAMS + " is not available in the JDK");
    }

    this.prfMechanism = prfMechanism;
    this.macLength = macLength;
    this.serverOrClient = serverOrClient;
  }

  @Override
  public Object getPKCS11ParamsObject() {
    try {
      return constructor.newInstance(prfMechanism, macLength, serverOrClient);
    } catch (SecurityException | InstantiationException | IllegalAccessException
        | IllegalArgumentException | InvocationTargetException ex) {
      throw new IllegalStateException(
          "Could not create new instance of " + CLASS_CK_PARAMS, ex);
    }
  }

  @Override
  public String toString() {
    return Util.concatObjects("prfMechanism", prfMechanism,
        "\nmacLength", macLength,
        "\nserverOrClient", serverOrClient);
  }

  @Override
  public boolean equals(Object otherObject) {
    if (this == otherObject) {
      return true;
    } else if (!(otherObject instanceof TLSMacParameters)) {
      return false;
    }

    TLSMacParameters other = (TLSMacParameters) otherObject;
    return prfMechanism == other.prfMechanism
        && macLength == other.macLength
        && serverOrClient == other.serverOrClient;
  }

  @Override
  public int hashCode() {
    return (int) prfMechanism ^ (int) macLength ^ (int) serverOrClient;
  }

}
