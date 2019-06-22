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

import sun.security.pkcs11.wrapper.CK_SSL3_RANDOM_DATA;
import sun.security.pkcs11.wrapper.CK_VERSION;

import iaik.pkcs.pkcs11.Util;

/**
 * CK_TLS12_MASTER_KEY_DERIVE_PARAMS from PKCS#11 v2.40.
 */
public class TLS12MasterKeyDeriveParameters
extends TLSMasterKeyDeriveParameters {

  public static final String CLASS_CK_PARAMS =
      "sun.security.pkcs11.wrapper.CK_TLS12_MASTER_KEY_DERIVE_PARAMS";

  private static final Constructor<?> constructor;

  /**
   * <B>PKCS#11:</B>
   * <PRE>
   *   CK_MECHANISM_TYPE prfHashMechanism;
   * </PRE>
   */
  public long prfHashMechanism;

  static {
    constructor = Util.getConstructor(CLASS_CK_PARAMS,
        CK_SSL3_RANDOM_DATA.class, CK_VERSION.class, long.class);
  }

  public TLS12MasterKeyDeriveParameters(SSL3RandomDataParameters random,
      VersionParameters version, long prfHashMechanism) {
    super(random, version);

    if (constructor == null) {
      throw new IllegalStateException(
          CLASS_CK_PARAMS + " is not available in the JDK");
    }

    this.prfHashMechanism = prfHashMechanism;
  }

  public String toString() {
    return Util.concatObjects(super.toString(),
        "\nprfHashMechanism: ", prfHashMechanism);
  }

  @Override
  public boolean equals(Object otherObject) {
    if (this == otherObject) {
      return true;
    } else if (!(otherObject instanceof TLS12KeyMaterialParameters)) {
      return false;
    }

    TLS12KeyMaterialParameters other = (TLS12KeyMaterialParameters) otherObject;
    return prfHashMechanism == other.prfHashMechanism;
  }

  @Override
  public int hashCode() {
    return super.hashCode() ^ (int) prfHashMechanism;
  }

  @Override
  public Object getPKCS11ParamsObject() {
    try {
      return constructor.newInstance(
          randomInfo == null ? null : randomInfo.getPKCS11ParamsObject(),
          version == null ? null : version.getPKCS11ParamsObject(),
          prfHashMechanism);
    } catch (SecurityException | InstantiationException | IllegalAccessException
        | IllegalArgumentException | InvocationTargetException ex) {
      throw new IllegalStateException(
          "Could not create new instance of " + CLASS_CK_PARAMS, ex);
    }
  }

}
