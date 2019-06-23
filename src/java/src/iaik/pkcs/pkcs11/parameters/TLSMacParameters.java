/*
 *
 * Copyright (c) 2019 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package iaik.pkcs.pkcs11.parameters;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import iaik.pkcs.pkcs11.Util;

/**
 * CK_TLS_MAC_PARAMS from PKCS#11 v2.40.
 *
 * @author Lijun Liao
 * @since 1.4.5
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
    return ((int) prfMechanism) ^ ((int) macLength) ^ ((int) serverOrClient);
  }

}
