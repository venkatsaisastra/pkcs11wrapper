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
import sun.security.pkcs11.wrapper.CK_SSL3_RANDOM_DATA;
import sun.security.pkcs11.wrapper.CK_VERSION;

/**
 * CK_TLS12_MASTER_KEY_DERIVE_PARAMS from PKCS#11 v2.40.
 *
 * @author Lijun Liao
 * @since 1.4.5
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
    return super.hashCode() ^ ((int) prfHashMechanism);
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
