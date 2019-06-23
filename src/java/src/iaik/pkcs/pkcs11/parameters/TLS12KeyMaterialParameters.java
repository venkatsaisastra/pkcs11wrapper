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
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;

import iaik.pkcs.pkcs11.Util;
import sun.security.pkcs11.wrapper.CK_SSL3_KEY_MAT_OUT;
import sun.security.pkcs11.wrapper.CK_SSL3_RANDOM_DATA;

/**
 * CK_TLS12_KEY_MAT_PARAMS from PKCS#11 v2.40.
 *
 * @author Lijun Liao
 * @since 1.4.5
 */
public class TLS12KeyMaterialParameters extends TLSKeyMaterialParameters {

  public static final String CLASS_CK_PARAMS =
      "sun.security.pkcs11.wrapper.CK_TLS12_KEY_MAT_PARAMS";

  private static final Constructor<?> constructor;

  private static final Field field_pReturnedKeyMaterial;

  /**
   * <B>PKCS#11:</B>
   * <PRE>
   *   CK_MECHANISM_TYPE prfHashMechanism;
   * </PRE>
   */
  public long prfHashMechanism;

  static {
    constructor = Util.getConstructor(CLASS_CK_PARAMS,
        int.class, int.class, int.class, boolean.class,
        CK_SSL3_RANDOM_DATA.class, long.class);

    Field field;
    try {
      Class<?> clazz = Class.forName(CLASS_CK_PARAMS, false,
          Parameters.class.getClassLoader());
      field = clazz.getField("pReturnedKeyMaterial");
    } catch (Throwable th) {
      field = null;
    }
    field_pReturnedKeyMaterial = field;
  }

  public static CK_SSL3_KEY_MAT_OUT getPReturnedKeyMaterial(Object object) {
    if (field_pReturnedKeyMaterial == null) {
      throw new IllegalStateException(
          "field field_pReturnedKeyMaterial does not exist");
    }

    try {
      return (CK_SSL3_KEY_MAT_OUT) field_pReturnedKeyMaterial.get(object);
    } catch (IllegalArgumentException | IllegalAccessException ex) {
      throw new IllegalStateException(
          "could not get field_pReturnedKeyMaterial", ex);
    }
  }

  public TLS12KeyMaterialParameters(int macSize, int keySize, int ivSize,
      boolean export, SSL3RandomDataParameters random,
      SSL3KeyMaterialOutParameters returnedKeyMaterial, long prfHashMechanism) {
    super(macSize, keySize, ivSize, export, random, returnedKeyMaterial);
    if (constructor == null) {
      throw new IllegalStateException(
          CLASS_CK_PARAMS + " is not available in the JDK");
    }
    if (field_pReturnedKeyMaterial == null) {
      throw new IllegalStateException(CLASS_CK_PARAMS
          + ".pReturnedKeyMaterialField is not available in the JDK");
    }

    this.prfHashMechanism = prfHashMechanism;
  }

  /**
   * Returns the string representation of CK_TLS12_KEY_MAT_PARAMS.
   *
   * @return the string representation of CK_TLS12_KEY_MAT_PARAMS
   */
  @Override
  public String toString() {
    return Util.concatObjects(
        super.toString(),
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
      Object params = constructor.newInstance(
          (int) macSizeInBits,(int) keySizeInBits, (int) ivSizeInBits,
          export, (CK_SSL3_RANDOM_DATA) randomInfo.getPKCS11ParamsObject(),
          prfHashMechanism);

      field_pReturnedKeyMaterial.set(params,
          returnedKeyMaterial.getPKCS11ParamsObject());
      return params;
    } catch (SecurityException | InstantiationException | IllegalAccessException
        | IllegalArgumentException | InvocationTargetException ex) {
      throw new IllegalStateException(
          "Could not create new instance of " + CLASS_CK_PARAMS, ex);
    }
  }

}
