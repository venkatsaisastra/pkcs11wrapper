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

package iaik.pkcs.pkcs11.wrapper;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * PKCS# Vendor Constants.
 * @author Lijun Liao
 * @version 1.4.1
 *
 */
// CHECKSTYLE:SKIP
class PKCS11VendorConstants {

  private static final String VENDOR_FILE = "pkcs11.ckm-vendor.file";

  private static final String VENDOR_PROPERTIES =
        "/iaik/pkcs/pkcs11/wrapper/ckm-vendor.properties";

  static final long CKK_VENDOR_SM2;

  static final long CKM_VENDOR_SM2_KEY_PAIR_GEN;

  static final long CKM_VENDOR_SM2;

  static final long CKM_VENDOR_SM2_SM3;

  static final long CKM_VENDOR_SM2_ENCRYPT;

  static final long CKM_VENDOR_SM3;

  static final long CKK_VENDOR_SM4;

  static final long CKM_VENDOR_SM4_KEY_GEN;

  static final long CKM_VENDOR_SM4_ECB;

  static final long CKM_VENDOR_SM4_CBC;

  static final long CKM_VENDOR_SM4_MAC_GENERAL;

  static final long CKM_VENDOR_SM4_MAC;

  static final long CKM_VENDOR_ISO2_SM4_MAC_GENERAL;

  static final long CKM_VENDOR_ISO2_SM4_MAC;

  static final long CKM_VENDOR_SM4_ECB_ENCRYPT_DATA;

  static {
    String file =  System.getProperty(VENDOR_FILE);

    InputStream is = null;
    if (file != null) {
      try {
        is = new FileInputStream(file);
      } catch (FileNotFoundException ex) {
        System.err.println("File " + file + " does not exist");
      }
    } else {
      is = PKCS11VendorConstants.class.getResourceAsStream(VENDOR_PROPERTIES);
    }

    Properties props = null;
    if (is != null) {
      props = new Properties();
      try {
        props.load(is);
      } catch (IOException ex) {
        System.err.println("Error while loading pkcs11-vendor properties");
        props = null;
      }
    }

    if (props == null) {
      System.out.println("could not load properties");
    }

    CKK_VENDOR_SM2 = readLong(props, "CKK_VENDOR_SM2");
    CKM_VENDOR_SM2_KEY_PAIR_GEN =
        readLong(props, "CKM_VENDOR_SM2_KEY_PAIR_GEN");
    CKM_VENDOR_SM2 = readLong(props, "CKM_VENDOR_SM2");
    CKM_VENDOR_SM2_SM3 = readLong(props, "CKM_VENDOR_SM2_SM3");
    CKM_VENDOR_SM2_ENCRYPT = readLong(props, "CKM_VENDOR_SM2_ENCRYPT");
    CKM_VENDOR_SM3 = readLong(props, "CKM_VENDOR_SM3");
    CKK_VENDOR_SM4 = readLong(props, "CKK_VENDOR_SM4");
    CKM_VENDOR_SM4_KEY_GEN = readLong(props, "CKM_VENDOR_SM4_KEY_GEN");
    CKM_VENDOR_SM4_ECB = readLong(props, "CKM_VENDOR_SM4_ECB");
    CKM_VENDOR_SM4_CBC = readLong(props, "CKM_VENDOR_SM4_CBC");
    CKM_VENDOR_SM4_MAC_GENERAL = readLong(props, "CKM_VENDOR_SM4_MAC_GENERAL");
    CKM_VENDOR_SM4_MAC = readLong(props, "CKM_VENDOR_SM4_MAC");
    CKM_VENDOR_ISO2_SM4_MAC_GENERAL =
        readLong(props, "CKM_VENDOR_ISO2_SM4_MAC_GENERAL");
    CKM_VENDOR_ISO2_SM4_MAC = readLong(props, "CKM_VENDOR_ISO2_SM4_MAC");
    CKM_VENDOR_SM4_ECB_ENCRYPT_DATA =
        readLong(props, "CKM_VENDOR_SM4_ECB_ENCRYPT_DATA");
  }

  private static long readLong(Properties props, String propKey) {
    if (props == null) {
      return 0x80000000L;
    }

    String str = props.getProperty(propKey);
    if (str == null || str.isEmpty()) {
      return 0x80000000L;
    }

    str = str.toLowerCase();

    boolean hex = false;
    if (str.startsWith("0x")) {
      str = str.substring(2);
      hex = true;
    }

    if (str.endsWith("ul")) {
      str = str.substring(0, str.length() - 2);
    } else if (str.endsWith("l")) {
      str = str.substring(0, str.length() - 1);
    }

    return Long.parseLong(str, hex ? 16 : 10);
  }

  private PKCS11VendorConstants() {
  }

}
