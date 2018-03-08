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

package iaik.pkcs.pkcs11.constants;

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
        "/iaik/pkcs/pkcs11/constants/ckm-vendor.properties";

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
