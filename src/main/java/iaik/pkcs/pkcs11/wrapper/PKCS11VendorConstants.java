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
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY  WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package iaik.pkcs.pkcs11.wrapper;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import iaik.pkcs.pkcs11.Util;

/**
 * PKCS# Vendor Constants.
 * @author Lijun Liao
 * @version 1.4.1
 *
 */
// CHECKSTYLE:SKIP
public class PKCS11VendorConstants {

  private static final String VENDOR_FILE = "pkcs11.ckm-vendor.file";

  private static final String VENDOR_PROPERTIES =
        "/iaik/pkcs/pkcs11/wrapper/ckm-vendor.properties";

  /**
   * True, if the mapping of mechanism codes to PKCS#11 mechanism names is
   * available.
   */
  private static boolean mechanismCodeNamesAvailable;

  /**
   * Maps mechanism codes as Long to their names as Strings.
   */
  private static Map<Long, String> mechanismNames;

  /**
   * Maps mechanism name as String to their code as Long.
   */
  private static Map<String, Long> mechanismNameToCodes;

  /**
   * This set contains the mechanisms that are full encrypt/decrypt
   * mechanisms; i.e. mechanisms that support the update functions.
   */
  private static Set<Long> fullEncryptDecryptMechanisms;

  /**
   * This set contains the mechanisms that are full sign/verify
   * mechanisms; i.e. mechanisms that support the update functions.
   */
  private static Set<Long> fullSignVerifyMechanisms;

  /**
   * This set contains the mechanisms that are digest mechanisms.
   * The Long values of the mechanisms are the keys, and the mechanism
   * names are the values.
   */
  private static Set<Long> digestMechanisms;

  /**
   * This table contains the mechanisms that key generation mechanisms; i.e.
   * mechanisms for generating symmetric keys.
   */
  private static Set<Long> keyGenerationMechanisms;

  /**
   * This table contains the mechanisms that key-pair generation mechanisms;
   * i.e. mechanisms for generating key-pairs.
   */
  private static Set<Long> keyPairGenerationMechanisms;

  /**
   * This table contains the mechanisms that are wrap/unwrap mechanisms.
   */
  private static Set<Long> wrapUnwrapMechanisms;

  /**
   * This table contains the mechanisms that are key derivation mechanisms.
   */
  private static Set<Long> keyDerivationMechanisms;

  public static final long CKK_VENDOR_SM2;

  public static final long CKM_VENDOR_SM2_KEY_PAIR_GEN;

  public static final long CKM_VENDOR_SM2;

  public static final long CKM_VENDOR_SM2_SM3;

  public static final long CKM_VENDOR_SM2_ENCRYPT;

  public static final long CKM_VENDOR_SM3;

  public static final long CKK_VENDOR_SM4;

  public static final long CKM_VENDOR_SM4_KEY_GEN;

  public static final long CKM_VENDOR_SM4_ECB;

  public static final long CKM_VENDOR_SM4_CBC;

  public static final long CKM_VENDOR_SM4_MAC_GENERAL;

  public static final long CKM_VENDOR_SM4_MAC;

  public static final long CKM_VENDOR_ISO2_SM4_MAC_GENERAL;

  public static final long CKM_VENDOR_ISO2_SM4_MAC;

  public static final long CKM_VENDOR_SM4_ECB_ENCRYPT_DATA;

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
      is = PKCS11VendorConstants.class.getResourceAsStream(
          VENDOR_PROPERTIES);
    }

    Properties props = null;
    if (is != null) {
      props = new Properties();
      try {
        props.load(is);
      } catch (IOException ex) {
        System.err.println(
            "Error while loading pkcs11-vendor properties");
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
    CKM_VENDOR_SM4_MAC_GENERAL =
        readLong(props, "CKM_VENDOR_SM4_MAC_GENERAL");
    CKM_VENDOR_SM4_MAC =
        readLong(props, "CKM_VENDOR_SM4_MAC");
    CKM_VENDOR_ISO2_SM4_MAC_GENERAL =
        readLong(props, "CKM_VENDOR_ISO2_SM4_MAC_GENERAL");
    CKM_VENDOR_ISO2_SM4_MAC = readLong(props, "CKM_VENDOR_ISO2_SM4_MAC");
    CKM_VENDOR_SM4_ECB_ENCRYPT_DATA =
        readLong(props, "CKM_VENDOR_SM4_ECB_ENCRYPT_DATA");
  }

  /**
   * This method checks, if the mechanism with the given code is a digest
   * mechanism.
   * If Returns true, the mechanism can be used with the digest
   * functions.
   *
   * @param mechCode
   *          The code of the mechanism to check.
   * @return True, if the provided mechanism is a digest mechanism. False,
   *         otherwise.
   * @preconditions
   * @postconditions
   */
  public static boolean isDigestMechanism(long mechCode) {
    // build the hashtable on demand (=first use)
    if (digestMechanisms == null) {
      long[] mechs = new long[]{PKCS11VendorConstants.CKM_VENDOR_SM3};

      Set<Long> mechanisms = new HashSet<>();
      for (Long mech : mechs) {
        mechanisms.add(mech);
      }
      digestMechanisms = mechanisms;
    }

    return digestMechanisms.contains(new Long(mechCode));
  }

  public static boolean isFullEncryptDecryptMechanism(long mechCode) {
    // build the hashtable on demand (=first use)
    if (fullEncryptDecryptMechanisms == null) {
      long[] mechs = new long[]{CKM_VENDOR_SM4_CBC, CKM_VENDOR_SM4_ECB};

      Set<Long> mechanisms = new HashSet<>();
      for (Long mech : mechs) {
        mechanisms.add(mech);
      }
      fullEncryptDecryptMechanisms = mechanisms;
    }

    return fullEncryptDecryptMechanisms.contains(new Long(mechCode));
  }

  public static boolean isFullSignVerifyMechanism(long mechCode) {
    // build the hashtable on demand (=first use)
    if (fullSignVerifyMechanisms == null) {
      long[] mechs = new long[]{CKM_VENDOR_SM2, CKM_VENDOR_SM2_SM3,
        CKM_VENDOR_ISO2_SM4_MAC, CKM_VENDOR_SM4_MAC,
        CKM_VENDOR_SM4_MAC_GENERAL, CKM_VENDOR_ISO2_SM4_MAC,
        CKM_VENDOR_ISO2_SM4_MAC_GENERAL};

      Set<Long> mechanisms = new HashSet<>();
      for (Long mech : mechs) {
        mechanisms.add(mech);
      }
      fullSignVerifyMechanisms = mechanisms;
    }

    return fullSignVerifyMechanisms.contains(new Long(mechCode));
  }

  public static boolean isKeyDerivationMechanism(long mechCode) {
    // build the hashtable on demand (=first use)
    if (keyDerivationMechanisms == null) {
      long[] mechs = new long[]{
        CKM_VENDOR_SM4_ECB_ENCRYPT_DATA};

      Set<Long> mechanisms = new HashSet<>();
      for (Long mech : mechs) {
        mechanisms.add(mech);
      }
      keyDerivationMechanisms = mechanisms;
    }

    return keyDerivationMechanisms.contains(new Long(mechCode));
  }

  public static boolean isKeyPairGenerationMechanism(long mechCode) {
    // build the hashtable on demand (=first use)
    if (keyPairGenerationMechanisms == null) {
      long[] mechs = new long[]{CKM_VENDOR_SM2_KEY_PAIR_GEN};

      Set<Long> mechanisms = new HashSet<>();
      for (Long mech : mechs) {
        mechanisms.add(mech);
      }
      keyPairGenerationMechanisms = mechanisms;
    }

    return keyPairGenerationMechanisms.contains(new Long(mechCode));
  }

  public static boolean isKeyGenerationMechanism(long mechCode) {
    // build the hashtable on demand (=first use)
    if (keyGenerationMechanisms == null) {
      long[] mechs = new long[]{CKM_VENDOR_SM4_KEY_GEN};

      Set<Long> mechanisms = new HashSet<>();
      for (Long mech : mechs) {
        mechanisms.add(mech);
      }
      keyGenerationMechanisms = mechanisms;
    }

    return keyGenerationMechanisms.contains(new Long(mechCode));
  }

  public static boolean isSignVerifyRecoverMechanism(long mechCode) {
    return false;
  }

  public static boolean isSingleOperationEncryptDecryptMechanism(
      long mechCode) {
    return false;
  }

  public static boolean isSingleOperationSignVerifyMechanism(long mechCode) {
    return false;
  }

  public static boolean isWrapUnwrapMechanism(long mechCode) {
    // build the hashtable on demand (=first use)
    if (wrapUnwrapMechanisms == null) {
      long[] mechs = new long[] {CKM_VENDOR_SM2_ENCRYPT,
        CKM_VENDOR_SM4_ECB};
      Set<Long> mechanisms = new HashSet<>();
      for (long m : mechs) {
        mechanisms.add(m);
      }
      wrapUnwrapMechanisms = mechanisms;
    }

    return wrapUnwrapMechanisms.contains(mechCode);
  }

  public static String mechanismCodeToString(long mechCode) {
    initMechanismMap();
    String name = mechanismCodeNamesAvailable
        ? mechanismNames.get(new Long(mechCode)) : null;
    if (name == null) {
      name = "Unknwon mechanism with code: 0x" + Util.toFullHex(mechCode);
    }

    return name;
  }

  /**
   * Converts the mechanism name to code value.
   *
   * @param mechanismName
   *          The name of the mechanism to be converted to a code.
   * @return The code representation of the mechanism.
   */
  public static long mechanismStringToCode(String mechanismName) {
    initMechanismMap();
    Long code = mechanismCodeNamesAvailable
        ? mechanismNameToCodes.get(mechanismName) : null;
    return (code != null) ? code : -1;
  }

  private static void initMechanismMap() {
    // ensure that another thread has not loaded the codes meanwhile
    if (mechanismNames != null) {
      return;
    }

    // if the names of the defined error codes are not yet loaded, load them
    Map<Long, String> codeNameMap = new HashMap<>();
    Map<String, Long> nameCodeMap = new HashMap<>();

    codeNameMap.put(CKM_VENDOR_ISO2_SM4_MAC, "CKM_VENDOR_ISO2_SM4_MAC");
    codeNameMap.put(CKM_VENDOR_ISO2_SM4_MAC_GENERAL,
        "CKM_VENDOR_ISO2_SM4_MAC_GENERAL");
    codeNameMap.put(CKM_VENDOR_SM2, "CKM_VENDOR_SM2");
    codeNameMap.put(CKM_VENDOR_SM2_ENCRYPT, "CKM_VENDOR_SM2_ENCRYPT");
    codeNameMap.put(CKM_VENDOR_SM2_KEY_PAIR_GEN,
        "CKM_VENDOR_SM2_KEY_PAIR_GEN");
    codeNameMap.put(CKM_VENDOR_SM2_SM3, "CKM_VENDOR_SM2_SM3");
    codeNameMap.put(CKM_VENDOR_SM3, "CKM_VENDOR_SM3");
    codeNameMap.put(CKM_VENDOR_SM4_CBC, "CKM_VENDOR_SM4_CBC");
    codeNameMap.put(CKM_VENDOR_SM4_ECB, "CKM_VENDOR_SM4_ECB");
    codeNameMap.put(CKM_VENDOR_SM4_ECB_ENCRYPT_DATA,
        "CKM_VENDOR_SM4_ECB_ENCRYPT_DATA");
    codeNameMap.put(CKM_VENDOR_SM4_KEY_GEN, "CKM_VENDOR_SM4_KEY_GEN");
    codeNameMap.put(CKM_VENDOR_SM4_MAC, "CKM_VENDOR_SM4_MAC");
    codeNameMap.put(CKM_VENDOR_SM4_MAC_GENERAL,
        "CKM_VENDOR_SM4_MAC_GENERAL");

    Set<Long> codes = codeNameMap.keySet();
    for (Long code : codes) {
      nameCodeMap.put(codeNameMap.get(code), code);
    }

    mechanismNames = codeNameMap;
    mechanismNameToCodes = nameCodeMap;
    mechanismCodeNamesAvailable = true;
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
