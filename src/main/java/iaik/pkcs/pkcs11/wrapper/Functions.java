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

package iaik.pkcs.pkcs11.wrapper;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;

import iaik.pkcs.pkcs11.Util;
import sun.security.pkcs11.wrapper.CK_DATE;

/**
 * This class contains only static methods. It is the place for all functions
 * that are used by several classes in this package.
 *
 * @author Karl Scheibelhofer
 * @author Martin Schlaeffer
 */
@SuppressWarnings("restriction")
public class Functions implements PKCS11Constants {

  /**
   * The name of the properties file that holds the names of the PKCS#11
   * mechanism-codes.
   */
  private static final String CKM_CODE_PROPERTIES
      = "/iaik/pkcs/pkcs11/wrapper/ckm.properties";

  /**
   * True, if the mapping of mechanism codes to PKCS#11 mechanism names is
   * available.
   */
  private static boolean mechCodeNamesAvailable;

  /**
   * Maps mechanism codes as Long to their names as Strings.
   */
  private static Map<Long, String> mechNames;

  /**
   * Maps mechanism name as String to their code as Long.
   */
  private static Map<String, Long> mechNameToCodes;

  /**
   * This set contains the mechanisms that are full encrypt/decrypt
   * mechanisms; i.e. mechanisms that support the update functions.
   */
  private static Set<Long> fullEncryptDecryptMechs;

  /**
   * This set contains the mechanisms that are single-operation
   * encrypt/decrypt mechanisms; i.e. mechanisms that do not support the
   * update functions.
   */
  private static Set<Long> sglOpEncryptDecryptMechs;

  /**
   * This set contains the mechanisms that are full sign/verify
   * mechanisms; i.e. mechanisms that support the update functions.
   */
  private static Set<Long> fullSignVerifyMechs;

  /**
   * This set contains the mechanisms that are single-operation
   * sign/verify mechanisms; i.e. mechanisms that do not support the update
   * functions.
   */
  private static Set<Long> sglOpSignVerifyMechs;

  /**
   * This table contains the mechanisms that are sign/verify mechanisms with
   * message recovery.
   */
  private static Set<Long> signVerifyRecoverMechs;

  /**
   * This set contains the mechanisms that are digest mechanisms.
   * The Long values of the mechanisms are the keys, and the mechanism
   * names are the values.
   */
  private static Set<Long> digestMechs;

  /**
   * This table contains the mechanisms that key generation mechanisms; i.e.
   * mechanisms for generating symmetric keys.
   */
  private static Set<Long> keyGenMechs;

  /**
   * This table contains the mechanisms that key-pair generation mechanisms;
   * i.e. mechanisms for generating key-pairs.
   */
  private static Set<Long> keyPairGenMechs;

  /**
   * This table contains the mechanisms that are wrap/unwrap mechanisms.
   */
  private static Set<Long> wrapUnwrapMechs;

  /**
   * This table contains the mechanisms that are key derivation mechanisms.
   */
  private static Set<Long> keyDerivationMechs;

  /**
   * Converts the long value code of a mechanism to a name.
   *
   * @param mechCode
   *          The code of the mechanism to be converted to a string.
   * @return The string representation of the mechanism.
   */
  public static String mechanismCodeToString(long mechCode) {
    initMechanismMap();
    String name = mechCodeNamesAvailable ? mechNames.get(mechCode) : null;
    if (name == null) {
      name = PKCS11VendorConstants.mechanismCodeToString(mechCode);
    }

    if (name == null) {
      name = "Unknwon mechanism with code: 0x" + Util.toFullHex(mechCode);
    }

    return name;
  }

  /**
   * Converts the mechanism name to code value.
   *
   * @param mechName
   *          The name of the mechanism to be converted to a code.
   * @return The code representation of the mechanism.
   */
  public static long mechanismStringToCode(String mechName) {
    initMechanismMap();
    Long code = mechCodeNamesAvailable
        ? mechNameToCodes.get(mechName) : null;
    if (code == null) {
      code = PKCS11VendorConstants.mechanismStringToCode(mechName);
    }
    return (code != null) ? code : -1;
  }

  private static void initMechanismMap() {
    // ensure that another thread has not loaded the codes meanwhile
    if (mechNames != null) {
      return;
    }

    // if the names of the defined codes are not yet loaded, load them
    Map<Long, String> codeNameMap = new HashMap<>();
    Map<String, Long> nameCodeMap = new HashMap<>();

    Properties props = new Properties();
    try {
      props.load(Functions.class.getResourceAsStream(CKM_CODE_PROPERTIES));
      for (String propName : props.stringPropertyNames()) {
        String mechNames = props.getProperty(propName);
        StringTokenizer tokens = new StringTokenizer(mechNames, ",");

        if (!tokens.hasMoreTokens()) {
          System.out.println(
              "No name defined for Mechanism code " + propName);
        }

        long code;
        if (propName.startsWith("0x") || propName.startsWith("0X")) {
          code = Long.parseLong(propName.substring(2), 16);
        } else {
          code = Long.parseLong(propName);
        }

        String mainMechName = tokens.nextToken();
        codeNameMap.put(code, mainMechName);
        nameCodeMap.put(mainMechName, code);

        while (tokens.hasMoreTokens()) {
          nameCodeMap.put(tokens.nextToken(), code);
        }
      }
      mechNames = codeNameMap;
      mechNameToCodes = nameCodeMap;
      mechCodeNamesAvailable = true;
    } catch (Exception ex) {
      System.err.println(
          "Could not read properties for code names: " + ex.getMessage());
    }
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
   * @preconditions
   * @postconditions
   */
  public static boolean equals(CK_DATE date1, CK_DATE date2) {
    boolean equal = false;

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
   * Calculate a hash code for the given byte array.
   *
   * @param array
   *          The byte array.
   * @return A hash code for the given array.
   * @preconditions
   * @postconditions
   */
  public static int hashCode(byte[] array) {
    int hash = 0;

    if (array != null) {
      for (int i = 0; (i < 4) && (i < array.length); i++) {
        hash ^= (0xFF & array[i]) << ((i % 4) << 3);
      }
    }

    return hash;
  }

  /**
   * Calculate a hash code for the given char array.
   *
   * @param array
   *          The char array.
   * @return A hash code for the given array.
   * @preconditions
   * @postconditions
   */
  public static int hashCode(char[] array) {
    int hash = 0;

    if (array != null) {
      for (int i = 0; (i < 4) && (i < array.length); i++) {
        hash ^= (0xFFFFFFFF & array[i]);
      }
    }

    return hash;
  }

  /**
   * Calculate a hash code for the given long array.
   *
   * @param array
   *          The long array.
   * @return A hash code for the given array.
   * @preconditions
   * @postconditions
   */
  public static int hashCode(long[] array) {
    int hash = 0;

    if (array != null) {
      for (int i = 0; (i < 4) && (i < array.length); i++) {
        hash ^= (0xFFFFFFFF & (array[i] >> 4));
        hash ^= (0xFFFFFFFF & array[i]);
      }
    }

    return hash;
  }

  /**
   * Calculate a hash code for the given date object.
   *
   * @param date
   *          The date object.
   * @return A hash code for the given date.
   * @preconditions
   * @postconditions
   */
  public static int hashCode(CK_DATE date) {
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

  private static Set<Long> asSet(long[] elements) {
    HashSet<Long> set = new HashSet<>();
    for (long el : elements) {
      set.add(el);
    }
    return set;
  }

  /**
   * This method checks, if the mechanism with the given code is a full
   * encrypt/decrypt mechanism; i.e. it supports the encryptUpdate() and
   * decryptUpdate() functions.
   * If Returns true, the mechanism can be used with the encrypt
   * and decrypt functions including encryptUpdate and decryptUpdate.
   *
   * @param mechCode
   *          The code of the mechanism to check.
   * @return True, if the provided mechanism is a full encrypt/decrypt
   *         mechanism. False, otherwise.
   * @preconditions
   * @postconditions
   */
  public static boolean isFullEncryptDecryptMechanism(long mechCode) {
    // build the hashtable on demand (=first use)
    if (fullEncryptDecryptMechs == null) {
      long[] mechs = new long[]{CKM_AES_ECB, CKM_AES_CBC, CKM_AES_CBC_PAD,
        CKM_AES_OFB, CKM_AES_CFB64, CKM_AES_CFB8, CKM_AES_CFB128,
        CKM_AES_CFB1, CKM_AES_CTR, CKM_AES_CTS, CKM_AES_GCM,
        CKM_AES_CCM, CKM_AES_KEY_WRAP_PAD,
        CKM_DES3_ECB, CKM_DES3_CBC, CKM_DES3_CBC_PAD, CKM_DES_OFB64,
        CKM_DES_OFB8, CKM_DES_CFB64, CKM_DES_CFB8,
        CKM_BLOWFISH_CBC, CKM_BLOWFISH_CBC_PAD,
        CKM_CAMELLIA_ECB, CKM_CAMELLIA_CBC, CKM_CAMELLIA_CBC_PAD,
        CKM_ARIA_ECB, CKM_ARIA_CBC, CKM_ARIA_CBC_PAD,
        CKM_SEED_CBC_PAD, CKM_GOST28147_ECB, CKM_GOST28147};
      fullEncryptDecryptMechs = asSet(mechs);
    }

    return fullEncryptDecryptMechs.contains(mechCode)
      || PKCS11VendorConstants.isFullEncryptDecryptMechanism(mechCode);
  }

  /**
   * This method checks, if the mechanism with the given code is a
   * single-operation encrypt/decrypt mechanism; i.e. it does not support the
   * encryptUpdate() and decryptUpdate() functions.
   * If Returns true, the mechanism can be used with the encrypt
   * and decrypt functions excluding encryptUpdate and decryptUpdate.
   *
   * @param mechCode
   *          The code of the mechanism to check.
   * @return True, if the provided mechanism is a single-operation
   *         encrypt/decrypt mechanism. False, otherwise.
   * @preconditions
   * @postconditions
   */
  public static boolean isSingleOperationEncryptDecryptMechanism(
      long mechCode) {
    // build the hashtable on demand (=first use)
    if (sglOpEncryptDecryptMechs == null) {
      long[] mechs = new long[]{CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP,
        CKM_RSA_X_509, CKM_RSA_PKCS_TPM_1_1, CKM_RSA_PKCS_OAEP_TPM_1_1};
      sglOpEncryptDecryptMechs = asSet(mechs);
    }

    return sglOpEncryptDecryptMechs.contains(mechCode)
      || PKCS11VendorConstants.isSingleOperationEncryptDecryptMechanism(
          mechCode);
  }

  /**
   * This method checks, if the mechanism with the given code is a full
   * sign/verify mechanism; i.e. it supports the signUpdate()
   * and verifyUpdate() functions.
   * If Returns true, the mechanism can be used with the sign and
   * verify functions including signUpdate and verifyUpdate.
   *
   * @param mechCode
   *          The code of the mechanism to check.
   * @return True, if the provided mechanism is a full sign/verify
   *         mechanism. False, otherwise.
   * @preconditions
   * @postconditions
   */
  public static boolean isFullSignVerifyMechanism(long mechCode) {
    // build the hashtable on demand (=first use)
    if (fullSignVerifyMechs == null) {
      long[] mechs = new long[]{CKM_SHA1_RSA_PKCS, CKM_SHA256_RSA_PKCS,
        CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS, CKM_SHA1_RSA_PKCS_PSS,
        CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS_PSS,
        CKM_SHA512_RSA_PKCS_PSS, CKM_SHA1_RSA_X9_31,
        CKM_DSA_SHA1, CKM_DSA_SHA224, CKM_DSA_SHA256, CKM_DSA_SHA384,
        CKM_DSA_SHA512, CKM_ECDSA_SHA1, CKM_AES_MAC_GENERAL,
        CKM_AES_MAC, CKM_AES_XCBC_MAC, CKM_AES_XCBC_MAC_96,
        CKM_AES_GMAC, CKM_AES_CMAC_GENERAL, CKM_AES_CMAC,
        CKM_DES3_MAC_GENERAL, CKM_DES3_MAC, CKM_DES3_CMAC_GENERAL,
        CKM_DES3_CMAC, CKM_SHA_1_HMAC_GENERAL, CKM_SHA_1_HMAC,
        CKM_SHA224_HMAC, CKM_SHA224_HMAC_GENERAL, CKM_SHA224_RSA_PKCS,
        CKM_SHA224_RSA_PKCS_PSS, CKM_SHA256_HMAC_GENERAL,
        CKM_SHA256_HMAC, CKM_SHA384_HMAC_GENERAL, CKM_SHA384_HMAC,
        CKM_SHA512_HMAC_GENERAL, CKM_SHA512_HMAC,
        CKM_SHA512_224_HMAC_GENERAL, CKM_SHA512_224_HMAC,
        CKM_SHA512_256_HMAC_GENERAL, CKM_SHA512_256_HMAC,
        CKM_SHA512_T_HMAC_GENERAL, CKM_SHA512_T_HMAC,
        CKM_SSL3_MD5_MAC, CKM_SSL3_SHA1_MAC, CKM_TLS10_MAC_SERVER,
        CKM_TLS10_MAC_CLIENT, CKM_TLS12_MAC, CKM_CMS_SIG,
        CKM_CAMELLIA_MAC_GENERAL, CKM_CAMELLIA_MAC,
        CKM_ARIA_MAC_GENERAL, CKM_ARIA_MAC, CKM_SECURID, CKM_HOTP,
        CKM_ACTI, CKM_KIP_MAC, CKM_GOST28147_MAC, CKM_GOSTR3411_HMAC,
        CKM_GOSTR3410_WITH_GOSTR3411, CKM_DSA_SHA3_224,
        CKM_DSA_SHA3_256, CKM_DSA_SHA3_384, CKM_DSA_SHA3_512,
        CKM_SHA3_224_RSA_PKCS, CKM_SHA3_256_RSA_PKCS,
        CKM_SHA3_384_RSA_PKCS, CKM_SHA3_512_RSA_PKCS,
        CKM_SHA3_224_RSA_PKCS_PSS, CKM_SHA3_256_RSA_PKCS_PSS,
        CKM_SHA3_384_RSA_PKCS_PSS, CKM_SHA3_512_RSA_PKCS_PSS,
        CKM_SHA3_224_HMAC, CKM_SHA3_224_HMAC_GENERAL, CKM_SHA3_256_HMAC,
        CKM_SHA3_256_HMAC_GENERAL, CKM_SHA3_384_HMAC,
        CKM_SHA3_384_HMAC_GENERAL, CKM_SHA3_512_HMAC,
        CKM_SHA3_512_HMAC_GENERAL, CKM_ECDSA_SHA3_224,
        CKM_ECDSA_SHA3_256, CKM_ECDSA_SHA3_384, CKM_ECDSA_SHA3_512,
        CKM_MD2_HMAC_GENERAL, CKM_MD2_HMAC, CKM_MD5_HMAC_GENERAL,
        CKM_MD5_HMAC, CKM_RIPEMD128_HMAC_GENERAL, CKM_RIPEMD128_HMAC,
        CKM_RIPEMD160_HMAC_GENERAL, CKM_RIPEMD160_HMAC,
        CKM_RIPEMD128_RSA_PKCS, CKM_RIPEMD160_RSA_PKCS};
      fullSignVerifyMechs = asSet(mechs);
    }

    return fullSignVerifyMechs.contains(mechCode)
      || PKCS11VendorConstants.isFullEncryptDecryptMechanism(mechCode);
  }

  /**
   * This method checks, if the mechanism with the given code is a
   * single-operation sign/verify mechanism; i.e. it does not support the
   * signUpdate() and encryptUpdate() functions.
   * If Returns true, the mechanism can be used with the sign and
   * verify functions excluding signUpdate and encryptUpdate.
   *
   * @param mechCode
   *          The code of the mechanism to check.
   * @return True, if the provided mechanism is a single-operation
   *         sign/verify mechanism. False, otherwise.
   * @preconditions
   * @postconditions
   */
  public static boolean isSingleOperationSignVerifyMechanism(long mechCode) {
    // build the hashtable on demand (=first use)
    if (sglOpSignVerifyMechs == null) {
      long[] mechs = new long[]{CKM_RSA_PKCS, CKM_RSA_PKCS_PSS,
        CKM_RSA_9796, CKM_RSA_X_509, CKM_RSA_X9_31, CKM_DSA, CKM_ECDSA,
        CKM_GOSTR3410};
      sglOpSignVerifyMechs = asSet(mechs);
    }

    return sglOpSignVerifyMechs.contains(mechCode)
      || PKCS11VendorConstants.isSingleOperationSignVerifyMechanism(
          mechCode);
  }

  /**
   * This method checks, if the mechanism with the given code is a sign/verify
   * mechanism with message recovery.
   * If Returns true, the mechanism can be used with the
   * signRecover and verifyRecover functions.
   *
   * @param mechCode
   *          The code of the mechanism to check.
   * @return True, if the provided mechanism is a sign/verify mechanism with
   *         message recovery. False, otherwise.
   * @preconditions
   * @postconditions
   */
  public static boolean isSignVerifyRecoverMechanism(long mechCode) {
    // build the hashtable on demand (=first use)
    if (signVerifyRecoverMechs == null) {
      long[] mechs = new long[]{CKM_RSA_PKCS, CKM_RSA_9796, CKM_RSA_X_509,
        CKM_CMS_SIG, CKM_SEED_ECB, CKM_SEED_CBC, CKM_SEED_MAC_GENERAL};
      signVerifyRecoverMechs = asSet(mechs);
    }

    return signVerifyRecoverMechs.contains(mechCode)
      || PKCS11VendorConstants.isSignVerifyRecoverMechanism(mechCode);
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
    if (digestMechs == null) {
      long[] mechs = new long[]{CKM_SHA_1, CKM_SHA224, CKM_SHA256,
        CKM_SHA384, CKM_SHA512, CKM_SHA512_224, CKM_SHA512_256,
        CKM_SHA512_T, CKM_SEED_MAC, CKM_GOSTR3411, CKM_SHA3_224,
        CKM_SHA3_256, CKM_SHA3_384, CKM_SHA3_512, CKM_MD2, CKM_MD5,
        CKM_RIPEMD128, CKM_RIPEMD160};
      digestMechs = asSet(mechs);
    }

    return digestMechs.contains(mechCode)
      || PKCS11VendorConstants.isDigestMechanism(mechCode);
  }

  /**
   * This method checks, if the mechanism with the given code is a key
   * generation mechanism for generating symmetric keys.
   * If Returns true, the mechanism can be used with the
   * generateKey function.
   *
   * @param mechCode
   *          The code of the mechanism to check.
   * @return True, if the provided mechanism is a key generation mechanism.
   *         False, otherwise.
   * @preconditions
   * @postconditions
   */
  public static boolean isKeyGenerationMechanism(long mechCode) {
    // build the hashtable on demand (=first use)
    if (keyGenMechs == null) {
      long[] mechs = new long[]{CKM_DSA_PARAMETER_GEN,
        CKM_DSA_PROBABLISTIC_PARAMETER_GEN,
        CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN,
        //CKM_DSA_FIPS_G_GEN,
        CKM_DH_PKCS_PARAMETER_GEN, CKM_X9_42_DH_PARAMETER_GEN,
        CKM_GENERIC_SECRET_KEY_GEN, CKM_AES_KEY_GEN, CKM_DES2_KEY_GEN,
        CKM_DES3_KEY_GEN, CKM_PBE_SHA1_DES3_EDE_CBC,
        CKM_PBE_SHA1_DES2_EDE_CBC, CKM_PBA_SHA1_WITH_SHA1_HMAC,
        CKM_PKCS5_PBKD2, CKM_SSL3_PRE_MASTER_KEY_GEN,
        CKM_WTLS_PRE_MASTER_KEY_GEN, CKM_CAMELLIA_KEY_GEN,
        CKM_ARIA_KEY_GEN, CKM_SEED_KEY_GEN, CKM_SECURID_KEY_GEN,
        CKM_HOTP_KEY_GEN, CKM_ACTI_KEY_GEN, CKM_GOST28147_KEY_GEN};
      keyGenMechs = asSet(mechs);
    }

    return keyGenMechs.contains(mechCode)
      || PKCS11VendorConstants.isKeyGenerationMechanism(mechCode);
  }

  /**
   * This method checks, if the mechanism with the given code is a key-pair
   * generation mechanism for generating key-pairs.
   * If Returns true, the mechanism can be used with the
   * generateKeyPair function.
   *
   * @param mechCode
   *          The code of the mechanism to check.
   * @return True, if the provided mechanism is a key-pair generation
   *         mechanism. False, otherwise.
   * @preconditions
   * @postconditions
   */
  public static boolean isKeyPairGenerationMechanism(long mechCode) {
    // build the hashtable on demand (=first use)
    if (keyPairGenMechs == null) {
      long[] mechs = new long[]{CKM_RSA_PKCS_KEY_PAIR_GEN,
        CKM_RSA_X9_31_KEY_PAIR_GEN, CKM_DSA_KEY_PAIR_GEN,
        CKM_EC_KEY_PAIR_GEN, CKM_DH_PKCS_KEY_PAIR_GEN,
        CKM_X9_42_DH_KEY_PAIR_GEN, CKM_GOSTR3410_KEY_PAIR_GEN};
      keyPairGenMechs = asSet(mechs);
    }

    return keyPairGenMechs.contains(mechCode)
      || PKCS11VendorConstants.isKeyPairGenerationMechanism(mechCode);
  }

  /**
   * This method checks, if the mechanism with the given code is a
   * wrap/unwrap mechanism; i.e. it supports the wrapKey()
   * and unwrapKey() functions.
   * If Returns true, the mechanism can be used with the wrapKey
   * and unwrapKey functions.
   *
   * @param mechCode
   *          The code of the mechanism to check.
   * @return True, if the provided mechanism is a wrap/unwrap mechanism.
   *         False, otherwise.
   * @preconditions
   * @postconditions
   */
  public static boolean isWrapUnwrapMechanism(long mechCode) {
    // build the hashtable on demand (=first use)
    if (wrapUnwrapMechs == null) {
      long[] mechs = new long[] {CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP,
        CKM_RSA_X_509, CKM_RSA_PKCS_TPM_1_1, CKM_RSA_PKCS_OAEP_TPM_1_1,
        CKM_ECDH_AES_KEY_WRAP, CKM_AES_ECB, CKM_AES_CBC,
        CKM_AES_CBC_PAD, CKM_AES_OFB, CKM_AES_CFB64, CKM_AES_CFB8,
        CKM_AES_CFB128, CKM_AES_CFB1, CKM_AES_CTR, CKM_AES_CTS,
        CKM_AES_GCM, CKM_AES_CCM, CKM_AES_KEY_WRAP, CKM_DES3_ECB,
        CKM_DES3_CBC, CKM_DES3_CBC_PAD, CKM_BLOWFISH_CBC,
        CKM_BLOWFISH_CBC_PAD, CKM_CAMELLIA_ECB, CKM_CAMELLIA_CBC,
        CKM_CAMELLIA_CBC_PAD, CKM_ARIA_ECB, CKM_ARIA_CBC,
        CKM_ARIA_CBC_PAD, CKM_SEED_CBC_PAD, CKM_KIP_WRAP,
        CKM_GOST28147_ECB, CKM_GOST28147, CKM_GOST28147_KEY_WRAP,
        CKM_GOSTR3410_KEY_WRAP};
      wrapUnwrapMechs = asSet(mechs);
    }

    return wrapUnwrapMechs.contains(mechCode)
        || PKCS11VendorConstants.isWrapUnwrapMechanism(mechCode);
  }

  /**
   * This method checks, if the mechanism with the given code is a key
   * derivation mechanism.
   * If Returns true, the mechanism can be used with the deriveKey
   * function.
   *
   * @param mechCode
   *          The code of the mechanism to check.
   * @return True, if the provided mechanism is a key derivation mechanism.
   *         False, otherwise.
   * @preconditions
   * @postconditions
   */
  public static boolean isKeyDerivationMechanism(long mechCode) {
    // build the hashtable on demand (=first use)
    if (keyDerivationMechs == null) {
      long[] mechs = new long[]{
        CKM_ECDH1_DERIVE, CKM_ECDH1_COFACTOR_DERIVE, CKM_ECMQV_DERIVE,
        CKM_DH_PKCS_DERIVE, CKM_X9_42_DH_DERIVE,
        CKM_X9_42_DH_HYBRID_DERIVE, CKM_X9_42_MQV_DERIVE, CKM_AES_GMAC,
        CKM_DES_ECB_ENCRYPT_DATA, CKM_DES_CBC_ENCRYPT_DATA,
        CKM_DES3_ECB_ENCRYPT_DATA, CKM_DES3_CBC_ENCRYPT_DATA,
        CKM_AES_ECB_ENCRYPT_DATA, CKM_AES_CBC_ENCRYPT_DATA,
        CKM_SHA1_KEY_DERIVATION, CKM_SHA224_KEY_DERIVATION,
        CKM_SHA256_KEY_DERIVATION, CKM_SHA384_KEY_DERIVATION,
        CKM_SHA512_KEY_DERIVATION, CKM_SHA512_224_KEY_DERIVATION,
        CKM_SHA512_256_KEY_DERIVATION, CKM_SHA512_T_KEY_DERIVATION,
        CKM_SSL3_MASTER_KEY_DERIVE, CKM_SSL3_MASTER_KEY_DERIVE_DH,
        CKM_SSL3_KEY_AND_MAC_DERIVE, CKM_TLS12_MASTER_KEY_DERIVE,
        CKM_TLS12_MASTER_KEY_DERIVE_DH, CKM_TLS12_KEY_AND_MAC_DERIVE,
        CKM_TLS12_KEY_SAFE_DERIVE, CKM_TLS_KDF,
        CKM_WTLS_MASTER_KEY_DERIVE, CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC,
        CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
        CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE, CKM_WTLS_PRF,
        CKM_CONCATENATE_BASE_AND_KEY, CKM_CONCATENATE_BASE_AND_DATA,
        CKM_CONCATENATE_DATA_AND_BASE, CKM_XOR_BASE_AND_DATA,
        CKM_EXTRACT_KEY_FROM_KEY, CKM_CAMELLIA_ECB_ENCRYPT_DATA,
        CKM_CAMELLIA_CBC_ENCRYPT_DATA, CKM_ARIA_ECB_ENCRYPT_DATA,
        CKM_ARIA_CBC_ENCRYPT_DATA, CKM_SEED_ECB_ENCRYPT_DATA,
        CKM_SEED_CBC_ENCRYPT_DATA, CKM_KIP_DERIVE, CKM_GOSTR3410_DERIVE,
        CKM_SHA3_224_KEY_DERIVE, CKM_SHA3_256_KEY_DERIVE,
        CKM_SHA3_384_KEY_DERIVE, CKM_SHA3_512_KEY_DERIVE,
        CKM_SHAKE_128_KEY_DERIVE, CKM_SHAKE_256_KEY_DERIVE,
        CKM_SHA256_KEY_DERIVATION, CKM_SHA256_KEY_DERIVATION,
        CKM_SHA256_KEY_DERIVATION, CKM_SHA256_KEY_DERIVATION};
      keyDerivationMechs = asSet(mechs);
    }

    return keyDerivationMechs.contains(mechCode)
        || PKCS11VendorConstants.isKeyDerivationMechanism(mechCode);
  }

}
