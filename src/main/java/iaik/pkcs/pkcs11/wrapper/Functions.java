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

import sun.security.pkcs11.wrapper.CK_DATE;

/**
 * This class contains only static methods. It is the place for all functions
 * that are used by several classes in this package.
 *
 * @author Karl Scheibelhofer
 * @author Martin Schlaeffer
 */
@SuppressWarnings("restriction")
public class Functions {

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
    private static boolean mechanismCodeNamesAvailable;

    /**
     * Maps mechanism codes as Long to their names as Strings.
     */
    private static Map<Long, String> mechanismNames;

    /**
     * This set contains the mechanisms that are full encrypt/decrypt
     * mechanisms; i.e. mechanisms that support the update functions.
     */
    private static Set<Long> fullEncryptDecryptMechanisms;

    /**
     * This set contains the mechanisms that are single-operation
     * encrypt/decrypt mechanisms; i.e. mechanisms that do not support the
     * update functions.
     */
    private static Set<Long> singleOperationEncryptDecryptMechanisms;

    /**
     * This set contains the mechanisms that are full sign/verify
     * mechanisms; i.e. mechanisms that support the update functions.
     */
    private static Set<Long> fullSignVerifyMechanisms;

    /**
     * This set contains the mechanisms that are single-operation
     * sign/verify mechanisms; i.e. mechanisms that do not support the update
     * functions.
     */
    private static Set<Long> singleOperationSignVerifyMechanisms;

    /**
     * This table contains the mechanisms that are sign/verify mechanisms with
     * message recovery.
     */
    private static Set<Long> signVerifyRecoverMechanisms;

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

    /**
     * For converting numbers to their hex presentation.
     */
    private static final char[] HEX_DIGITS = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

    /**
     * Converts a long value to a hexadecimal String of length 16. Includes
     * leading zeros if necessary.
     *
     * @param value
     *          The long value to be converted.
     * @return The hexadecimal string representation of the long value.
     */
    public static String toFullHexString(long value) {
        long currentValue = value;
        StringBuilder stringBuffer = new StringBuilder(16);
        for (int j = 0; j < 16; j++) {
            int currentDigit = (int) currentValue & 0xf;
            stringBuffer.append(HEX_DIGITS[currentDigit]);
            currentValue >>>= 4;
        }

        return stringBuffer.reverse().toString();
    }

    /**
     * Converts a byte array to a hexadecimal String. Each byte is presented by
     * its two digit hex-code; 0x0A -> "0a", 0x00 -> "00". No leading "0x" is
     * included in the result.
     *
     * @param value
     *          The byte array to be converted
     * @return the hexadecimal string representation of the byte array
     */
    public static String toHexString(byte[] value) {
        if (value == null) {
            return null;
        }

        StringBuilder buffer = new StringBuilder(2 * value.length);
        int single;

        for (int i = 0; i < value.length; i++) {
            single = value[i] & 0xFF;

            if (single < 0x10) {
                buffer.append('0');
            }

            buffer.append(Integer.toString(single, 16));
        }

        return buffer.toString();
    }

    /**
     * Converts the long value code of a mechanism to a name.
     *
     * @param mechanismCode
     *          The code of the mechanism to be converted to a string.
     * @return The string representation of the mechanism.
     */
    public static String mechanismCodeToString(long mechanismCode) {
        initMechanismMap();
        String name = mechanismCodeNamesAvailable
                ? mechanismNames.get(new Long(mechanismCode)) : null;
        if (name == null) {
            name = PKCS11VendorConstants.mechanismCodeToString(mechanismCode);
        }

        if (name == null) {
            name = "Unknwon mechanism with code: 0x"
                    + toFullHexString(mechanismCode);
        }

        return name;
    }

    private static void initMechanismMap() {
        // ensure that another thread has not loaded the codes meanwhile
        if (mechanismNames != null) {
            return;
        }

        // if the names of the defined error codes are not yet loaded, load them
        Map<Long, String> codeNameMap = new HashMap<>();

        Properties props = new Properties();
        try {
            props.load(Functions.class.getResourceAsStream(
                CKM_CODE_PROPERTIES));
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
            }
            mechanismNames = codeNameMap;
            mechanismCodeNamesAvailable = true;
        } catch (Exception exception) {
            System.err.println(
                "Could not read properties for error code names: "
                + exception.getMessage());
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

    /**
     * This method checks, if the mechanism with the given code is a full
     * encrypt/decrypt mechanism; i.e. it supports the encryptUpdate() and
     * decryptUpdate() functions.
     * If Returns true, the mechanism can be used with the encrypt
     * and decrypt functions including encryptUpdate and decryptUpdate.
     *
     * @param mechanismCode
     *          The code of the mechanism to check.
     * @return True, if the provided mechanism is a full encrypt/decrypt
     *         mechanism. False, otherwise.
     * @preconditions
     * @postconditions
     */
    public static boolean isFullEncryptDecryptMechanism(long mechanismCode) {
        // build the hashtable on demand (=first use)
        if (fullEncryptDecryptMechanisms == null) {
            long[] mechs = new long[]{
                PKCS11Constants.CKM_AES_ECB,
                PKCS11Constants.CKM_AES_CBC,
                PKCS11Constants.CKM_AES_CBC_PAD,
                PKCS11Constants.CKM_AES_OFB,
                PKCS11Constants.CKM_AES_CFB64,
                PKCS11Constants.CKM_AES_CFB8,
                PKCS11Constants.CKM_AES_CFB128,
                PKCS11Constants.CKM_AES_CFB1,
                PKCS11Constants.CKM_AES_CTR,
                PKCS11Constants.CKM_AES_CTS,
                PKCS11Constants.CKM_AES_GCM,
                PKCS11Constants.CKM_AES_CCM,
                PKCS11Constants.CKM_AES_KEY_WRAP_PAD,
                PKCS11Constants.CKM_DES3_ECB,
                PKCS11Constants.CKM_DES3_CBC,
                PKCS11Constants.CKM_DES3_CBC_PAD,
                PKCS11Constants.CKM_DES_OFB64,
                PKCS11Constants.CKM_DES_OFB8,
                PKCS11Constants.CKM_DES_CFB64,
                PKCS11Constants.CKM_DES_CFB8,
                PKCS11Constants.CKM_BLOWFISH_CBC,
                PKCS11Constants.CKM_BLOWFISH_CBC_PAD,
                PKCS11Constants.CKM_CAMELLIA_ECB,
                PKCS11Constants.CKM_CAMELLIA_CBC,
                PKCS11Constants.CKM_CAMELLIA_CBC_PAD,
                PKCS11Constants.CKM_ARIA_ECB,
                PKCS11Constants.CKM_ARIA_CBC,
                PKCS11Constants.CKM_ARIA_CBC_PAD,
                PKCS11Constants.CKM_SEED_CBC_PAD,
                PKCS11Constants.CKM_GOST28147_ECB,
                PKCS11Constants.CKM_GOST28147,
            };

            Set<Long> mechanisms = new HashSet<>();
            for (Long mech : mechs) {
                mechanisms.add(mech);
            }
            fullEncryptDecryptMechanisms = mechanisms;
        }

        boolean contained = fullEncryptDecryptMechanisms.contains(
                new Long(mechanismCode));
        if (!contained) {
            contained = PKCS11VendorConstants.isFullEncryptDecryptMechanism(
                    mechanismCode);
        }
        return contained;
    }

    /**
     * This method checks, if the mechanism with the given code is a
     * single-operation encrypt/decrypt mechanism; i.e. it does not support the
     * encryptUpdate() and decryptUpdate() functions.
     * If Returns true, the mechanism can be used with the encrypt
     * and decrypt functions excluding encryptUpdate and decryptUpdate.
     *
     * @param mechanismCode
     *          The code of the mechanism to check.
     * @return True, if the provided mechanism is a single-operation
     *         encrypt/decrypt mechanism. False, otherwise.
     * @preconditions
     * @postconditions
     */
    public static boolean isSingleOperationEncryptDecryptMechanism(
            long mechanismCode) {
        // build the hashtable on demand (=first use)
        if (singleOperationEncryptDecryptMechanisms == null) {
            long[] mechs = new long[]{
                PKCS11Constants.CKM_RSA_PKCS,
                PKCS11Constants.CKM_RSA_PKCS_OAEP,
                PKCS11Constants.CKM_RSA_X_509,
                PKCS11Constants.CKM_RSA_PKCS_TPM_1_1,
                PKCS11Constants.CKM_RSA_PKCS_OAEP_TPM_1_1
            };

            Set<Long> mechanisms = new HashSet<>();
            for (Long mech : mechs) {
                mechanisms.add(mech);
            }
            singleOperationEncryptDecryptMechanisms = mechanisms;
        }

        boolean contained = singleOperationEncryptDecryptMechanisms.contains(
                new Long(mechanismCode));
        if (!contained) {
            contained = PKCS11VendorConstants
                    .isSingleOperationEncryptDecryptMechanism(mechanismCode);
        }
        return contained;
    }

    /**
     * This method checks, if the mechanism with the given code is a full
     * sign/verify mechanism; i.e. it supports the signUpdate()
     * and verifyUpdate() functions.
     * If Returns true, the mechanism can be used with the sign and
     * verify functions including signUpdate and verifyUpdate.
     *
     * @param mechanismCode
     *          The code of the mechanism to check.
     * @return True, if the provided mechanism is a full sign/verify
     *         mechanism. False, otherwise.
     * @preconditions
     * @postconditions
     */
    public static boolean isFullSignVerifyMechanism(long mechanismCode) {
        // build the hashtable on demand (=first use)
        if (fullSignVerifyMechanisms == null) {
            long[] mechs = new long[]{
                PKCS11Constants.CKM_SHA1_RSA_PKCS,
                PKCS11Constants.CKM_SHA256_RSA_PKCS,
                PKCS11Constants.CKM_SHA384_RSA_PKCS,
                PKCS11Constants.CKM_SHA512_RSA_PKCS,
                PKCS11Constants.CKM_SHA1_RSA_PKCS_PSS,
                PKCS11Constants.CKM_SHA256_RSA_PKCS_PSS,
                PKCS11Constants.CKM_SHA384_RSA_PKCS_PSS,
                PKCS11Constants.CKM_SHA512_RSA_PKCS_PSS,
                PKCS11Constants.CKM_SHA1_RSA_X9_31,
                PKCS11Constants.CKM_DSA_SHA1,
                PKCS11Constants.CKM_DSA_SHA224,
                PKCS11Constants.CKM_DSA_SHA256,
                PKCS11Constants.CKM_DSA_SHA384,
                PKCS11Constants.CKM_DSA_SHA512,
                PKCS11Constants.CKM_ECDSA_SHA1,
                PKCS11Constants.CKM_AES_MAC_GENERAL,
                PKCS11Constants.CKM_AES_MAC,
                PKCS11Constants.CKM_AES_XCBC_MAC,
                PKCS11Constants.CKM_AES_XCBC_MAC_96,
                PKCS11Constants.CKM_AES_GMAC,
                PKCS11Constants.CKM_AES_CMAC_GENERAL,
                PKCS11Constants.CKM_AES_CMAC,
                PKCS11Constants.CKM_DES3_MAC_GENERAL,
                PKCS11Constants.CKM_DES3_MAC,
                PKCS11Constants.CKM_DES3_CMAC_GENERAL,
                PKCS11Constants.CKM_DES3_CMAC,
                PKCS11Constants.CKM_SHA_1_HMAC_GENERAL,
                PKCS11Constants.CKM_SHA_1_HMAC,
                PKCS11Constants.CKM_SHA224_HMAC,
                PKCS11Constants.CKM_SHA224_HMAC_GENERAL,
                PKCS11Constants.CKM_SHA224_RSA_PKCS,
                PKCS11Constants.CKM_SHA224_RSA_PKCS_PSS,
                PKCS11Constants.CKM_SHA256_HMAC_GENERAL,
                PKCS11Constants.CKM_SHA256_HMAC,
                PKCS11Constants.CKM_SHA384_HMAC_GENERAL,
                PKCS11Constants.CKM_SHA384_HMAC,
                PKCS11Constants.CKM_SHA512_HMAC_GENERAL,
                PKCS11Constants.CKM_SHA512_HMAC,
                PKCS11Constants.CKM_SHA512_224_HMAC_GENERAL,
                PKCS11Constants.CKM_SHA512_224_HMAC,
                PKCS11Constants.CKM_SHA512_256_HMAC_GENERAL,
                PKCS11Constants.CKM_SHA512_256_HMAC,
                PKCS11Constants.CKM_SHA512_T_HMAC_GENERAL,
                PKCS11Constants.CKM_SHA512_T_HMAC,
                PKCS11Constants.CKM_SSL3_MD5_MAC,
                PKCS11Constants.CKM_SSL3_SHA1_MAC,
                PKCS11Constants.CKM_TLS10_MAC_SERVER,
                PKCS11Constants.CKM_TLS10_MAC_CLIENT,
                PKCS11Constants.CKM_TLS12_MAC,
                PKCS11Constants.CKM_CMS_SIG,
                PKCS11Constants.CKM_CAMELLIA_MAC_GENERAL,
                PKCS11Constants.CKM_CAMELLIA_MAC,
                PKCS11Constants.CKM_ARIA_MAC_GENERAL,
                PKCS11Constants.CKM_ARIA_MAC,
                PKCS11Constants.CKM_SECURID,
                PKCS11Constants.CKM_HOTP,
                PKCS11Constants.CKM_ACTI,
                PKCS11Constants.CKM_KIP_MAC,
                PKCS11Constants.CKM_GOST28147_MAC,
                PKCS11Constants.CKM_GOSTR3411_HMAC,
                PKCS11Constants.CKM_GOSTR3410_WITH_GOSTR3411,
                PKCS11Constants.CKM_DSA_SHA3_224,
                PKCS11Constants.CKM_DSA_SHA3_256,
                PKCS11Constants.CKM_DSA_SHA3_384,
                PKCS11Constants.CKM_DSA_SHA3_512,
                PKCS11Constants.CKM_SHA3_224_RSA_PKCS,
                PKCS11Constants.CKM_SHA3_256_RSA_PKCS,
                PKCS11Constants.CKM_SHA3_384_RSA_PKCS,
                PKCS11Constants.CKM_SHA3_512_RSA_PKCS,
                PKCS11Constants.CKM_SHA3_224_RSA_PKCS_PSS,
                PKCS11Constants.CKM_SHA3_256_RSA_PKCS_PSS,
                PKCS11Constants.CKM_SHA3_384_RSA_PKCS_PSS,
                PKCS11Constants.CKM_SHA3_512_RSA_PKCS_PSS,
                PKCS11Constants.CKM_SHA3_224_HMAC,
                PKCS11Constants.CKM_SHA3_224_HMAC_GENERAL,
                PKCS11Constants.CKM_SHA3_256_HMAC,
                PKCS11Constants.CKM_SHA3_256_HMAC_GENERAL,
                PKCS11Constants.CKM_SHA3_384_HMAC,
                PKCS11Constants.CKM_SHA3_384_HMAC_GENERAL,
                PKCS11Constants.CKM_SHA3_512_HMAC,
                PKCS11Constants.CKM_SHA3_512_HMAC_GENERAL,
                PKCS11Constants.CKM_ECDSA_SHA3_224,
                PKCS11Constants.CKM_ECDSA_SHA3_256,
                PKCS11Constants.CKM_ECDSA_SHA3_384,
                PKCS11Constants.CKM_ECDSA_SHA3_512,
                PKCS11Constants.CKM_MD2_HMAC_GENERAL,
                PKCS11Constants.CKM_MD2_HMAC,
                PKCS11Constants.CKM_MD5_HMAC_GENERAL,
                PKCS11Constants.CKM_MD5_HMAC,
                PKCS11Constants.CKM_RIPEMD128_HMAC_GENERAL,
                PKCS11Constants.CKM_RIPEMD128_HMAC,
                PKCS11Constants.CKM_RIPEMD160_HMAC_GENERAL,
                PKCS11Constants.CKM_RIPEMD160_HMAC,
                PKCS11Constants.CKM_RIPEMD128_RSA_PKCS,
                PKCS11Constants.CKM_RIPEMD160_RSA_PKCS
            };

            Set<Long> mechanisms = new HashSet<>();
            for (Long mech : mechs) {
                mechanisms.add(mech);
            }
            fullSignVerifyMechanisms = mechanisms;
        }

        boolean contained = fullSignVerifyMechanisms.contains(
                new Long(mechanismCode));
        if (!contained) {
            contained = PKCS11VendorConstants.isFullEncryptDecryptMechanism(
                    mechanismCode);
        }
        return contained;
    }

    /**
     * This method checks, if the mechanism with the given code is a
     * single-operation sign/verify mechanism; i.e. it does not support the
     * signUpdate() and encryptUpdate() functions.
     * If Returns true, the mechanism can be used with the sign and
     * verify functions excluding signUpdate and encryptUpdate.
     *
     * @param mechanismCode
     *          The code of the mechanism to check.
     * @return True, if the provided mechanism is a single-operation
     *         sign/verify mechanism. False, otherwise.
     * @preconditions
     * @postconditions
     */
    public static boolean isSingleOperationSignVerifyMechanism(
            long mechanismCode) {
        // build the hashtable on demand (=first use)
        if (singleOperationSignVerifyMechanisms == null) {
            long[] mechs = new long[]{
                PKCS11Constants.CKM_RSA_PKCS,
                PKCS11Constants.CKM_RSA_PKCS_PSS,
                PKCS11Constants.CKM_RSA_9796,
                PKCS11Constants.CKM_RSA_X_509,
                PKCS11Constants.CKM_RSA_X9_31,
                PKCS11Constants.CKM_DSA,
                PKCS11Constants.CKM_ECDSA,
                PKCS11Constants.CKM_GOSTR3410
            };

            Set<Long> mechanisms = new HashSet<>();
            for (Long mech : mechs) {
                mechanisms.add(mech);
            }
            singleOperationSignVerifyMechanisms = mechanisms;
        }

        boolean contained = singleOperationSignVerifyMechanisms.contains(
                new Long(mechanismCode));
        if (!contained) {
            contained = PKCS11VendorConstants
                    .isSingleOperationSignVerifyMechanism(mechanismCode);
        }
        return contained;
    }

    /**
     * This method checks, if the mechanism with the given code is a sign/verify
     * mechanism with message recovery.
     * If Returns true, the mechanism can be used with the
     * signRecover and verifyRecover functions.
     *
     * @param mechanismCode
     *          The code of the mechanism to check.
     * @return True, if the provided mechanism is a sign/verify mechanism with
     *         message recovery. False, otherwise.
     * @preconditions
     * @postconditions
     */
    public static boolean isSignVerifyRecoverMechanism(long mechanismCode) {
        // build the hashtable on demand (=first use)
        if (signVerifyRecoverMechanisms == null) {
            long[] mechs = new long[]{
                PKCS11Constants.CKM_RSA_PKCS,
                PKCS11Constants.CKM_RSA_9796,
                PKCS11Constants.CKM_RSA_X_509,
                PKCS11Constants.CKM_CMS_SIG,
                PKCS11Constants.CKM_SEED_ECB,
                PKCS11Constants.CKM_SEED_CBC,
                PKCS11Constants.CKM_SEED_MAC_GENERAL
            };

            Set<Long> mechanisms = new HashSet<>();
            for (Long mech : mechs) {
                mechanisms.add(mech);
            }
            signVerifyRecoverMechanisms = mechanisms;
        }

        boolean contained = signVerifyRecoverMechanisms.contains(
                new Long(mechanismCode));
        if (!contained) {
            contained = PKCS11VendorConstants.isSignVerifyRecoverMechanism(
                    mechanismCode);
        }
        return contained;
    }

    /**
     * This method checks, if the mechanism with the given code is a digest
     * mechanism.
     * If Returns true, the mechanism can be used with the digest
     * functions.
     *
     * @param mechanismCode
     *          The code of the mechanism to check.
     * @return True, if the provided mechanism is a digest mechanism. False,
     *         otherwise.
     * @preconditions
     * @postconditions
     */
    public static boolean isDigestMechanism(long mechanismCode) {
        // build the hashtable on demand (=first use)
        if (digestMechanisms == null) {
            long[] mechs = new long[]{
                PKCS11Constants.CKM_SHA_1,
                PKCS11Constants.CKM_SHA224,
                PKCS11Constants.CKM_SHA256,
                PKCS11Constants.CKM_SHA384,
                PKCS11Constants.CKM_SHA512,
                PKCS11Constants.CKM_SHA512_224,
                PKCS11Constants.CKM_SHA512_256,
                PKCS11Constants.CKM_SHA512_T,
                PKCS11Constants.CKM_SEED_MAC,
                PKCS11Constants.CKM_GOSTR3411,
                PKCS11Constants.CKM_SHA3_224,
                PKCS11Constants.CKM_SHA3_256,
                PKCS11Constants.CKM_SHA3_384,
                PKCS11Constants.CKM_SHA3_512,
                PKCS11Constants.CKM_MD2,
                PKCS11Constants.CKM_MD5,
                PKCS11Constants.CKM_RIPEMD128,
                PKCS11Constants.CKM_RIPEMD160,
            };

            Set<Long> mechanisms = new HashSet<>();
            for (Long mech : mechs) {
                mechanisms.add(mech);
            }
            digestMechanisms = mechanisms;
        }

        boolean contained = digestMechanisms.contains(new Long(mechanismCode));
        if (!contained) {
            contained = PKCS11VendorConstants.isDigestMechanism(mechanismCode);
        }
        return contained;
    }

    /**
     * This method checks, if the mechanism with the given code is a key
     * generation mechanism for generating symmetric keys.
     * If Returns true, the mechanism can be used with the
     * generateKey function.
     *
     * @param mechanismCode
     *          The code of the mechanism to check.
     * @return True, if the provided mechanism is a key generation mechanism.
     *         False, otherwise.
     * @preconditions
     * @postconditions
     */
    public static boolean isKeyGenerationMechanism(long mechanismCode) {
        // build the hashtable on demand (=first use)
        if (keyGenerationMechanisms == null) {
            long[] mechs = new long[]{
                PKCS11Constants.CKM_DSA_PARAMETER_GEN,
                PKCS11Constants.CKM_DSA_PROBABLISTIC_PARAMETER_GEN,
                PKCS11Constants.CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN,
                //PKCS11Constants.CKM_DSA_FIPS_G_GEN,
                PKCS11Constants.CKM_DH_PKCS_PARAMETER_GEN,
                PKCS11Constants.CKM_X9_42_DH_PARAMETER_GEN,
                PKCS11Constants.CKM_GENERIC_SECRET_KEY_GEN,
                PKCS11Constants.CKM_AES_KEY_GEN,
                PKCS11Constants.CKM_DES2_KEY_GEN,
                PKCS11Constants.CKM_DES3_KEY_GEN,
                PKCS11Constants.CKM_PBE_SHA1_DES3_EDE_CBC,
                PKCS11Constants.CKM_PBE_SHA1_DES2_EDE_CBC,
                PKCS11Constants.CKM_PBA_SHA1_WITH_SHA1_HMAC,
                PKCS11Constants.CKM_PKCS5_PBKD2,
                PKCS11Constants.CKM_SSL3_PRE_MASTER_KEY_GEN,
                PKCS11Constants.CKM_WTLS_PRE_MASTER_KEY_GEN,
                PKCS11Constants.CKM_CAMELLIA_KEY_GEN,
                PKCS11Constants.CKM_ARIA_KEY_GEN,
                PKCS11Constants.CKM_SEED_KEY_GEN,
                PKCS11Constants.CKM_SECURID_KEY_GEN,
                PKCS11Constants.CKM_HOTP_KEY_GEN,
                PKCS11Constants.CKM_ACTI_KEY_GEN,
                PKCS11Constants.CKM_GOST28147_KEY_GEN
            };

            Set<Long> mechanisms = new HashSet<>();
            for (Long mech : mechs) {
                mechanisms.add(mech);
            }
            keyGenerationMechanisms = mechanisms;
        }

        boolean contained = keyGenerationMechanisms.contains(
                new Long(mechanismCode));
        if (!contained) {
            contained = PKCS11VendorConstants.isKeyGenerationMechanism(
                    mechanismCode);
        }
        return contained;
    }

    /**
     * This method checks, if the mechanism with the given code is a key-pair
     * generation mechanism for generating key-pairs.
     * If Returns true, the mechanism can be used with the
     * generateKeyPair function.
     *
     * @param mechanismCode
     *          The code of the mechanism to check.
     * @return True, if the provided mechanism is a key-pair generation
     *         mechanism. False, otherwise.
     * @preconditions
     * @postconditions
     */
    public static boolean isKeyPairGenerationMechanism(long mechanismCode) {
        // build the hashtable on demand (=first use)
        if (keyPairGenerationMechanisms == null) {
            long[] mechs = new long[]{
                PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN,
                PKCS11Constants.CKM_RSA_X9_31_KEY_PAIR_GEN,
                PKCS11Constants.CKM_DSA_KEY_PAIR_GEN,
                PKCS11Constants.CKM_EC_KEY_PAIR_GEN,
                PKCS11Constants.CKM_DH_PKCS_KEY_PAIR_GEN,
                PKCS11Constants.CKM_X9_42_DH_KEY_PAIR_GEN,
                PKCS11Constants.CKM_GOSTR3410_KEY_PAIR_GEN
            };

            Set<Long> mechanisms = new HashSet<>();
            for (Long mech : mechs) {
                mechanisms.add(mech);
            }
            keyPairGenerationMechanisms = mechanisms;
        }

        boolean contained = keyPairGenerationMechanisms.contains(
                new Long(mechanismCode));
        if (!contained) {
            contained = PKCS11VendorConstants.isKeyPairGenerationMechanism(
                    mechanismCode);
        }
        return contained;
    }

    /**
     * This method checks, if the mechanism with the given code is a
     * wrap/unwrap mechanism; i.e. it supports the wrapKey()
     * and unwrapKey() functions.
     * If Returns true, the mechanism can be used with the wrapKey
     * and unwrapKey functions.
     *
     * @param mechanismCode
     *          The code of the mechanism to check.
     * @return True, if the provided mechanism is a wrap/unwrap mechanism.
     *         False, otherwise.
     * @preconditions
     * @postconditions
     */
    public static boolean isWrapUnwrapMechanism(long mechanismCode) {
        // build the hashtable on demand (=first use)
        if (wrapUnwrapMechanisms == null) {
            long[] mechs = new long[] {
                PKCS11Constants.CKM_RSA_PKCS,
                PKCS11Constants.CKM_RSA_PKCS_OAEP,
                PKCS11Constants.CKM_RSA_X_509,
                PKCS11Constants.CKM_RSA_PKCS_TPM_1_1,
                PKCS11Constants.CKM_RSA_PKCS_OAEP_TPM_1_1,
                PKCS11Constants.CKM_ECDH_AES_KEY_WRAP,
                PKCS11Constants.CKM_AES_ECB,
                PKCS11Constants.CKM_AES_CBC,
                PKCS11Constants.CKM_AES_CBC_PAD,
                PKCS11Constants.CKM_AES_OFB,
                PKCS11Constants.CKM_AES_CFB64,
                PKCS11Constants.CKM_AES_CFB8,
                PKCS11Constants.CKM_AES_CFB128,
                PKCS11Constants.CKM_AES_CFB1,
                PKCS11Constants.CKM_AES_CTR,
                PKCS11Constants.CKM_AES_CTS,
                PKCS11Constants.CKM_AES_GCM,
                PKCS11Constants.CKM_AES_CCM,
                PKCS11Constants.CKM_AES_KEY_WRAP,
                PKCS11Constants.CKM_DES3_ECB,
                PKCS11Constants.CKM_DES3_CBC,
                PKCS11Constants.CKM_DES3_CBC_PAD,
                PKCS11Constants.CKM_BLOWFISH_CBC,
                PKCS11Constants.CKM_BLOWFISH_CBC_PAD,
                PKCS11Constants.CKM_CAMELLIA_ECB,
                PKCS11Constants.CKM_CAMELLIA_CBC,
                PKCS11Constants.CKM_CAMELLIA_CBC_PAD,
                PKCS11Constants.CKM_ARIA_ECB,
                PKCS11Constants.CKM_ARIA_CBC,
                PKCS11Constants.CKM_ARIA_CBC_PAD,
                PKCS11Constants.CKM_SEED_CBC_PAD,
                PKCS11Constants.CKM_KIP_WRAP,
                PKCS11Constants.CKM_GOST28147_ECB,
                PKCS11Constants.CKM_GOST28147,
                PKCS11Constants.CKM_GOST28147_KEY_WRAP,
                PKCS11Constants.CKM_GOSTR3410_KEY_WRAP
            };
            Set<Long> wrapUnwrapMechs = new HashSet<>();
            for (long m : mechs) {
                wrapUnwrapMechs.add(m);
            }
            wrapUnwrapMechanisms = wrapUnwrapMechs;
        }

        boolean contained = wrapUnwrapMechanisms.contains(mechanismCode);
        if (!contained) {
            contained = PKCS11VendorConstants.isWrapUnwrapMechanism(
                    mechanismCode);
        }
        return contained;
    }

    /**
     * This method checks, if the mechanism with the given code is a key
     * derivation mechanism.
     * If Returns true, the mechanism can be used with the deriveKey
     * function.
     *
     * @param mechanismCode
     *          The code of the mechanism to check.
     * @return True, if the provided mechanism is a key derivation mechanism.
     *         False, otherwise.
     * @preconditions
     * @postconditions
     */
    public static boolean isKeyDerivationMechanism(long mechanismCode) {
        // build the hashtable on demand (=first use)
        if (keyDerivationMechanisms == null) {
            long[] mechs = new long[]{
                PKCS11Constants.CKM_ECDH1_DERIVE,
                PKCS11Constants.CKM_ECDH1_COFACTOR_DERIVE,
                PKCS11Constants.CKM_ECMQV_DERIVE,
                PKCS11Constants.CKM_DH_PKCS_DERIVE,
                PKCS11Constants.CKM_X9_42_DH_DERIVE,
                PKCS11Constants.CKM_X9_42_DH_HYBRID_DERIVE,
                PKCS11Constants.CKM_X9_42_MQV_DERIVE,
                PKCS11Constants.CKM_AES_GMAC,
                PKCS11Constants.CKM_DES_ECB_ENCRYPT_DATA,
                PKCS11Constants.CKM_DES_CBC_ENCRYPT_DATA,
                PKCS11Constants.CKM_DES3_ECB_ENCRYPT_DATA,
                PKCS11Constants.CKM_DES3_CBC_ENCRYPT_DATA,
                PKCS11Constants.CKM_AES_ECB_ENCRYPT_DATA,
                PKCS11Constants.CKM_AES_CBC_ENCRYPT_DATA,
                PKCS11Constants.CKM_SHA1_KEY_DERIVATION,
                PKCS11Constants.CKM_SHA224_KEY_DERIVATION,
                PKCS11Constants.CKM_SHA256_KEY_DERIVATION,
                PKCS11Constants.CKM_SHA384_KEY_DERIVATION,
                PKCS11Constants.CKM_SHA512_KEY_DERIVATION,
                PKCS11Constants.CKM_SHA512_224_KEY_DERIVATION,
                PKCS11Constants.CKM_SHA512_256_KEY_DERIVATION,
                PKCS11Constants.CKM_SHA512_T_KEY_DERIVATION,
                PKCS11Constants.CKM_SSL3_MASTER_KEY_DERIVE,
                PKCS11Constants.CKM_SSL3_MASTER_KEY_DERIVE_DH,
                PKCS11Constants.CKM_SSL3_KEY_AND_MAC_DERIVE,
                PKCS11Constants.CKM_TLS12_MASTER_KEY_DERIVE,
                PKCS11Constants.CKM_TLS12_MASTER_KEY_DERIVE_DH,
                PKCS11Constants.CKM_TLS12_KEY_AND_MAC_DERIVE,
                PKCS11Constants.CKM_TLS12_KEY_SAFE_DERIVE,
                PKCS11Constants.CKM_TLS_KDF,
                PKCS11Constants.CKM_WTLS_MASTER_KEY_DERIVE,
                PKCS11Constants.CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC,
                PKCS11Constants.CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
                PKCS11Constants.CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE,
                PKCS11Constants.CKM_WTLS_PRF,
                PKCS11Constants.CKM_CONCATENATE_BASE_AND_KEY,
                PKCS11Constants.CKM_CONCATENATE_BASE_AND_DATA,
                PKCS11Constants.CKM_CONCATENATE_DATA_AND_BASE,
                PKCS11Constants.CKM_XOR_BASE_AND_DATA,
                PKCS11Constants.CKM_EXTRACT_KEY_FROM_KEY,
                PKCS11Constants.CKM_CAMELLIA_ECB_ENCRYPT_DATA,
                PKCS11Constants.CKM_CAMELLIA_CBC_ENCRYPT_DATA,
                PKCS11Constants.CKM_ARIA_ECB_ENCRYPT_DATA,
                PKCS11Constants.CKM_ARIA_CBC_ENCRYPT_DATA,
                PKCS11Constants.CKM_SEED_ECB_ENCRYPT_DATA,
                PKCS11Constants.CKM_SEED_CBC_ENCRYPT_DATA,
                PKCS11Constants.CKM_KIP_DERIVE,
                PKCS11Constants.CKM_GOSTR3410_DERIVE,
                PKCS11Constants.CKM_SHA3_224_KEY_DERIVE,
                PKCS11Constants.CKM_SHA3_256_KEY_DERIVE,
                PKCS11Constants.CKM_SHA3_384_KEY_DERIVE,
                PKCS11Constants.CKM_SHA3_512_KEY_DERIVE,
                PKCS11Constants.CKM_SHAKE_128_KEY_DERIVE,
                PKCS11Constants.CKM_SHAKE_256_KEY_DERIVE,
                PKCS11Constants.CKM_SHA256_KEY_DERIVATION,
                PKCS11Constants.CKM_SHA256_KEY_DERIVATION,
                PKCS11Constants.CKM_SHA256_KEY_DERIVATION,
                PKCS11Constants.CKM_SHA256_KEY_DERIVATION
            };

            Set<Long> mechanisms = new HashSet<>();
            for (Long mech : mechs) {
                mechanisms.add(mech);
            }
            keyDerivationMechanisms = mechanisms;
        }

        boolean contained = keyDerivationMechanisms.contains(
                new Long(mechanismCode));
        if (!contained) {
            contained = PKCS11VendorConstants.isKeyDerivationMechanism(
                    mechanismCode);
        }
        return contained;

    }

}
