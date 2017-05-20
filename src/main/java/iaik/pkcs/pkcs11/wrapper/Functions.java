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

import java.math.BigInteger;
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
 * @author Karl Scheibelhofer <Karl.Scheibelhofer@iaik.at>
 * @author Martin Schlaeffer <schlaeff@sbox.tugraz.at>
 */
@SuppressWarnings("restriction")
public class Functions {

    /**
     * The name of the properties file that holds the names of the PKCS#11
     * mechanism-codes.
     */
    private static final String CKM_CODE_PROPERTIES
            = "iaik/pkcs/pkcs11/wrapper/ckm.properties";

    /**
     * True, if the mapping of mechanism codes to PKCS#11 mechanism names is
     * available.
     */
    private static boolean mechanismCodeNamesAvailable_;

    /**
     * Maps mechanism codes as Long to their names as Strings.
     */
    private static Map<Long, String> mechanismNames_;

    /**
     * Maps mechanism name as String to their code as Long.
     */
    private static Map<String, Long> mechanismNameToCodes_;

    /**
     * This set contains the mechanisms that are full encrypt/decrypt
     * mechanisms; i.e. mechanisms that support the update functions.
     */
    private static Set<Long> fullEncryptDecryptMechanisms_;

    /**
     * This set contains the mechanisms that are single-operation
     * encrypt/decrypt mechanisms; i.e. mechanisms that do not support the
     * update functions.
     */
    private static Set<Long> singleOperationEncryptDecryptMechanisms_;

    /**
     * This set contains the mechanisms that are full sign/verify
     * mechanisms; i.e. mechanisms that support the update functions.
     */
    private static Set<Long> fullSignVerifyMechanisms_;

    /**
     * This set contains the mechanisms that are single-operation
     * sign/verify mechanisms; i.e. mechanisms that do not support the update
     * functions.
     */
    private static Set<Long> singleOperationSignVerifyMechanisms_;

    /**
     * This table contains the mechanisms that are sign/verify mechanisms with
     * message recovery.
     */
    private static Set<Long> signVerifyRecoverMechanisms_;

    /**
     * This set contains the mechanisms that are digest mechanisms.
     * The Long values of the mechanisms are the keys, and the mechanism
     * names are the values.
     */
    private static Set<Long> digestMechanisms_;

    /**
     * This table contains the mechanisms that key generation mechanisms; i.e.
     * mechanisms for generating symmetric keys.
     */
    private static Set<Long> keyGenerationMechanisms_;

    /**
     * This table contains the mechanisms that key-pair generation mechanisms;
     * i.e. mechanisms for generating key-pairs.
     */
    private static Set<Long> keyPairGenerationMechanisms_;

    /**
     * This table contains the mechanisms that are wrap/unwrap mechanisms.
     */
    private static Set<Long> wrapUnwrapMechanisms_;

    /**
     * This table contains the mechanisms that are key derivation mechanisms.
     */
    private static Set<Long> keyDerivationMechanisms_;

    /**
     * For converting numbers to their hex presentation.
     */
    private static final char HEX_DIGITS[] = {
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
     * Converts an int value to a hexadecimal String of length 8. Includes
     * leading zeros if necessary.
     *
     * @param value
     *         The int value to be converted.
     * @return The hexadecimal string representation of the int value.
     */
    public static String toFullHexString(int value) {
        int currentValue = value;
        StringBuilder stringBuffer = new StringBuilder(8);
        for (int i = 0; i < 8; i++) {
            int currentDigit = currentValue & 0xf;
            stringBuffer.append(HEX_DIGITS[currentDigit]);
            currentValue >>>= 4;
        }

        return stringBuffer.reverse().toString();
    }

    /**
     * Converts a long value to a hexadecimal String.
     *
     * @param value
     *          The long value to be converted.
     * @return The hexadecimal string representation of the long value.
     */
    public static String toHexString(long value) {
        return Long.toHexString(value);
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
     * Converts a long value to a binary String.
     *
     * @param value
     *          The long value to be converted.
     * @return the binary string representation of the long value.
     */
    public static String toBinaryString(long value) {
        return Long.toString(value, 2);
    }

    /**
     * Converts a byte array to a binary String.
     *
     * @param value
     *          The byte array to be converted.
     * @return The binary string representation of the byte array.
     */
    public static String toBinaryString(byte[] value) {
        BigInteger helpBigInteger = new BigInteger(1, value);

        return helpBigInteger.toString(2);
    }

    /**
     * Converts the long value flags to a SlotInfoFlag string.
     *
     * @param flags
     *          The flags to be converted.
     * @return The SlotInfoFlag string representation of the flags.
     */
    public static String slotInfoFlagsToString(long flags) {
        StringBuilder buffer = new StringBuilder();
        boolean notFirst = false;

        if ((flags & PKCS11Constants.CKF_TOKEN_PRESENT) != 0L) {
            buffer.append("CKF_TOKEN_PRESENT");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_REMOVABLE_DEVICE) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_TOKEN_PRESENT");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_HW_SLOT) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_HW_SLOT");
        }

        return buffer.toString();
    }

    /**
     * Converts long value flags to a TokenInfoFlag string.
     *
     * @param flags
     *          The flags to be converted.
     * @return The TokenInfoFlag string representation of the flags.
     */
    public static String tokenInfoFlagsToString(long flags) {
        StringBuilder buffer = new StringBuilder();
        boolean notFirst = false;

        if ((flags & PKCS11Constants.CKF_RNG) != 0L) {
            buffer.append("CKF_RNG");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_WRITE_PROTECTED) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_WRITE_PROTECTED");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_LOGIN_REQUIRED) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_LOGIN_REQUIRED");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_USER_PIN_INITIALIZED) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_USER_PIN_INITIALIZED");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_RESTORE_KEY_NOT_NEEDED) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_RESTORE_KEY_NOT_NEEDED");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_CLOCK_ON_TOKEN) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_CLOCK_ON_TOKEN");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_PROTECTED_AUTHENTICATION_PATH) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_PROTECTED_AUTHENTICATION_PATH");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_DUAL_CRYPTO_OPERATIONS) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_DUAL_CRYPTO_OPERATIONS");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_TOKEN_INITIALIZED) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_TOKEN_INITIALIZED");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_SECONDARY_AUTHENTICATION) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_SECONDARY_AUTHENTICATION");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_USER_PIN_COUNT_LOW) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_USER_PIN_COUNT_LOW");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_USER_PIN_FINAL_TRY) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_USER_PIN_FINAL_TRY");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_USER_PIN_LOCKED) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_USER_PIN_LOCKED");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_USER_PIN_TO_BE_CHANGED) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_USER_PIN_TO_BE_CHANGED");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_SO_PIN_COUNT_LOW) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_SO_PIN_COUNT_LOW");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_SO_PIN_FINAL_TRY) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_SO_PIN_FINAL_TRY");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_SO_PIN_LOCKED) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_USER_PIN_FINAL_TRY");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_SO_PIN_TO_BE_CHANGED) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_USER_PIN_LOCKED");

            notFirst = true;
        }

        return buffer.toString();
    }

    /**
     * Converts the long value flags to a SessionInfoFlag string.
     *
     * @param flags
     *          The flags to be converted.
     * @return The SessionInfoFlag string representation of the flags.
     */
    public static String sessionInfoFlagsToString(long flags) {
        StringBuilder buffer = new StringBuilder();
        boolean notFirst = false;

        if ((flags & PKCS11Constants.CKF_RW_SESSION) != 0L) {
            buffer.append("CKF_RW_SESSION");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_SERIAL_SESSION) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_SERIAL_SESSION");
        }

        return buffer.toString();
    }

    /**
     * Converts the long value state to a SessionState string.
     *
     * @param state
     *          The state to be converted.
     * @return The SessionState string representation of the state.
     */
    public static String sessionStateToString(long state) {
        String name;

        if (state == PKCS11Constants.CKS_RO_PUBLIC_SESSION) {
            name = "CKS_RO_PUBLIC_SESSION";
        } else if (state == PKCS11Constants.CKS_RO_USER_FUNCTIONS) {
            name = "CKS_RO_USER_FUNCTIONS";
        } else if (state == PKCS11Constants.CKS_RW_PUBLIC_SESSION) {
            name = "CKS_RW_PUBLIC_SESSION";
        } else if (state == PKCS11Constants.CKS_RW_USER_FUNCTIONS) {
            name = "CKS_RW_USER_FUNCTIONS";
        } else if (state == PKCS11Constants.CKS_RW_SO_FUNCTIONS) {
            name = "CKS_RW_SO_FUNCTIONS";
        } else {
            name = "ERROR: unknown session state 0x" + toFullHexString(state);
        }

        return name;
    }

    /**
     * Converts the long value flags to a MechanismInfoFlag string.
     *
     * @param flags
     *          The flags to be converted to a string representation.
     * @return The MechanismInfoFlag string representation of the flags.
     */
    public static String mechanismInfoFlagsToString(long flags) {
        StringBuilder buffer = new StringBuilder();
        boolean notFirst = false;

        if ((flags & PKCS11Constants.CKF_HW) != 0L) {
            buffer.append("CKF_HW");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_ENCRYPT) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_ENCRYPT");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_DECRYPT) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_DECRYPT");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_DIGEST) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_DIGEST");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_SIGN) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_SIGN");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_SIGN_RECOVER) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_SIGN_RECOVER");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_VERIFY) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_VERIFY");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_VERIFY_RECOVER) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_VERIFY_RECOVER");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_GENERATE) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_GENERATE");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_GENERATE_KEY_PAIR) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_GENERATE_KEY_PAIR");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_WRAP) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_WRAP");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_UNWRAP) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_UNWRAP");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_DERIVE) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_DERIVE");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_EC_F_P) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_EC_F_P");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_EC_F_2M) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_EC_F_2M");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_EC_ECPARAMETERS) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_EC_ECPARAMETERS");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_EC_NAMEDCURVE) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_EC_NAMEDCURVE");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_EC_UNCOMPRESS) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_EC_UNCOMPRESS");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_EC_COMPRESS) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_EC_COMPRESS");

            notFirst = true;
        }

        if ((flags & PKCS11Constants.CKF_EXTENSION) != 0L) {
            if (notFirst) {
                buffer.append(" | ");
            }

            buffer.append("CKF_EXTENSION");

            notFirst = true;
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
        String name = mechanismCodeNamesAvailable_
                ? mechanismNames_.get(new Long(mechanismCode)) : null;
        if (name == null) {
            name = "Unknwon mechanism with code: 0x"
                    + toFullHexString(mechanismCode);
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
        Long code = mechanismCodeNamesAvailable_
                ? mechanismNameToCodes_.get(mechanismName) : null;
        return (code != null) ? code : -1;
    }

    private static void initMechanismMap() {
        // ensure that another thread has not loaded the codes meanwhile
        if (mechanismNames_ != null) {
            return;
        }

        // if the names of the defined error codes are not yet loaded, load them
        Map<Long, String> codeNameMap = new HashMap<>();
        Map<String, Long> nameCodeMap = new HashMap<>();

        Properties props = new Properties();
        try {
            props.load(Functions.class.getClassLoader().getResourceAsStream(
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
                nameCodeMap.put(mainMechName, code);

                if (tokens.hasMoreTokens()) {
                    nameCodeMap.put(tokens.nextToken(), code);
                }
            }
            mechanismNames_ = codeNameMap;
            mechanismNameToCodes_ = nameCodeMap;
            mechanismCodeNamesAvailable_ = true;
        } catch (Exception exception) {
            System.err.println(
                "Could not read properties for error code names: "
                + exception.getMessage());
        }
    }

    /**
     * Converts the long value classType to a string representation of it.
     *
     * @param classType
     *          The classType to be converted.
     * @return The string representation of the classType.
     */
    public static String classTypeToString(long classType) {
        String name;

        if (classType == PKCS11Constants.CKO_DATA) {
            name = "CKO_DATA";
        } else if (classType == PKCS11Constants.CKO_CERTIFICATE) {
            name = "CKO_CERTIFICATE";
        } else if (classType == PKCS11Constants.CKO_PUBLIC_KEY) {
            name = "CKO_PUBLIC_KEY";
        } else if (classType == PKCS11Constants.CKO_PRIVATE_KEY) {
            name = "CKO_PRIVATE_KEY";
        } else if (classType == PKCS11Constants.CKO_SECRET_KEY) {
            name = "CKO_SECRET_KEY";
        } else if (classType == PKCS11Constants.CKO_HW_FEATURE) {
            name = "CKO_HW_FEATURE";
        } else if (classType == PKCS11Constants.CKO_DOMAIN_PARAMETERS) {
            name = "CKO_DOMAIN_PARAMETERS";
        } else if (classType == PKCS11Constants.CKO_VENDOR_DEFINED) {
            name = "CKO_VENDOR_DEFINED";
        } else {
            name = "ERROR: unknown classType with code: 0x"
                    + toFullHexString(classType);
        }

        return name;
    }

    /**
     * Check the given arrays for equality. This method considers both arrays as
     * equal, if both are <code>null</code> or both have the same length and
     * contain exactly the same byte values.
     *
     * @param array1
     *          The first array.
     * @param array2
     *          The second array.
     * @return True, if both arrays are <code>null</code> or both have the same
     *         length and contain exactly the same byte values. False,
     *         otherwise.
     * @preconditions
     * @postconditions
     */
    public static boolean equals(byte[] array1, byte[] array2) {
        boolean equal = false;

        if (array1 == array2) {
            equal = true;
        } else if ((array1 != null) && (array2 != null)) {
            int length = array1.length;
            if (length == array2.length) {
                equal = true;
                for (int i = 0; i < length; i++) {
                    if (array1[i] != array2[i]) {
                        equal = false;
                        break;
                    }
                }
            } else {
                equal = false;
            }
        } else {
            equal = false;
        }

        return equal;
    }

    /**
     * Check the given arrays for equality. This method considers both arrays as
     * equal, if both are <code>null</code> or both have the same length and
     * contain exactly the same char values.
     *
     * @param array1
     *          The first array.
     * @param array2
     *          The second array.
     * @return True, if both arrays are <code>null</code> or both have the same
     *         length and contain exactly the same char values. False,
     *         otherwise.
     * @preconditions
     * @postconditions
     */
    public static boolean equals(char[] array1, char[] array2) {
        boolean equal = false;

        if (array1 == array2) {
            equal = true;
        } else if ((array1 != null) && (array2 != null)) {
            int length = array1.length;
            if (length == array2.length) {
                equal = true;
                for (int i = 0; i < length; i++) {
                    if (array1[i] != array2[i]) {
                        equal = false;
                        break;
                    }
                }
            } else {
                equal = false;
            }
        } else {
            equal = false;
        }

        return equal;
    }

    /**
     * Check the given arrays for equality. This method considers both arrays as
     * equal, if both are <code>null</code> or both have the same length and
     * contain exactly the same byte values.
     *
     * @param array1
     *          The first array.
     * @param array2
     *          The second array.
     * @return True, if both arrays are <code>null</code> or both have the same
     *         length and contain exactly the same byte values. False,
     *         otherwise.
     * @preconditions
     * @postconditions
     */
    public static boolean equals(long[] array1, long[] array2) {
        boolean equal = false;

        if (array1 == array2) {
            equal = true;
        } else if ((array1 != null) && (array2 != null)) {
            int length = array1.length;
            if (length == array2.length) {
                equal = true;
                for (int i = 0; i < length; i++) {
                    if (array1[i] != array2[i]) {
                        equal = false;
                        break;
                    }
                }
            } else {
                equal = false;
            }
        } else {
            equal = false;
        }

        return equal;
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
            equal = equals(date1.year, date2.year)
                    && equals(date1.month, date2.month)
                    && equals(date1.day, date2.day);
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
     * If this method returns true, the mechanism can be used with the encrypt
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
        if (fullEncryptDecryptMechanisms_ == null) {
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
            fullEncryptDecryptMechanisms_ = mechanisms;
        }

        return fullEncryptDecryptMechanisms_.contains(new Long(mechanismCode));
    }

    /**
     * This method checks, if the mechanism with the given code is a
     * single-operation encrypt/decrypt mechanism; i.e. it does not support the
     * encryptUpdate() and decryptUpdate() functions.
     * If this method returns true, the mechanism can be used with the encrypt
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
        if (singleOperationEncryptDecryptMechanisms_ == null) {
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
            singleOperationEncryptDecryptMechanisms_ = mechanisms;
        }

        return singleOperationEncryptDecryptMechanisms_.contains(
                new Long(mechanismCode));
    }

    /**
     * This method checks, if the mechanism with the given code is a full
     * sign/verify mechanism; i.e. it supports the signUpdate()
     * and verifyUpdate() functions.
     * If this method returns true, the mechanism can be used with the sign and
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
        if (fullSignVerifyMechanisms_ == null) {
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
            fullSignVerifyMechanisms_ = mechanisms;
        }

        return fullSignVerifyMechanisms_.contains(new Long(mechanismCode));
    }

    /**
     * This method checks, if the mechanism with the given code is a
     * single-operation sign/verify mechanism; i.e. it does not support the
     * signUpdate() and encryptUpdate() functions.
     * If this method returns true, the mechanism can be used with the sign and
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
        if (singleOperationSignVerifyMechanisms_ == null) {
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
            singleOperationSignVerifyMechanisms_ = mechanisms;
        }

        return singleOperationSignVerifyMechanisms_.contains(
                new Long(mechanismCode));
    }

    /**
     * This method checks, if the mechanism with the given code is a sign/verify
     * mechanism with message recovery.
     * If this method returns true, the mechanism can be used with the
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
        if (signVerifyRecoverMechanisms_ == null) {
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
            signVerifyRecoverMechanisms_ = mechanisms;
        }

        return signVerifyRecoverMechanisms_.contains(new Long(mechanismCode));
    }

    /**
     * This method checks, if the mechanism with the given code is a digest
     * mechanism.
     * If this method returns true, the mechanism can be used with the digest
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
        if (digestMechanisms_ == null) {
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
            digestMechanisms_ = mechanisms;
        }

        return digestMechanisms_.contains(new Long(mechanismCode));
    }

    /**
     * This method checks, if the mechanism with the given code is a key
     * generation mechanism for generating symmetric keys.
     * If this method returns true, the mechanism can be used with the
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
        if (keyGenerationMechanisms_ == null) {
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
            keyGenerationMechanisms_ = mechanisms;
        }

        return keyGenerationMechanisms_.contains(new Long(mechanismCode));
    }

    /**
     * This method checks, if the mechanism with the given code is a key-pair
     * generation mechanism for generating key-pairs.
     * If this method returns true, the mechanism can be used with the
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
        if (keyPairGenerationMechanisms_ == null) {
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
            keyPairGenerationMechanisms_ = mechanisms;
        }

        return keyPairGenerationMechanisms_.contains(new Long(mechanismCode));
    }

    /**
     * This method checks, if the mechanism with the given code is a
     * wrap/unwrap mechanism; i.e. it supports the wrapKey()
     * and unwrapKey() functions.
     * If this method returns true, the mechanism can be used with the wrapKey
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
        if (wrapUnwrapMechanisms_ == null) {
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
            Set<Long> wrapUnwrapMechanisms = new HashSet<>();
            for (long m : mechs) {
                wrapUnwrapMechanisms.add(m);
            }
            wrapUnwrapMechanisms_ = wrapUnwrapMechanisms;
        }

        return wrapUnwrapMechanisms_.contains(mechanismCode);
    }

    /**
     * This method checks, if the mechanism with the given code is a key
     * derivation mechanism.
     * If this method returns true, the mechanism can be used with the deriveKey
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
        if (keyDerivationMechanisms_ == null) {
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
            keyDerivationMechanisms_ = mechanisms;
        }

        return keyDerivationMechanisms_.contains(new Long(mechanismCode));
    }

}
