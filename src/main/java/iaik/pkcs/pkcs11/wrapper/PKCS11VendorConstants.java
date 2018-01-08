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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * 
 * @author Lijun Liao
 * @version 1.4.1
 *
 */
// CHECKSTYLE:SKIP
public class PKCS11VendorConstants {

    public static final String CKM_VENDOR_VENDOR_CODE_PROPERTIES_FILE = 
                "pkcs11.ckm-vendor.file";

    private static final String CKM_VENDOR_VENDOR_CODE_PROPERTIES =
                "/iaik/pkcs/pkcs11/wrapper/ckm-vendor.properties";

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
     * This set contains the mechanisms that are full sign/verify
     * mechanisms; i.e. mechanisms that support the update functions.
     */
    private static Set<Long> fullSignVerifyMechanisms_;

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
        String file = 
                System.getProperty(CKM_VENDOR_VENDOR_CODE_PROPERTIES_FILE);
        
        InputStream is = null;
        if (file != null) {
            try {
                is = new FileInputStream(file);
            } catch (FileNotFoundException ex) {
                System.err.println("File " + file + " does not exist");
            } 
        } else {
            is = PKCS11VendorConstants.class.getResourceAsStream(
                    CKM_VENDOR_VENDOR_CODE_PROPERTIES);
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

    public static void main(String[] args) {
        new PKCS11VendorConstants();
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
        if (digestMechanisms_ == null) {
            long[] mechs = new long[]{
                PKCS11VendorConstants.CKM_VENDOR_SM3
            };

            Set<Long> mechanisms = new HashSet<>();
            for (Long mech : mechs) {
                mechanisms.add(mech);
            }
            digestMechanisms_ = mechanisms;
        }

        return digestMechanisms_.contains(new Long(mechanismCode));
    }

    public static boolean isFullEncryptDecryptMechanism(long mechanismCode) {
        // build the hashtable on demand (=first use)
        if (fullEncryptDecryptMechanisms_ == null) {
            long[] mechs = new long[]{
                PKCS11VendorConstants.CKM_VENDOR_SM4_CBC,
                PKCS11VendorConstants.CKM_VENDOR_SM4_ECB,
            };

            Set<Long> mechanisms = new HashSet<>();
            for (Long mech : mechs) {
                mechanisms.add(mech);
            }
            fullEncryptDecryptMechanisms_ = mechanisms;
        }

        return fullEncryptDecryptMechanisms_.contains(new Long(mechanismCode));
    }

    public static boolean isFullSignVerifyMechanism(long mechanismCode) {
        // build the hashtable on demand (=first use)
        if (fullSignVerifyMechanisms_ == null) {
            long[] mechs = new long[]{
                PKCS11VendorConstants.CKM_VENDOR_SM2,
                PKCS11VendorConstants.CKM_VENDOR_SM2_SM3,
                PKCS11VendorConstants.CKM_VENDOR_ISO2_SM4_MAC,
                PKCS11VendorConstants.CKM_VENDOR_SM4_MAC,
                PKCS11VendorConstants.CKM_VENDOR_SM4_MAC_GENERAL,
                PKCS11VendorConstants.CKM_VENDOR_ISO2_SM4_MAC,
                PKCS11VendorConstants.CKM_VENDOR_ISO2_SM4_MAC_GENERAL,
            };

            Set<Long> mechanisms = new HashSet<>();
            for (Long mech : mechs) {
                mechanisms.add(mech);
            }
            fullSignVerifyMechanisms_ = mechanisms;
        }

        return fullSignVerifyMechanisms_.contains(new Long(mechanismCode));
    }

    public static boolean isKeyDerivationMechanism(long mechanismCode) {
        // build the hashtable on demand (=first use)
        if (keyDerivationMechanisms_ == null) {
            long[] mechs = new long[]{
                PKCS11VendorConstants.CKM_VENDOR_SM4_ECB_ENCRYPT_DATA
            };

            Set<Long> mechanisms = new HashSet<>();
            for (Long mech : mechs) {
                mechanisms.add(mech);
            }
            keyDerivationMechanisms_ = mechanisms;
        }

        return keyDerivationMechanisms_.contains(new Long(mechanismCode));
    }

    public static boolean isKeyPairGenerationMechanism(long mechanismCode) {
        // build the hashtable on demand (=first use)
        if (keyPairGenerationMechanisms_ == null) {
            long[] mechs = new long[]{
                CKM_VENDOR_SM2_KEY_PAIR_GEN
            };

            Set<Long> mechanisms = new HashSet<>();
            for (Long mech : mechs) {
                mechanisms.add(mech);
            }
            keyPairGenerationMechanisms_ = mechanisms;
        }

        return keyPairGenerationMechanisms_.contains(new Long(mechanismCode));
    }
    
    public static boolean isKeyGenerationMechanism(long mechanismCode) {
        // build the hashtable on demand (=first use)
        if (keyGenerationMechanisms_ == null) {
            long[] mechs = new long[]{
                PKCS11VendorConstants.CKM_VENDOR_SM4_KEY_GEN
            };

            Set<Long> mechanisms = new HashSet<>();
            for (Long mech : mechs) {
                mechanisms.add(mech);
            }
            keyGenerationMechanisms_ = mechanisms;
        }

        return keyGenerationMechanisms_.contains(new Long(mechanismCode));
    } 

    public static boolean isSignVerifyRecoverMechanism(long mechanismCode) {
        return false;
    }

    public static boolean isSingleOperationEncryptDecryptMechanism(
            long mechanismCode) {
        return false;
    }
    
    public static boolean isSingleOperationSignVerifyMechanism(
            long mechanismCode) {
        return false;
    }
    
    public static boolean isWrapUnwrapMechanism(long mechanismCode) {
        // build the hashtable on demand (=first use)
        if (wrapUnwrapMechanisms_ == null) {
            long[] mechs = new long[] {
                PKCS11VendorConstants.CKM_VENDOR_SM2_ENCRYPT,
                PKCS11VendorConstants.CKM_VENDOR_SM4_ECB
            };
            Set<Long> wrapUnwrapMechanisms = new HashSet<>();
            for (long m : mechs) {
                wrapUnwrapMechanisms.add(m);
            }
            wrapUnwrapMechanisms_ = wrapUnwrapMechanisms;
        }

        return wrapUnwrapMechanisms_.contains(mechanismCode);
    }

    public static String mechanismCodeToString(long mechanismCode) {
        initMechanismMap();
        String name = mechanismCodeNamesAvailable_
                ? mechanismNames_.get(new Long(mechanismCode)) : null;
        if (name == null) {
            name = "Unknwon mechanism with code: 0x"
                    + Functions.toFullHexString(mechanismCode);
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
        
        long[] codes = new long[]{
            CKM_VENDOR_ISO2_SM4_MAC,
            CKM_VENDOR_ISO2_SM4_MAC_GENERAL,
            CKM_VENDOR_SM2,
            CKM_VENDOR_SM2_ENCRYPT,
            CKM_VENDOR_SM2_KEY_PAIR_GEN,
            CKM_VENDOR_SM2_SM3,
            CKM_VENDOR_SM3,
            CKM_VENDOR_SM4_CBC,
            CKM_VENDOR_SM4_ECB,
            CKM_VENDOR_SM4_ECB_ENCRYPT_DATA,
            CKM_VENDOR_SM4_KEY_GEN,
            CKM_VENDOR_SM4_MAC,
            CKM_VENDOR_SM4_MAC_GENERAL};

        String[] names = new String[]{
            "CKM_VENDOR_ISO2_SM4_MAC",
            "CKM_VENDOR_ISO2_SM4_MAC_GENERAL",
            "CKM_VENDOR_SM2",
            "CKM_VENDOR_SM2_ENCRYPT",
            "CKM_VENDOR_SM2_KEY_PAIR_GEN",
            "CKM_VENDOR_SM2_SM3",
            "CKM_VENDOR_SM3",
            "CKM_VENDOR_SM4",
            "CKM_VENDOR_SM4_CBC",
            "CKM_VENDOR_SM4_ECB",
            "CKM_VENDOR_SM4_ECB_ENCRYPT_DATA",
            "CKM_VENDOR_SM4_KEY_GEN",
            "CKM_VENDOR_SM4_MAC",
            "CKM_VENDOR_SM4_MAC_GENERAL"};

        for (int i = 0; i < codes.length; i++) {
            codeNameMap.put(codes[i], names[i]);
            nameCodeMap.put(names[i], codes[i]);
        }

        mechanismNames_ = codeNameMap;
        mechanismNameToCodes_ = nameCodeMap;
        mechanismCodeNamesAvailable_ = true;
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
