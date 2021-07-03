package iaik.pkcs.pkcs11;

public interface VendorCodeConverter {

    // CKK
    long CKK_VENDOR_SM2                  = 0xFFFFF001L;
    long CKK_VENDOR_SM4                  = 0xFFFFF002L;

    // CKM
    long CKM_VENDOR_SM2_KEY_PAIR_GEN     = 0xFFFFF001L;
    long CKM_VENDOR_SM2                  = 0xFFFFF002L;
    long CKM_VENDOR_SM2_SM3              = 0xFFFFF003L;
    long CKM_VENDOR_SM2_ENCRYPT          = 0xFFFFF004L;
    long CKM_VENDOR_SM3                  = 0xFFFFF005L;
    long CKM_VENDOR_SM4_KEY_GEN          = 0xFFFFF006L;
    long CKM_VENDOR_SM4_ECB              = 0xFFFFF007L;
    long CKM_VENDOR_SM4_CBC              = 0xFFFFF008L;
    long CKM_VENDOR_SM4_MAC_GENERAL      = 0xFFFFF009L;
    long CKM_VENDOR_SM4_MAC              = 0xFFFFF00AL;
    long CKM_VENDOR_ISO2_SM4_MAC_GENERAL = 0xFFFFF00BL;
    long CKM_VENDOR_ISO2_SM4_MAC         = 0xFFFFF00CL;
    long CKM_VENDOR_SM4_ECB_ENCRYPT_DATA = 0xFFFFF00DL;

    /**
     * Convert the generic CKK code to vendor specific one.
     * @param ckk the generic CKK code.
     * @return the vendor specific CKK code
     */
    long genericToVendorCKK(long ckk);

    /**
     * Convert the vendor specific CKK code to generic one.
     * @param ckk the vencor specfic CKK code.
     * @return the generic CKK code
     */
    long vendorToGenericCKK(long ckk);

    /**
     * Convert the generic CKM code to vendor specific CKM one.
     * @param ckm the generic CKM code.
     * @return the vendor specific CKM code
     */
    long genericToVendorCKM(long ckm);

    /**
     * Convert the vendor specific CKM value to the generic one.
     * @param ckm the vendor specific CKM code.
     * @return the generic CKM code
     */
    long vendorToGenericCKM(long ckm);

}
