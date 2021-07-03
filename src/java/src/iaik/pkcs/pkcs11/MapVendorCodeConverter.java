package iaik.pkcs.pkcs11;

import iaik.pkcs.pkcs11.wrapper.Functions;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public class MapVendorCodeConverter implements VendorCodeConverter {

    private final Map<Long, Long> ckkGenericToVendorMap = new HashMap<>();

    private final Map<Long, Long> ckkVendorToGenericMap = new HashMap<>();

    private final Map<Long, Long> ckmGenericToVendorMap = new HashMap<>();

    private final Map<Long, Long> ckmVendorToGenericMap = new HashMap<>();

    public MapVendorCodeConverter(
            Map<Long, Long> ckkGenericToVendorMap,
            Map<Long, Long> ckmGenericToVendorMap) {
        copyMapIfNotNull(ckkGenericToVendorMap,
                this.ckkGenericToVendorMap, this.ckkVendorToGenericMap);
        copyMapIfNotNull(ckmGenericToVendorMap,
                this.ckmGenericToVendorMap, this.ckmVendorToGenericMap);
    }

    public static MapVendorCodeConverter getInstance(
            Map<String, String> nameToCodeMap) {
        Map<Long, Long> ckkGenericToVendor = new HashMap<>();
        Map<Long, Long> ckmGenericToVendor = new HashMap<>();

        for (String name : nameToCodeMap.keySet()) {
            String codeStr = nameToCodeMap.get(name);
            long vendorCode = toLong(codeStr);

            String uname = name.trim().toUpperCase(Locale.ROOT);
            if (uname.startsWith("CKK_VENDOR_")) {
                long genericCode;
                switch (uname) {
                    case "CKK_VENDOR_SM2":
                        genericCode = CKK_VENDOR_SM2;
                        break;
                    case "CKK_VENDOR_SM4":
                        genericCode = CKK_VENDOR_SM4;
                        break;
                    default:
                        throw new IllegalArgumentException(
                                "unknown name " + name);
                }
                ckkGenericToVendor.put(genericCode, vendorCode);
            } else if (uname.startsWith("CKM_VENDOR_")) {
                long genericCode = Functions.mechanismStringToCode(uname);
                if (genericCode == -1) {
                    throw new IllegalArgumentException("unknown name " + name);
                }
                ckmGenericToVendor.put(genericCode, vendorCode);
            }
        }

        return new MapVendorCodeConverter(
                ckkGenericToVendor, ckmGenericToVendor);
    }

    private static void copyMapIfNotNull(
            Map<Long, Long> source,
            Map<Long, Long> genericToVendorMap,
            Map<Long, Long> vendorToGenericMap) {
        if (source == null || source.isEmpty()) {
            return;
        }

        for (Long generic : source.keySet())  {
            if (generic == null) {
                continue;
            }

            Long vendor = source.get(generic);
            if (vendor != null) {
                genericToVendorMap.put(generic, vendor);
            }
        }

        for (Long generic : genericToVendorMap.keySet()) {
            Long vendor = genericToVendorMap.get(generic);
            if (vendorToGenericMap.containsKey(vendor)) {
                throw new IllegalArgumentException(
                        "duplicated vendor code 0x" + Functions.toFullHex(vendor));
            }
            vendorToGenericMap.put(vendor, generic);
        }
    }

    private static long toLong(String str) {
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

    @Override
    public long genericToVendorCKK(long ckk) {
        return 0;
    }

    @Override
    public long vendorToGenericCKK(long ckk) {
        return 0;
    }

    @Override
    public long genericToVendorCKM(long ckm) {
        return 0;
    }

    @Override
    public long vendorToGenericCKM(long ckm) {
        return 0;
    }

}
