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

package iaik.pkcs.pkcs11.params;

import iaik.pkcs.pkcs11.Util;
import sun.security.pkcs11.wrapper.CK_SSL3_MASTER_KEY_DERIVE_PARAMS;
import sun.security.pkcs11.wrapper.CK_SSL3_RANDOM_DATA;
import sun.security.pkcs11.wrapper.CK_VERSION;

/**
 * This class encapsulates parameters for the Mechanism.SSL3_MASTER_KEY_DERIVE
 * mechanism and the Mechanism.TLS_MASTER_KEY_DERIVE.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (randomInfo <> null)
 *             and (version <> null)
 */
@SuppressWarnings("restriction")
// CHECKSTYLE:SKIP
public class SSL3MasterKeyDeriveParams implements Params {

    /**
     * The client's and server's random data information.
     */
    protected SSL3RandomDataParams randomInfo;

    /**
     * The SSL protocol version information.
     */
    protected VersionParams version;

    /**
     * Create a new SSL3MasterKeyDeriveParameters object with the given
     * random info and version.
     *
     * @param randomInfo
     *          The client's and server's random data information.
     * @param version
     *          The SSL protocol version information.
     * @preconditions (randomInfo <> null)
     *                and (version <> null)
     * @postconditions
     */
    public SSL3MasterKeyDeriveParams(SSL3RandomDataParams randomInfo,
            VersionParams version) {
        this.randomInfo = Util.requireNonNull("randomInfo", randomInfo);
        this.version = Util.requireNonNull("version", version);
    }

    /**
     * Get this parameters object as a CK_SSL3_RANDOM_DATA object.
     *
     * @return This object as a CK_SSL3_RANDOM_DATA object.
     * @preconditions
     * @postconditions (result <> null)
     */
    @Override
    public Object getPKCS11ParamsObject() {
        CK_SSL3_MASTER_KEY_DERIVE_PARAMS params
            = new CK_SSL3_MASTER_KEY_DERIVE_PARAMS(
                (CK_SSL3_RANDOM_DATA) randomInfo.getPKCS11ParamsObject(),
                (CK_VERSION) version.getPKCS11ParamsObject());

        return params;
    }

    /**
     * Get the client's and server's random data information.
     *
     * @return The client's and server's random data information.
     * @preconditions
     * @postconditions (result <> null)
     */
    public SSL3RandomDataParams getRandomInfo() {
        return randomInfo;
    }

    /**
     * Get the SSL protocol version information.
     *
     * @return The SSL protocol version information.
     * @preconditions
     * @postconditions (result <> null)
     */
    public VersionParams getVersion() {
        return version;
    }

    /**
     * Set the client's and server's random data information.
     *
     * @param randomInfo
     *          The client's and server's random data information.
     * @preconditions (randomInfo <> null)
     * @postconditions
     */
    public void setRandomInfo(SSL3RandomDataParams randomInfo) {
        this.randomInfo = Util.requireNonNull("randomInfo", randomInfo);
    }

    /**
     * Set the SSL protocol version information.
     *
     * @param version
     *          The SSL protocol version information.
     * @preconditions (version <> null)
     * @postconditions
     */
    public void setVersion(VersionParams version) {
        this.version = Util.requireNonNull("version", version);
    }

    /**
     * Returns the string representation of this object. Do not parse data from
     * this string, it is for debugging only.
     *
     * @return A string representation of this object.
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("  Random Information:\n").append(randomInfo);
        sb.append("\n  Version: ").append(version);
        return sb.toString();
    }

    /**
     * Compares all member variables of this object with the other object.
     * Returns only true, if all are equal in both objects.
     *
     * @param otherObject
     *          The other object to compare to.
     * @return True, if other is an instance of this class and all member
     *         variables of both objects are equal. False, otherwise.
     * @preconditions
     * @postconditions
     */
    @Override
    public boolean equals(Object otherObject) {
        if (this == otherObject) {
            return true;
        } else if (!(otherObject instanceof SSL3MasterKeyDeriveParams)) {
            return false;
        }

        SSL3MasterKeyDeriveParams other
                = (SSL3MasterKeyDeriveParams) otherObject;
        return this.randomInfo.equals(other.randomInfo)
                && this.version.equals(other.version);
    }

    /**
     * The overriding of this method should ensure that the objects of this
     * class work correctly in a hashtable.
     *
     * @return The hash code of this object.
     * @preconditions
     * @postconditions
     */
    @Override
    public int hashCode() {
        return randomInfo.hashCode() ^ version.hashCode();
    }

}
