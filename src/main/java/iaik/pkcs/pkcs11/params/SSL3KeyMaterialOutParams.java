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

import java.util.Arrays;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.Util;
import iaik.pkcs.pkcs11.objects.PKCS11Object;
import iaik.pkcs.pkcs11.objects.SecretKey;
import sun.security.pkcs11.wrapper.CK_SSL3_KEY_MAT_OUT;

/**
 * Objects of this class encapsulates key material output for the mechanism
 * Mechanism.SSL3_KEY_AND_MAC_DERIVE.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants
 */
@SuppressWarnings("restriction")
// CHECKSTYLE:SKIP
public class SSL3KeyMaterialOutParams implements Params {

    /**
     * The resulting Client MAC Secret key.
     */
    protected SecretKey clientMacSecret;

    /**
     * The resulting Server MAC Secret key.
     */
    protected SecretKey serverMacSecret;

    /**
     * The resulting Client Secret key.
     */
    protected SecretKey clientKey;

    /**
     * The resulting Server Secret key.
     */
    protected SecretKey serverKey;

    /**
     * The initialization vector (IV) created for the client (if any).
     */
    // CHECKSTYLE:SKIP
    protected byte[] clientIV;

    /**
     * The initialization vector (IV) created for the server (if any).
     */
    // CHECKSTYLE:SKIP
    protected byte[] serverIV;

    /**
     * Create a new SSL3KeyMaterialOutParameters object. It does not take any
     * parameters, because they user does not need to set any of them. The token
     * sets all of them, after a call to DeriveKey using the mechanism
     * Mechanism.SSL3_KEY_AND_MAC_DERIVE. After the call to deriveKey, the
     * members of this object will hold the generated keys and IVs.
     *
     * @param clientIV
     *          The buffer for the client initialization vector.
     * @param serverIV
     *          The buffer for the server initialization vector.
     * @preconditions (clientIV <> null)
     *                and (serverIV <> null)
     * @postconditions
     */
    // CHECKSTYLE:SKIP
    public SSL3KeyMaterialOutParams(byte[] clientIV, byte[] serverIV) {
        this.clientIV = Util.requireNonNull("clientIV", clientIV);
        this.serverIV = Util.requireNonNull("serverIV", serverIV);
    }

    /**
     * Get this parameters object as an object of the CK_SSL3_KEY_MAT_OUT
     * class.
     *
     * @return This object as a CK_SSL3_KEY_MAT_OUT object.
     * @preconditions
     * @postconditions (result <> null)
     */
    @Override
    public Object getPKCS11ParamsObject() {
        CK_SSL3_KEY_MAT_OUT params = new CK_SSL3_KEY_MAT_OUT();

        params.hClientMacSecret = (clientMacSecret != null)
                ? clientMacSecret.getObjectHandle() : 0L;
        params.hServerMacSecret = (serverMacSecret != null)
                ? serverMacSecret.getObjectHandle() : 0L;
        params.hClientKey = (clientKey != null)
                ? clientKey.getObjectHandle() : 0L;
        params.hServerKey = (serverKey != null)
                ? serverKey.getObjectHandle() : 0L;
        params.pIVClient = clientIV;
        params.pIVServer = serverIV;

        return params;
    }

    /**
     * This method takes the key handles from the given input structure, which
     * will be the result after a call to DeriveKey, and creates the SecretKey
     * objects for this object. It also reads the IVs.
     *
     * @param input
     *          The structure that holds the necessary key handles and IVs.
     * @param session
     *          The session to use for reading attributes. This session must
     *          have the appropriate rights; i.e. it must be a user-session, if
     *          it is a private object.
     * @exception TokenException
     *              If reading the secret key object attributes fails.
     * @preconditions (input <> null)
     *                and (session <> null)
     * @postconditions
     */
    // CHECKSTYLE:SKIP
    public void setPKCS11ParamsObject(CK_SSL3_KEY_MAT_OUT input,
            Session session)
        throws TokenException {
        clientMacSecret = (SecretKey) PKCS11Object.getInstance(session,
                        input.hClientMacSecret);
        serverMacSecret = (SecretKey) PKCS11Object.getInstance(session,
                        input.hServerMacSecret);
        clientKey = (SecretKey) PKCS11Object.getInstance(session,
                        input.hClientKey);
        serverKey = (SecretKey) PKCS11Object.getInstance(session,
                        input.hServerKey);
        clientIV = input.pIVClient;
        serverIV = input.pIVServer;
    }

    /**
     * Get the resulting client MAC secret key.
     *
     * @return The resulting client MAC secret key.
     * @preconditions
     * @postconditions (result == null)
     */
    public SecretKey getClientMacSecret() {
        return clientMacSecret;
    }

    /**
     * Get the resulting server MAC secret key.
     *
     * @return The resulting server MAC secret key.
     * @preconditions
     * @postconditions (result == null)
     */
    public SecretKey getServerMacSecret() {
        return serverMacSecret;
    }

    /**
     * Get the resulting client secret key.
     *
     * @return The resulting client secret key.
     * @preconditions
     * @postconditions (result == null)
     */
    public SecretKey getClientSecret() {
        return clientKey;
    }

    /**
     * Get the resulting server secret key.
     *
     * @return The resulting server secret key.
     * @preconditions
     * @postconditions (result == null)
     */
    public SecretKey getServerSecret() {
        return serverKey;
    }

    /**
     * Get the resulting client initialization vector.
     *
     * @return The resulting client initialization vector.
     * @preconditions
     * @postconditions
     */
    // CHECKSTYLE:SKIP
    public byte[] getClientIV() {
        return clientIV;
    }

    /**
     * Get the resulting server initialization vector.
     *
     * @return The resulting server initialization vector.
     * @preconditions
     * @postconditions
     */
    // CHECKSTYLE:SKIP
    public byte[] getServerIV() {
        return serverIV;
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
        sb.append("  Client MAC Secret key:\n").append(clientMacSecret);
        sb.append("\n\n  Server MAC Secret key:\n")
            .append(serverMacSecret);
        sb.append("\n\n  Client Secret key:\n").append(clientKey);
        sb.append("\n\n  Server Secret key:\n").append(serverKey);
        sb.append("\n\n  Client Initializatin Vector (hex):\n")
            .append(Util.toHex(clientIV));
        sb.append("\n  Server Initializatin Vector (hex): ")
            .append(Util.toHex(serverIV));

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
        } else if (!(otherObject instanceof SSL3KeyMaterialOutParams)) {
            return false;
        }

        SSL3KeyMaterialOutParams other = (SSL3KeyMaterialOutParams) otherObject;
        return Util.objEquals(this.clientMacSecret, other.clientMacSecret)
                && Util.objEquals(this.serverMacSecret, other.serverMacSecret)
                && Util.objEquals(this.clientKey, other.clientKey)
                && Util.objEquals(this.serverKey, other.serverKey)
                && Arrays.equals(this.clientIV, other.clientIV)
                && Arrays.equals(this.serverIV, other.serverIV);
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
        return ((clientMacSecret != null) ? clientMacSecret.hashCode() : 0)
            ^ ((serverMacSecret != null) ? serverMacSecret.hashCode() : 0)
            ^ ((clientKey != null) ? clientKey.hashCode() : 0)
            ^ ((serverKey != null) ? serverKey.hashCode() : 0);
    }

}
