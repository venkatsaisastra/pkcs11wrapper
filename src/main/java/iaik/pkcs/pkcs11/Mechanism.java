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

package iaik.pkcs.pkcs11;

import iaik.pkcs.pkcs11.parameters.Parameters;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * Objects of this class represent a mechanism as defined in PKCS#11. There are
 * constants defined for all mechanisms that PKCS#11 version 2.11 defines.
 *
 * @author <a href="mailto:Karl.Scheibelhofer@iaik.at"> Karl Scheibelhofer </a>
 * @version 1.0
 * @invariants
 */
public class Mechanism implements Cloneable {

    /**
     * The code of the mechanism as defined in PKCS11Constants (or pkcs11t.h
     * likewise).
     */
    protected long pkcs11MechanismCode;

    /**
     * The parameters of the mechanism. Not all mechanisms use these parameters.
     */
    protected Parameters parameters;

    /**
     * Constructor taking just the mechanism code as defined in PKCS11Constants.
     *
     * @param pkcs11MechanismCode
     *          The mechanism code.
     * @preconditions
     * @postconditions
     */
    public Mechanism(long pkcs11MechanismCode) {
        this.pkcs11MechanismCode = pkcs11MechanismCode;
    }

    /**
     * Gets the mechanism specified by the given mechanism code. Helper
     * {@link PKCS11Constants} is available.
     *
     * @param pkcs11MechanismCode
     *          the pkcs11 mechanism code
     * @return the mechanism
     */
    public static Mechanism get(long pkcs11MechanismCode) {
        return new Mechanism(pkcs11MechanismCode);
    }

    /**
     * Makes a clone of this object.
     *
     * @return A shallow clone of this object.
     * @preconditions
     * @postconditions (result <> null)
     */
    @Override
    public Object clone() {
        Mechanism clone = null;

        try {
            clone = (Mechanism) super.clone();
        } catch (CloneNotSupportedException ex) {
            // this must not happen according to Java specifications
        }

        return clone;
    }

    /**
     * Override equals to check for the equality of mechanism code and
     * parameter.
     *
     * @param otherObject
     *          The other Mechanism object.
     * @return True, if other is an instance of this class and
     *         pkcs11MechanismCode and parameter of both objects are equal.
     * @preconditions
     * @postconditions
     */
    @Override
    public boolean equals(Object otherObject) {
        if (this == otherObject) {
            return true;
        }

        if (!(otherObject instanceof Mechanism)) {
            return false;
        }

        Mechanism other = (Mechanism) otherObject;
        if  (this.pkcs11MechanismCode != other.pkcs11MechanismCode) {
            return false;
        }

        return Util.objEquals(this.parameters, other.parameters);
    }

    /**
     * Override hashCode to ensure that hashtable still works after overriding
     * equals.
     *
     * @return The hash code of this object. Taken from the mechanism code.
     * @preconditions
     * @postconditions
     */
    @Override
    public int hashCode() {
        return (int) pkcs11MechanismCode;
    }

    /**
     * This method checks, if this mechanism is a digest mechanism.
     * This is the information as provided by the table on page 229
     * of the PKCS#11 v2.11 standard.
     * If Returns true, the mechanism can be used with the digest
     * functions.
     *
     * @return True, if this mechanism is a digest mechanism. False,
     *         otherwise.
     * @preconditions
     * @postconditions
     */
    public boolean isDigestMechanism() {
        return Functions.isDigestMechanism(pkcs11MechanismCode);
    }

    /**
     * This method checks, if this mechanism is a full
     * encrypt/decrypt mechanism; i.e. it supports the encryptUpdate()
     * and decryptUpdate() functions.
     * This is the information as provided by the table on page 229
     * of the PKCS#11 v2.11 standard.
     * If Returns true, the mechanism can be used with the encrypt
     * and decrypt functions including encryptUpdate and decryptUpdate.
     *
     * @return True, if this mechanism is a full encrypt/decrypt
     *         mechanism. False, otherwise.
     * @preconditions
     * @postconditions
     */
    public boolean isFullEncryptDecryptMechanism() {
        return Functions.isFullEncryptDecryptMechanism(pkcs11MechanismCode);
    }

    /**
     * This method checks, if this mechanism is a full
     * sign/verify mechanism; i.e. it supports the signUpdate()
     * and verifyUpdate() functions.
     * This is the information as provided by the table on page 229
     * of the PKCS#11 v2.11 standard.
     * If Returns true, the mechanism can be used with the sign and
     * verify functions including signUpdate and verifyUpdate.
     *
     * @return True, if this mechanism is a full sign/verify
     *         mechanism. False, otherwise.
     * @preconditions
     * @postconditions
     */
    public boolean isFullSignVerifyMechanism() {
        return Functions.isFullSignVerifyMechanism(pkcs11MechanismCode);
    }

    /**
     * This method checks, if this mechanism is a
     * key derivation mechanism.
     * This is the information as provided by the table on page 229
     * of the PKCS#11 v2.11 standard.
     * If Returns true, the mechanism can be used with the deriveKey
     * function.
     *
     * @return True, if this mechanism is a key derivation mechanism.
     *         False, otherwise.
     * @preconditions
     * @postconditions
     */
    public boolean isKeyDerivationMechanism() {
        return Functions.isKeyDerivationMechanism(pkcs11MechanismCode);
    }

    /**
     * This method checks, if this mechanism is a key
     * generation mechanism for generating symmetric keys.
     * This is the information as provided by the table on page 229
     * of the PKCS#11 v2.11 standard.
     * If Returns true, the mechanism can be used with the
     * generateKey function.
     *
     * @return True, if this mechanism is a key generation mechanism.
     *         False, otherwise.
     * @preconditions
     * @postconditions
     */
    public boolean isKeyGenerationMechanism() {
        return Functions.isKeyGenerationMechanism(pkcs11MechanismCode);
    }

    /**
     * This method checks, if this mechanism is a key-pair
     * generation mechanism for generating key-pairs.
     * This is the information as provided by the table on page 229
     * of the PKCS#11 v2.11 standard.
     * If this method returns true, the mechanism can be used with the
     * generateKeyPair function.
     *
     * @return True, if this mechanism is a key-pair generation mechanism.
     *         False, otherwise.
     * @preconditions
     * @postconditions
     */
    public boolean isKeyPairGenerationMechanism() {
        return Functions.isKeyPairGenerationMechanism(pkcs11MechanismCode);
    }

    /**
     * This method checks, if this mechanism is a sign/verify
     * mechanism with message recovery.
     * This is the information as provided by the table on page 229
     * of the PKCS#11 v2.11 standard.
     * If Returns true, the mechanism can be used with the
     * signRecover and verifyRecover functions.
     *
     * @return True, if this mechanism is a sign/verify mechanism with
     *         message recovery. False, otherwise.
     * @preconditions
     * @postconditions
     */
    public boolean isSignVerifyRecoverMechanism() {
        return Functions.isSignVerifyRecoverMechanism(pkcs11MechanismCode);
    }

    /**
     * This method checks, if this mechanism is a
     * single-operation encrypt/decrypt mechanism; i.e. it does not support the
     * encryptUpdate() and decryptUpdate() functions.
     * This is the information as provided by the table on page 229
     * of the PKCS#11 v2.11 standard.
     * If this method returns true, the mechanism can be used with the encrypt
     * and decrypt functions excluding encryptUpdate and decryptUpdate.
     *
     * @return True, if this mechanism is a single-operation
     *         encrypt/decrypt mechanism. False, otherwise.
     * @preconditions
     * @postconditions
     */
    public boolean isSingleOperationEncryptDecryptMechanism() {
        return Functions.isSingleOperationEncryptDecryptMechanism(
                pkcs11MechanismCode);
    }

    /**
     * This method checks, if this mechanism is a
     * single-operation sign/verify mechanism; i.e. it does not support the
     * signUpdate() and encryptUpdate() functions.
     * This is the information as provided by the table on page 229
     * of the PKCS#11 v2.11 standard.
     * If this method returns true, the mechanism can be used with the sign and
     * verify functions excluding signUpdate and encryptUpdate.
     *
     * @return True, if this mechanism is a single-operation
     *         sign/verify mechanism. False, otherwise.
     * @preconditions
     * @postconditions
     */
    public boolean isSingleOperationSignVerifyMechanism() {
        return Functions.isSingleOperationSignVerifyMechanism(
                pkcs11MechanismCode);
    }

    /**
     * This method checks, if this mechanism is a
     * wrap/unwrap mechanism; i.e. it supports the wrapKey()
     * and unwrapKey() functions.
     * This is the information as provided by the table on page 229
     * of the PKCS#11 v2.11 standard.
     * If this method returns true, the mechanism can be used with the wrapKey
     * and unwrapKey functions.
     *
     * @return True, if this mechanism is a wrap/unwrap mechanism.
     *         False, otherwise.
     * @preconditions
     * @postconditions
     */
    public boolean isWrapUnwrapMechanism() {
        return Functions.isWrapUnwrapMechanism(pkcs11MechanismCode);
    }

    /**
     * Get the parameters object of this mechanism.
     *
     * @return The parameters of this mechanism. May be null.
     * @preconditions
     * @postconditions
     */
    public Parameters getParameters() {
        return parameters;
    }

    /**
     * Set the parameters for this mechanism.
     *
     * @param parameters
     *          The mechanism parameters to set.
     * @preconditions
     * @postconditions
     */
    public void setParameters(Parameters parameters) {
        this.parameters = parameters;
    }

    /**
     * Get the code of this mechanism as defined in PKCS11Constants (of
     * pkcs11t.h likewise).
     *
     * @return The code of this mechanism.
     * @preconditions
     * @postconditions
     */
    public long getMechanismCode() {
        return pkcs11MechanismCode;
    }

    /**
     * Get the name of this mechanism.
     *
     * @return The name of this mechanism.
     * @preconditions
     * @postconditions
     */
    public String getName() {
        return Functions.mechanismCodeToString(pkcs11MechanismCode);
    }

    /**
     * Returns the string representation of this object.
     *
     * @return the string representation of this object
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(128);
        sb.append("    Mechanism: ")
            .append(Functions.mechanismCodeToString(pkcs11MechanismCode));
        sb.append("\n    Parameters:\n").append(parameters);
        return sb.toString();
    }

}
