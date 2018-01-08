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

import java.util.Date;

import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.CK_TOKEN_INFO;

/**
 * Objects of this class provide information about a token. Serial number,
 * manufacturer, free memory,... . Notice that this is just a snapshot of the
 * token's status at the time this object was created.
 *
 * @author <a href="mailto:Karl.Scheibelhofer@iaik.at"> Karl Scheibelhofer </a>
 * @version 1.0
 * @invariants (label <> null)
 *             and (manufacturerID <> null)
 *             and (model <> null)
 *             and (serialNumber <> null)
 *             and (hardwareVersion <> null)
 *             and (firmwareVersion <> null)
 *             and (time <> null)
 */
@SuppressWarnings("restriction")
public class TokenInfo implements Cloneable {

    /**
     * This is the value which can be used for ulMaxSessionCount and
     * ulMaxRwSessionCount to express an infinite number.
     */
    public static final long EFFECTIVELY_INFINITE =
            PKCS11Constants.CK_EFFECTIVELY_INFINITE;

    /**
     * This is the value which can be used for ulMaxSessionCount,
     * ulSessionCount, ulMaxRwSessionCount, ulRwSessionCount,
     * ulTotalPublicMemory, ulFreePublicMemory, ulTotalPrivateMemory, and
     * ulFreePrivateMemory to signal that the information is unavailable.
     */
    public static final long UNAVAILABLE_INFORMATION =
            PKCS11Constants.CK_UNAVAILABLE_INFORMATION;

    /**
     * The label of this token.
     */
    protected String label;

    /**
     * The identifier of the manufacturer of this token.
     */
    // CHECKSTYLE:SKIP
    protected String manufacturerID;

    /**
     * The model of this token.
     */
    protected String model;

    /**
     * The serial number of this token.
     */
    protected String serialNumber;

    /**
     * The maximum number of concurrent (open) sessions.
     */
    protected long maxSessionCount;

    /**
     * The current number of open sessions.
     */
    protected long sessionCount;

    /**
     * Maximum number of concurrent (open) read-write sessions.
     */
    protected long maxRwSessionCount;

    /**
     * The current number of open read-write sessions.
     */
    protected long rwSessionCount;

    /**
     * The maximum PIN length that this token allows.
     */
    protected long maxPinLen;

    /**
     * The minimum PIN length that this token allows.
     */
    protected long minPinLen;

    /**
     * The total amount of memory for public objects on this token.
     */
    protected long totalPublicMemory;

    /**
     * The amount of free memory for public objects on this token.
     */
    protected long freePublicMemory;

    /**
     * The total amount of memory for private objects on this token.
     */
    protected long totalPrivateMemory;

    /**
     * The amount of free memory for private objects on this token.
     */
    protected long freePrivateMemory;

    /**
     * The version of the hardware of this token.
     */
    protected Version hardwareVersion;

    /**
     * The version of the firmware of this token.
     */
    protected Version firmwareVersion;

    /**
     * The current time on the token. This value only makes sense, if the token
     * contains a clock.
     */
    protected Date time;

    /**
     * True, if the token has a random number generator.
     */
    protected boolean rng;

    /**
     * True, if the token is write protected.
     */
    protected boolean writeProtected;

    /**
     * True, if the token requires the user to login to perform certain
     * operations.
     */
    protected boolean loginRequired;

    /**
     * True, if the user-PIN is already initialized.
     */
    protected boolean userPinInitialized;

    /**
     * True, if a successful save of a session's cryptographic operations state
     * always contains all keys needed to restore the state of the session.
     */
    protected boolean restoreKeyNotNeeded;

    /**
     * True, if the token has a clock.
     */
    protected boolean clockOnToken;

    /**
     * True, if there are different means to authenticate the user than passing
     * the user-PIN to a login operation.
     */
    protected boolean protectedAuthenticationPath;

    /**
     * True, if the token supports dual cryptographic operations.
     */
    protected boolean dualCryptoOperations;

    /**
     * True, if the token is already initialized.
     */
    protected boolean tokenInitialized;

    /**
     * True, if the token supports secondary authentication for private key
     * objects.
     */
    protected boolean secondaryAuthentication;

    /**
     * True, if the user-PIN has been entered incorrectly at least once since
     * the last successful authentication.
     */
    protected boolean userPinCountLow;

    /**
     * True, if the user has just one try left to supply the correct PIN before
     * the user-PIN gets locked.
     */
    protected boolean userPinFinalTry;

    /**
     * True, if the user-PIN is locked.
     */
    protected boolean userPinLocked;

    /**
     * True, if the user PIN value is the default value set by token
     * initialization or manufacturing.
     */
    protected boolean userPinToBeChanged;

    /**
     * True, if the security officer-PIN has been entered incorrectly at least
     * once since the last successful authentication.
     */
    protected boolean soPinCountLow;

    /**
     * True, if the security officer has just one try left to supply the correct
     * PIN before the security officer-PIN gets locked.
     */
    protected boolean soPinFinalTry;

    /**
     * True, if the security officer-PIN is locked.
     */
    protected boolean soPinLocked;

    /**
     * True, if the security officer-PIN value is the default value set by token
     * initialization or manufacturing.
     */
    protected boolean soPinToBeChanged;

    /**
     * Constructor taking CK_TOKEN_INFO as given returned by
     * PKCS11.C_GetTokenInfo.
     *
     * @param ckTokenInfo
     *          The CK_TOKEN_INFO object as returned by
     *          PKCS11.C_GetTokenInfo.
     * @preconditions (ckTokenInfo <> null)
     * @postconditions
     */
    protected TokenInfo(CK_TOKEN_INFO ckTokenInfo) {
        Util.requireNonNull("ckTokenInfo", ckTokenInfo);
        label = new String(ckTokenInfo.label);
        manufacturerID = new String(ckTokenInfo.manufacturerID);
        model = new String(ckTokenInfo.model);
        serialNumber = new String(ckTokenInfo.serialNumber);
        maxSessionCount = ckTokenInfo.ulMaxSessionCount;
        sessionCount = ckTokenInfo.ulSessionCount;
        maxRwSessionCount = ckTokenInfo.ulMaxRwSessionCount;
        rwSessionCount = ckTokenInfo.ulRwSessionCount;
        maxPinLen = ckTokenInfo.ulMaxPinLen;
        minPinLen = ckTokenInfo.ulMinPinLen;
        totalPublicMemory = ckTokenInfo.ulTotalPublicMemory;
        freePublicMemory = ckTokenInfo.ulFreePublicMemory;
        totalPrivateMemory = ckTokenInfo.ulTotalPrivateMemory;
        freePrivateMemory = ckTokenInfo.ulFreePrivateMemory;
        hardwareVersion = new Version(ckTokenInfo.hardwareVersion);
        firmwareVersion = new Version(ckTokenInfo.firmwareVersion);
        time = Util.parseTime(ckTokenInfo.utcTime);
        rng = (ckTokenInfo.flags & PKCS11Constants.CKF_RNG) != 0L;
        final long flags = ckTokenInfo.flags;
        writeProtected = (flags & PKCS11Constants.CKF_WRITE_PROTECTED) != 0L;
        loginRequired = (flags & PKCS11Constants.CKF_LOGIN_REQUIRED) != 0L;
        userPinInitialized =
                (flags & PKCS11Constants.CKF_USER_PIN_INITIALIZED) != 0L;
        restoreKeyNotNeeded =
                (flags & PKCS11Constants.CKF_RESTORE_KEY_NOT_NEEDED) != 0L;
        clockOnToken =
                (flags & PKCS11Constants.CKF_CLOCK_ON_TOKEN) != 0L;
        protectedAuthenticationPath =
                (flags & PKCS11Constants.CKF_PROTECTED_AUTHENTICATION_PATH)
                    != 0L;
        dualCryptoOperations =
                (flags & PKCS11Constants.CKF_DUAL_CRYPTO_OPERATIONS) != 0L;
        tokenInitialized =
                (flags & PKCS11Constants.CKF_TOKEN_INITIALIZED) != 0L;
        secondaryAuthentication =
                (flags & PKCS11Constants.CKF_SECONDARY_AUTHENTICATION) != 0L;
        userPinCountLow =
                (flags & PKCS11Constants.CKF_USER_PIN_COUNT_LOW) != 0L;
        userPinFinalTry =
                (flags & PKCS11Constants.CKF_USER_PIN_FINAL_TRY) != 0L;
        userPinLocked =
                (flags & PKCS11Constants.CKF_USER_PIN_LOCKED) != 0L;
        userPinToBeChanged =
                (flags & PKCS11Constants.CKF_USER_PIN_TO_BE_CHANGED) != 0L;
        soPinCountLow =
                (flags & PKCS11Constants.CKF_SO_PIN_COUNT_LOW) != 0L;
        soPinFinalTry =
                (flags & PKCS11Constants.CKF_SO_PIN_FINAL_TRY) != 0L;
        soPinLocked =
                (flags & PKCS11Constants.CKF_SO_PIN_LOCKED) != 0L;
        soPinToBeChanged =
                (flags & PKCS11Constants.CKF_SO_PIN_TO_BE_CHANGED) != 0L;
    }

    /**
     * Create a (deep) clone of this object.
     *
     * @return A clone of this object.
     * @preconditions
     * @postconditions (result <> null)
     *                 and (result instanceof TokenInfo)
     *                 and (result.equals(this))
     */
    @Override
    public java.lang.Object clone() {
        TokenInfo clone;

        try {
            clone = (TokenInfo) super.clone();

            clone.hardwareVersion = (Version) this.hardwareVersion.clone();
            clone.firmwareVersion = (Version) this.firmwareVersion.clone();
            clone.time = new Date(this.time.getTime());
        } catch (CloneNotSupportedException ex) {
            // this must not happen, because this class is clone-able
            throw new TokenRuntimeException(
                    "An unexpected clone exception occurred.", ex);
        }

        return clone;
    }

    /**
     * Get the label of this token.
     *
     * @return The label of this token.
     * @preconditions
     * @postconditions (result <> null)
     */
    public String getLabel() {
        return label;
    }

    /**
     * Get the manufacturer identifier.
     *
     * @return A string identifying the manufacturer of this token.
     * @preconditions
     * @postconditions (result <> null)
     */
    // CHECKSTYLE:SKIP
    public String getManufacturerID() {
        return manufacturerID;
    }

    /**
     * Get the model of this token.
     *
     * @return A string specifying the model of this token.
     * @preconditions
     * @postconditions (result <> null)
     */
    public String getModel() {
        return model;
    }

    /**
     * Get the serial number of this token.
     *
     * @return A string holding the serial number of this token.
     * @preconditions
     * @postconditions (result <> null)
     */
    public String getSerialNumber() {
        return serialNumber;
    }

    /**
     * Get the maximum allowed number of (open) concurrent sessions.
     *
     * @return The maximum allowed number of (open) concurrent sessions.
     * @preconditions
     * @postconditions
     */
    public long getMaxSessionCount() {
        return maxSessionCount;
    }

    /**
     * Get the current number of open sessions.
     *
     * @return The current number of open sessions.
     * @preconditions
     * @postconditions
     */
    public long getSessionCount() {
        return sessionCount;
    }

    /**
     * Get the maximum allowed number of (open) concurrent read-write sessions.
     *
     * @return The maximum allowed number of (open) concurrent read-write
     *         sessions.
     * @preconditions
     * @postconditions
     */
    public long getMaxRwSessionCount() {
        return maxRwSessionCount;
    }

    /**
     * Get the current number of open read-write sessions.
     *
     * @return The current number of open read-write sessions.
     * @preconditions
     * @postconditions
     */
    public long getRwSessionCount() {
        return rwSessionCount;
    }

    /**
     * Get the maximum length for the PIN.
     *
     * @return The maximum length for the PIN.
     * @preconditions
     * @postconditions
     */
    public long getMaxPinLen() {
        return maxPinLen;
    }

    /**
     * Get the minimum length for the PIN.
     *
     * @return The minimum length for the PIN.
     * @preconditions
     * @postconditions
     */
    public long getMinPinLen() {
        return minPinLen;
    }

    /**
     * Get the total amount of memory for public objects.
     *
     * @return The total amount of memory for public objects.
     * @preconditions
     * @postconditions
     */
    public long getTotalPublicMemory() {
        return totalPublicMemory;
    }

    /**
     * Get the amount of free memory for public objects.
     *
     * @return The amount of free memory for public objects.
     * @preconditions
     * @postconditions
     */
    public long getFreePublicMemory() {
        return freePublicMemory;
    }

    /**
     * Get the total amount of memory for private objects.
     *
     * @return The total amount of memory for private objects.
     * @preconditions
     * @postconditions
     */
    public long getTotalPrivateMemory() {
        return totalPrivateMemory;
    }

    /**
     * Get the amount of free memory for private objects.
     *
     * @return The amount of free memory for private objects.
     * @preconditions
     * @postconditions
     */
    public long getFreePrivateMemory() {
        return freePrivateMemory;
    }

    /**
     * Get the version of the token's hardware.
     *
     * @return The version of the token's hardware.
     * @preconditions
     * @postconditions (result <> null)
     */
    public Version getHardwareVersion() {
        return hardwareVersion;
    }

    /**
     * Get the version of the token's firmware.
     *
     * @return The version of the token's firmware.
     * @preconditions
     * @postconditions (result <> null)
     */
    public Version getFirmwareVersion() {
        return firmwareVersion;
    }

    /**
     * Get the current time of the token's clock. This value does only make
     * sense if the token has a clock. Remind that, this is the time this object
     * was created and not the time the application called this method.
     *
     * @return The current time on the token's clock.
     * @see #isClockOnToken()
     * @preconditions
     * @postconditions (result <> null)
     */
    public Date getTime() {
        return time;
    }

    /**
     * Check, if the token has a random number generator.
     *
     * @return True, if the token has a random number generator. False,
     *         otherwise.
     * @preconditions
     * @postconditions
     */
    // CHECKSTYLE:SKIP
    public boolean isRNG() {
        return rng;
    }

    /**
     * Check, if the token is write protected.
     *
     * @return True, if the token is write protected. False, otherwise.
     * @preconditions
     * @postconditions
     */
    public boolean isWriteProtected() {
        return writeProtected;
    }

    /**
     * Check, if the token requires the user to log in before certain operations
     * can be performed.
     *
     * @return True, if the token requires the user to log in before certain
     *         operations can be performed. False, otherwise.
     * @preconditions
     * @postconditions
     */
    public boolean isLoginRequired() {
        return loginRequired;
    }

    /**
     * Check, if the user-PIN is already initialized.
     *
     * @return True, if the user-PIN is already initialized. False, otherwise.
     * @preconditions
     * @postconditions
     */
    public boolean isUserPinInitialized() {
        return userPinInitialized;
    }

    /**
     * Check, if a successful save of a session's cryptographic operations
     * state always contains all keys needed to restore the state of the
     * session.
     *
     * @return True, if a successful save of a session's cryptographic
     *         operations state always contains all keys needed to restore the
     *         state of the session. False, otherwise.
     * @preconditions
     * @postconditions
     */
    public boolean isRestoreKeyNotNeeded() {
        return restoreKeyNotNeeded;
    }

    /**
     * Check, if the token has an own clock.
     *
     * @return True, if the token has its own clock. False, otherwise.
     * @preconditions
     * @postconditions
     */
    public boolean isClockOnToken() {
        return clockOnToken;
    }

    /**
     * Check, if the token has an protected authentication path. This means that
     * a user may log in without providing a PIN to the login method, because
     * the token has other means to authenticate the user; e.g. a PIN-pad on the
     * reader or some biometric authentication.
     *
     * @return True, if the token has an protected authentication path. False,
     *         otherwise.
     * @preconditions
     * @postconditions
     */
    public boolean isProtectedAuthenticationPath() {
        return protectedAuthenticationPath;
    }

    /**
     * Check, if the token supports dual crypto operations.
     *
     * @return True, if the token supports dual crypto operations. False,
     *         otherwise.
     * @preconditions
     * @postconditions
     */
    public boolean isDualCryptoOperations() {
        return dualCryptoOperations;
    }

    /**
     * Check, if the token is already initialized.
     *
     * @return True, if the token is already initialized. False, otherwise.
     * @preconditions
     * @postconditions
     */
    public boolean isTokenInitialized() {
        return tokenInitialized;
    }

    /**
     * Check, if the token supports secondary authentication for private key
     * objects.
     *
     * @return True, if the token supports secondary authentication. False,
     *         otherwise.
     * @preconditions
     * @postconditions
     */
    public boolean isSecondaryAuthentication() {
        return secondaryAuthentication;
    }

    /**
     * Check, if the user-PIN has been entered incorrectly at least once since
     * the last successful authentication.
     *
     * @return True, if the the user-PIN has been entered incorrectly at least
     *         one since the last successful authentication. False, otherwise.
     * @preconditions
     * @postconditions
     */
    public boolean isUserPinCountLow() {
        return userPinCountLow;
    }

    /**
     * Check, if the user has just one try left to supply the correct PIN before
     * the user-PIN gets locked.
     *
     * @return True, if the user has just one try left to supply the correct PIN
     *         before the user-PIN gets locked. False, otherwise.
     * @preconditions
     * @postconditions
     */
    public boolean isUserPinFinalTry() {
        return userPinFinalTry;
    }

    /**
     * Check, if the user-PIN is locked.
     *
     * @return True, if the user-PIN is locked. False, otherwise.
     * @preconditions
     * @postconditions
     */
    public boolean isUserPinLocked() {
        return userPinLocked;
    }

    /**
     * Check, if the user PIN value is the default value set by token
     * initialization or manufacturing.
     *
     * @return True, if the user PIN value is the default value set by token
     *         initialization or manufacturing. False, otherwise.
     * @preconditions
     * @postconditions
     */
    public boolean isUserPinToBeChanged() {
        return userPinToBeChanged;
    }

    /**
     * Check, if the security officer-PIN has been entered incorrectly at least
     * once since the last successful authentication.
     *
     * @return True, if the the security officer-PIN has been entered
     *         incorrectly at least one since the last successful
     *         authentication. False, otherwise.
     * @preconditions
     * @postconditions
     */
    public boolean isSoPinCountLow() {
        return soPinCountLow;
    }

    /**
     * Check, if the security officer has just one try left to supply the
     * correct PIN before the security officer-PIN gets locked.
     *
     * @return True, if the security officer has just one try left to supply the
     *         correct PIN before the security officer-PIN gets locked. False,
     *         otherwise.
     * @preconditions
     * @postconditions
     */
    public boolean isSoPinFinalTry() {
        return soPinFinalTry;
    }

    /**
     * Check, if the security officer-PIN is locked.
     *
     * @return True, if the security officer-PIN is locked. False, otherwise.
     * @preconditions
     * @postconditions
     */
    public boolean isSoPinLocked() {
        return soPinLocked;
    }

    /**
     * Check, if the security officer PIN value is the default value set by
     * token initialization or manufacturing.
     *
     * @return True, if the security officer PIN value is the default value set
     *         by token initialization or manufacturing. False, otherwise.
     * @preconditions
     * @postconditions
     */
    public boolean isSoPinToBeChanged() {
        return soPinToBeChanged;
    }

    /**
     * Returns the string representation of this object.
     *
     * @return the string representation of object
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Label: ").append(label);
        sb.append("\nManufacturer ID: ").append(manufacturerID);
        sb.append("\nModel: ").append(model);
        sb.append("\nSerial Number: ").append(serialNumber);
        sb.append("\nRandom Number Generator: ").append(rng);
        sb.append("\nWrite protected: ").append(writeProtected);
        sb.append("\nLogin required: ").append(loginRequired);
        sb.append("\nUser PIN initialized: ").append(userPinInitialized);
        sb.append("\nRestore Key not needed: ").append(restoreKeyNotNeeded);
        sb.append("\nClock on Token: ").append(clockOnToken);
        sb.append("\nProtected Authentication Path: ")
            .append(protectedAuthenticationPath);
        sb.append("\nDual Crypto Operations: ").append(dualCryptoOperations);
        sb.append("\nToken initialized: ").append(tokenInitialized);
        sb.append("\nSecondary Authentication: ").append(secondaryAuthentication);
        sb.append("\nUser PIN-Count low: ").append(userPinCountLow);
        sb.append("\nUser PIN final Try: ").append(userPinFinalTry);
        sb.append("\nUser PIN locked: ").append(userPinLocked);
        sb.append("\nUser PIN to be changed: ").append(userPinToBeChanged);
        sb.append("\nSecurity Officer PIN-Count low: ").append(soPinCountLow);
        sb.append("\nSecurity Officer PIN final Try: ").append(soPinFinalTry);
        sb.append("\nSecurity Officer PIN locked: ").append(soPinLocked);
        sb.append("\nSecurity Officer PIN to be changed: ")
            .append(soPinToBeChanged);

        sb.append("\nMaximum Session Count: ");
        if (maxSessionCount == UNAVAILABLE_INFORMATION) {
            sb.append("<Information unavailable>");
        } else {
            sb.append((maxSessionCount == EFFECTIVELY_INFINITE)
                ? "<effectively infinite>" : Long.toString(maxSessionCount));
        }

        sb.append("\nSession Count: ");
        sb.append((sessionCount == UNAVAILABLE_INFORMATION)
            ? "<Information unavailable>" : Long.toString(sessionCount));

        sb.append("\nMaximum Read/Write Session Count: ");
        if (maxRwSessionCount == UNAVAILABLE_INFORMATION) {
            sb.append("<Information unavailable>");
        } else {
            sb.append((maxRwSessionCount == EFFECTIVELY_INFINITE)
                ? "<effectively infinite>" : Long.toString(maxRwSessionCount));
        }

        sb.append("\nRead/Write Session Count: ");
        sb.append((rwSessionCount == UNAVAILABLE_INFORMATION)
            ? "<Information unavailable>" : Long.toString(rwSessionCount));

        sb.append("\nMaximum PIN Length: ").append(maxPinLen);
        sb.append("\nMinimum PIN Length: ").append(minPinLen);

        sb.append("\nTotal Public Memory: ");
        sb.append((totalPublicMemory == UNAVAILABLE_INFORMATION)
            ? "<Information unavailable>" : Long.toString(totalPublicMemory));

        sb.append("\nFree Public Memory: ");
        sb .append((freePublicMemory == UNAVAILABLE_INFORMATION)
            ? "<Information unavailable>" : Long.toString(freePublicMemory));

        sb.append("\nTotal Private Memory: ");
        sb.append((totalPrivateMemory == UNAVAILABLE_INFORMATION)
            ? "<Information unavailable>" : Long.toString(totalPrivateMemory));

        sb.append("\nFree Private Memory: ");
        sb.append((freePrivateMemory == UNAVAILABLE_INFORMATION)
            ? "<Information unavailable>" : Long.toString(freePrivateMemory));

        sb.append("\nHardware Version: ").append(hardwareVersion);
        sb.append("\nFirmware Version: ").append(firmwareVersion);
        sb.append("\nTime: ").append(time);

        return sb.toString();
    }

    /**
     * Compares all member variables of this object with the other object.
     * Returns only true, if all are equal in both objects.
     *
     * @param otherObject
     *          The other TokenInfo object.
     * @return True, if other is an instance of Info and all member variables of
     *         both objects are equal. False, otherwise.
     * @preconditions
     * @postconditions
     */
    @Override
    public boolean equals(java.lang.Object otherObject) {
        if (this == otherObject) {
            return true;
        }

        if (!(otherObject instanceof TokenInfo)) {
            return false;
        }

        TokenInfo other = (TokenInfo) otherObject;
        return this.label.equals(other.label)
                && this.manufacturerID.equals(other.manufacturerID)
                && this.model.equals(other.model)
                && this.serialNumber.equals(other.serialNumber)
                && (this.maxSessionCount == other.maxSessionCount)
                && (this.sessionCount == other.sessionCount)
                && (this.maxRwSessionCount == other.maxRwSessionCount)
                && (this.rwSessionCount == other.rwSessionCount)
                && (this.maxPinLen == other.maxPinLen)
                && (this.minPinLen == other.minPinLen)
                && (this.totalPublicMemory == other.totalPublicMemory)
                && (this.freePublicMemory == other.freePublicMemory)
                && (this.totalPrivateMemory == other.totalPrivateMemory)
                && (this.freePrivateMemory == other.freePrivateMemory)
                && this.hardwareVersion.equals(other.hardwareVersion)
                && this.firmwareVersion.equals(other.firmwareVersion)
                && this.time.equals(other.time)
                && (this.rng == other.rng)
                && (this.writeProtected == other.writeProtected)
                && (this.loginRequired == other.loginRequired)
                && (this.userPinInitialized == other.userPinInitialized)
                && (this.restoreKeyNotNeeded == other.restoreKeyNotNeeded)
                && (this.clockOnToken == other.clockOnToken)
                && (this.protectedAuthenticationPath
                        == other.protectedAuthenticationPath)
                && (this.dualCryptoOperations == other.dualCryptoOperations)
                && (this.tokenInitialized == other.tokenInitialized)
                && (this.secondaryAuthentication
                        == other.secondaryAuthentication)
                && (this.userPinCountLow == other.userPinCountLow)
                && (this.userPinFinalTry == other.userPinFinalTry)
                && (this.userPinLocked == other.userPinLocked)
                && (this.userPinToBeChanged == other.userPinToBeChanged)
                && (this.soPinCountLow == other.soPinCountLow)
                && (this.soPinFinalTry == other.soPinFinalTry)
                && (this.soPinLocked == other.soPinLocked)
                && (this.soPinToBeChanged == other.soPinToBeChanged);
    }

    /**
     * The overriding of this method should ensure that the objects of this
     * class work correctly in a hashtable.
     *
     * @return The hash code of this object. Gained from the label,
     *         manufacturerID, model and serialNumber.
     * @preconditions
     * @postconditions
     */
    @Override
    public int hashCode() {
        return label.hashCode() ^ manufacturerID.hashCode()
                ^ model.hashCode() ^ serialNumber.hashCode();
    }

}
