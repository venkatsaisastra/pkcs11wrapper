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

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Vector;

import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.PKCS11Object;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.SecretKey;
import iaik.pkcs.pkcs11.parameters.AesCtrParameters;
import iaik.pkcs.pkcs11.parameters.CCMParameters;
import iaik.pkcs.pkcs11.parameters.DHPkcsDeriveParameters;
import iaik.pkcs.pkcs11.parameters.EcDH1KeyDerivationParameters;
import iaik.pkcs.pkcs11.parameters.EcDH2KeyDerivationParameters;
import iaik.pkcs.pkcs11.parameters.ExtractParameters;
import iaik.pkcs.pkcs11.parameters.GCMParameters;
import iaik.pkcs.pkcs11.parameters.InitializationVectorParameters;
import iaik.pkcs.pkcs11.parameters.MacGeneralParameters;
import iaik.pkcs.pkcs11.parameters.ObjectHandleParameters;
import iaik.pkcs.pkcs11.parameters.OpaqueParameters;
import iaik.pkcs.pkcs11.parameters.PBEParameters;
import iaik.pkcs.pkcs11.parameters.PKCS5PBKD2Parameters;
import iaik.pkcs.pkcs11.parameters.Parameters;
import iaik.pkcs.pkcs11.parameters.RSAPkcsOaepParameters;
import iaik.pkcs.pkcs11.parameters.RSAPkcsPssParameters;
import iaik.pkcs.pkcs11.parameters.SSL3KeyMaterialParameters;
import iaik.pkcs.pkcs11.parameters.SSL3MasterKeyDeriveParameters;
import iaik.pkcs.pkcs11.parameters.SSL3RandomDataParameters;
import iaik.pkcs.pkcs11.parameters.TLS12KeyMaterialParameters;
import iaik.pkcs.pkcs11.parameters.TLS12MasterKeyDeriveParameters;
import iaik.pkcs.pkcs11.parameters.TLSMacParameters;
import iaik.pkcs.pkcs11.parameters.TLSPRFParameters;
import iaik.pkcs.pkcs11.parameters.VersionParameters;
import iaik.pkcs.pkcs11.parameters.X942DH1KeyDerivationParameters;
import iaik.pkcs.pkcs11.parameters.X942DH2KeyDerivationParameters;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_MECHANISM;
import sun.security.pkcs11.wrapper.CK_RSA_PKCS_PSS_PARAMS;
import sun.security.pkcs11.wrapper.CK_SESSION_INFO;
import sun.security.pkcs11.wrapper.CK_SSL3_KEY_MAT_OUT;
import sun.security.pkcs11.wrapper.CK_SSL3_KEY_MAT_PARAMS;
import sun.security.pkcs11.wrapper.CK_SSL3_MASTER_KEY_DERIVE_PARAMS;
import sun.security.pkcs11.wrapper.CK_VERSION;
import sun.security.pkcs11.wrapper.PKCS11;

/**
 * Session objects are used to perform cryptographic operations on a token. The
 * application gets a Session object by calling openSession on a certain Token
 * object. Having the session object, the application may log-in the user, if
 * required.
 *
 * <pre>
 * <code>
 *   TokenInfo tokenInfo = token.getTokenInfo();
 *   // check, if log-in of the user is required at all
 *   if (tokenInfo.isLoginRequired()) {
 *     // check, if the token has own means to authenticate the user; e.g. a
 *     // PIN-pad on the reader
 *     if (tokenInfo.isProtectedAuthenticationPath()) {
 *       System.out.println(
 *               "Please enter the user PIN at the PIN-pad of your reader.");
 *       // the token prompts the PIN by other means; e.g. PIN-pad
 *       session.login(Session.UserType.USER, null);
 *     } else {
 *       System.out.print("Enter user-PIN and press [return key]: ");
 *       System.out.flush();
 *       BufferedReader input = new BufferedReader(
 *               new InputStreamReader(System.in));
 *       String userPINString = input.readLine();
 *       session.login(Session.UserType.USER, userPINString.toCharArray());
 *     }
 *   }
 * </code>
 * </pre>
 * With this session object the application can search for token objects and
 * perform a cryptographic operation. For example, to find private RSA keys that
 * the application can use for signing, you can write:
 *
 * <pre>
 * <code>
 *   RSAPrivateKey privateSignatureKeyTemplate = new RSAPrivateKey();
 *   privateSignatureKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
 *
 *   session.findObjectsInit(privateSignatureKeyTemplate);
 *   PKCS11Object[] privateSignatureKeys;
 *
 *   List signatureKeyList = new Vector(4);
 *   while ((privateSignatureKeys = session.findObjects(1)).length &gt; 0) {
 *     signatureKeyList.add(privateSignatureKeys[0]);
 *   }
 *   session.findObjectsFinal();
 * </code>
 * </pre>
 * Having chosen one of this keys, the application can create a signature value
 * using it.
 *
 * <pre>
 * <code>
 *   // e.g. the encoded digest info object that contains an identifier of the
 *   // hash algorithm and the hash value
 *   byte[] toBeSigned;
 *
 *   // toBeSigned = ... assign value
 *
 *   RSAPrivateKey selectedSignatureKey;
 *
 *   // selectedSignatureKey = ... assign one of the available signature keys
 *
 *   // initialize for signing
 *   session.signInit(Mechanism.RSA_PKCS, selectedSignatureKey);
 *
 *   // sign the data to be signed
 *   byte[] signatureValue = session.sign(toBeSigned);
 * </code>
 * </pre>
 * If the application does not need the session any longer, it should close the
 * session.
 *
 * <pre>
 * <code>
 *   session.closeSession();
 * </code>
 * </pre>
 *
 * @see iaik.pkcs.pkcs11.objects.PKCS11Object
 * @see iaik.pkcs.pkcs11.parameters.Parameters
 * @see iaik.pkcs.pkcs11.Session
 * @see iaik.pkcs.pkcs11.SessionInfo
 * @author Karl Scheibelhofer
 * @version 1.0
 */
public class Session {

  /**
   * This interface defines the different user types of PKCS#11.
   *
   * @author Karl Scheibelhofer
   * @version 1.0
   */
  public interface UserType {

    /**
     * This constant stands for the security officer.
     */
    public static boolean SO = false;

    /**
     * Thsi constant stands for the user (token owner).
     */
    public static boolean USER = true;

  }

  private static final Method encrypt0;

  private static final Method encrypt1;

  private static final Method decrypt0;

  private static final Method decrypt1;

  private static final Field field_CK_MECHANISM_pParameter;

  private static final Method method_CK_MECHANISM_setParameter;

  private static final Constructor<?> constructor_CK_MECHANISM_CCM;

  private static final Constructor<?> constructor_CK_MECHANISM_GCM;

  private static final Constructor<?> constructor_CK_MECHANISM_TLS12KeyMat;

  private static final Constructor<?>
      constructor_CK_MECHANISM_TLS12MasterKeyDerive;

  private static final Constructor<?> constructor_CK_MECHANISM_TLSMac;

  /**
   * A reference to the underlying PKCS#11 module to perform the operations.
   */
  private Module module;

  /**
   * A reference to the underlying PKCS#11 module to perform the operations.
   */
  private PKCS11 pkcs11Module;

  /**
   * The session handle to perform the operations with.
   */
  private long sessionHandle;

  /**
   * The token to perform the operations on.
   */
  private Token token;

  static {
    Class<?> clazz = PKCS11.class;
    decrypt0 = Util.getMethod(clazz, "C_Decrypt",
        long.class, byte[].class, int.class, int.class,
        byte[].class, int.class, int.class);

    encrypt0 = Util.getMethod(clazz, "C_Encrypt",
        long.class, byte[].class, int.class, int.class,
        byte[].class, int.class, int.class);

    if (decrypt0 == null) {
      decrypt1 = Util.getMethod(clazz, "C_Decrypt",
          long.class, long.class, byte[].class, int.class, int.class,
          long.class, byte[].class, int.class, int.class);
    } else {
      decrypt1 = null;
    }

    if (encrypt0 == null) {
      encrypt1 = Util.getMethod(clazz, "C_Encrypt",
          long.class, long.class, byte[].class, int.class, int.class,
          long.class, byte[].class, int.class, int.class);
    } else {
      encrypt1 = null;
    }

    clazz = CK_MECHANISM.class;
    field_CK_MECHANISM_pParameter = Util.getField(clazz, "pParameter");
    method_CK_MECHANISM_setParameter = Util.getMethod(clazz, "setParameter",
        CK_RSA_PKCS_PSS_PARAMS.class);

    constructor_CK_MECHANISM_CCM =
        getConstructofOfCK_MECHANISM(CCMParameters.CLASS_CK_PARAMS);

    constructor_CK_MECHANISM_GCM =
        getConstructofOfCK_MECHANISM(GCMParameters.CLASS_CK_PARAMS);

    constructor_CK_MECHANISM_TLS12KeyMat =
        getConstructofOfCK_MECHANISM(
            TLS12KeyMaterialParameters.CLASS_CK_PARAMS);

    constructor_CK_MECHANISM_TLS12MasterKeyDerive =
        getConstructofOfCK_MECHANISM(
            TLS12MasterKeyDeriveParameters.CLASS_CK_PARAMS);

    constructor_CK_MECHANISM_TLSMac =
        getConstructofOfCK_MECHANISM(TLSMacParameters.CLASS_CK_PARAMS);
  }

  private static Constructor<?> getConstructofOfCK_MECHANISM(
      String paramsClassName) {
    Class<?> paramsClass;
    try {
      paramsClass = Class.forName(paramsClassName);
    } catch (ClassNotFoundException ex) {
      return null;
    }

    return Util.getConstructor(CK_MECHANISM.class, long.class, paramsClass);
  }

  /**
   * Constructor taking the token and the session handle.
   *
   * @param token
   *          The token this session operates with.
   * @param sessionHandle
   *          The session handle to perform the operations with.
   */
  protected Session(Token token, long sessionHandle) {
    this.token = Util.requireNonNull("token", token);
    this.module = token.getSlot().getModule();
    this.pkcs11Module = module.getPKCS11Module();
    this.sessionHandle = sessionHandle;
  }

  /**
   * Initializes the user-PIN. Can only be called from a read-write security
   * officer session. May be used to set a new user-PIN if the user-PIN is
   * locked.
   *
   * @param pin
   *          The new user-PIN. This parameter may be null, if the token has
   *          a protected authentication path. Refer to the PKCS#11 standard
   *          for details.
   * @exception TokenException
   *              If the session has not the right to set the PIN of if the
   *              operation fails for some other reason.
   */
  /*
  public void initPIN(char[] pin)
    throws TokenException {
    pkcs11Module.C_InitPIN(sessionHandle, pin, useUtf8Encoding);
  }*/

  /**
   * Set the user-PIN to a new value. Can only be called from a read-write
   * sessions.
   *
   * @param oldPin
   *          The old (current) user-PIN.
   * @param newPin
   *          The new value for the user-PIN.
   * @exception TokenException
   *              If setting the new PIN fails.
   */
  /*
  public void setPIN(char[] oldPin, char[] newPin)
    throws TokenException {
    pkcs11Module.C_SetPIN(sessionHandle, oldPin, newPin,
        useUtf8Encoding);
  }*/

  /**
   * Closes this session.
   *
   * @exception TokenException
   *              If closing the session failed.
   */
  public void closeSession() throws TokenException {
    try {
      pkcs11Module.C_CloseSession(sessionHandle);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Compares the sessionHandle and token of this object with the other
   * object. Returns only true, if those are equal in both objects.
   *
   * @param otherObject
   *          The other Session object.
   * @return True, if other is an instance of Token and the session handles
   *         and tokens of both objects are equal. False, otherwise.
   */
  @Override
  public boolean equals(Object otherObject) {
    if (this == otherObject) {
      return true;
    } else if (!(otherObject instanceof Session)) {
      return false;
    }

    Session other = (Session) otherObject;
    if (this.sessionHandle != other.sessionHandle) {
      return false;
    }

    return this.token.equals(other.token);
  }

  /**
   * The overriding of this method should ensure that the objects of this
   * class work correctly in a hashtable.
   *
   * @return The hash code of this object. Gained from the sessionHandle.
   */
  @Override
  public int hashCode() {
    return (int) sessionHandle;
  }

  /**
   * Get the handle of this session.
   *
   * @return The handle of this session.
   */
  public long getSessionHandle() {
    return sessionHandle;
  }

  /**
   * Get information about this session.
   *
   * @return An object providing information about this session.
   * @exception TokenException
   *              If getting the information failed.
   */
  public SessionInfo getSessionInfo() throws TokenException  {
    CK_SESSION_INFO ckSessionInfo;
    try {
      ckSessionInfo = pkcs11Module.C_GetSessionInfo(sessionHandle);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }

    return new SessionInfo(ckSessionInfo);
  }

  /**
   * Get the Module which this Session object operates with.
   *
   * @return The module of this session.
   */
  public Module getModule() {
    return module;
  }

  /**
   * Get the token that created this Session object.
   *
   * @return The token of this session.
   */
  public Token getToken() {
    return token;
  }

  /**
   * Get the current operation state. This state can be used later to restore
   * the operation to exactly this state.
   *
   * @return The current operation state as a byte array.
   * @exception TokenException
   *              If saving the state fails or is not possible.
   * @see #setOperationState(byte[],Key,Key)
   */
  public byte[] getOperationState() throws TokenException {
    try {
      return pkcs11Module.C_GetOperationState(sessionHandle);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Sets the operation state of this session to a previously saved one. This
   * method may need the key used during the saved operation to continue,
   * because it may not be possible to save a key into the state's byte array.
   * Refer to the PKCS#11 standard for details on this function.
   *
   * @param operationState
   *          The previously saved state as returned by getOperationState().
   * @param encryptionKey
   *          A encryption or decryption key, if a encryption or decryption
   *          operation was saved which should be continued, but the keys
   *          could not be saved.
   * @param authenticationKey
   *          A signing, verification of MAC key, if a signing, verification
   *          or MAC operation needs to be restored that could not save the
   *          key.
   * @exception TokenException
   *              If restoring the state fails.
   * @see #getOperationState()
   */
  public void setOperationState(byte[] operationState, Key encryptionKey,
      Key authenticationKey) throws TokenException {
    try {
      pkcs11Module.C_SetOperationState(sessionHandle, operationState,
          encryptionKey.getObjectHandle(), authenticationKey.getObjectHandle());
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  public void setSessionHandle(long sessionHandle) {
    this.sessionHandle = sessionHandle;
  }

  /**
   * Logs in the user or the security officer to the session. Notice that all
   * sessions of a token have the same login state; i.e. if you login the user
   * to one session all other open sessions of this token get user rights.
   *
   * @param userType
   *          UserType.SO for the security officer or UserType.USER to login
   *          the user.
   * @param pin
   *          The PIN. The security officer-PIN or the user-PIN depending on
   *          the userType parameter.
   * @exception TokenException
   *              If login fails.
   */
  public void login(boolean userType, char[] pin) throws TokenException {
    long tmpUserType = (userType == UserType.SO)
        ? PKCS11Constants.CKU_SO : PKCS11Constants.CKU_USER;
    try {
      pkcs11Module.C_Login(sessionHandle, tmpUserType, pin);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Logs in the user or the security officer to the session. Notice that all
   * sessions of a token have the same login state; i.e. if you login the user
   * to one session all other open sessions of this token get user rights.
   *
   * @param userType
   *          PKCS11Constants.CKU_SO for the security officer or
   *          PKCS11Constants.CKU_USER to login the user.
   * @param pin
   *          The PIN. The security officer-PIN or the user-PIN depending on
   *          the userType parameter.
   * @exception TokenException
   *              If login fails.
   */
  public void login(long userType, char[] pin) throws TokenException {
    try {
      pkcs11Module.C_Login(sessionHandle, userType, pin);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Logs out this session.
   *
   * @exception TokenException
   *              If logging out the session fails.
   */
  public void logout() throws TokenException {
    try {
      pkcs11Module.C_Logout(sessionHandle);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Create a new object on the token (or in the session). The application
   * must provide a template that holds enough information to create a certain
   * object. For instance, if the application wants to create a new DES key
   * object it creates a new instance of the DESSecretKey class to serve as a
   * template. The application must set all attributes of this new object
   * which are required for the creation of such an object on the token. Then
   * it passes this DESSecretKey object to this method to create the object on
   * the token. Example:
   * <pre>
   *   ValuedSecretKey aesKeyTemplate =
   *       new ValuedSecretKey(PKCS11Constants.CKK_AES);
   *   aesKeyTemplate.setValue(myDesKeyValueAs8BytesLongByteArray);
   *   aesKeyTemplate.setToken(Boolean.TRUE);
   *   aesKeyTemplate.setPrivate(Boolean.TRUE);
   *   aesKeyTemplate.setEncrypt(Boolean.TRUE);
   *   aesKeyTemplate.setDecrypt(Boolean.TRUE);
   *   ...
   *   ValuedSecretKey theCreatedAESKeyObject =
   *           (ValuedSecretKey) userSession.createObject(aesKeyTemplate);
   * </pre>
   *
   * Refer to the PKCS#11 standard to find out what attributes must be
   * set for certain types of objects to create them on the token.
   *
   * @param templateObject
   *          The template object that holds all values that the new object on
   *          the token should contain. (this is not a Object!)
   * @return A new PKCS#11 PKCS11Object (this is not a Object!) that
   *         serves holds all the (readable) attributes of the object on the
   *         token. In contrast to the templateObject, this object might have
   *         certain attributes set to token-dependent default-values.
   * @exception TokenException
   *              If the creation of the new object fails. If it fails, the no
   *              new object was created on the token.
   */
  public PKCS11Object createObject(PKCS11Object templateObject)
      throws TokenException {
    CK_ATTRIBUTE[] ckAttributes = PKCS11Object.getSetAttributes(templateObject);
    long objectHandle;
    try {
      objectHandle = pkcs11Module.C_CreateObject(sessionHandle, ckAttributes);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }

    return PKCS11Object.getInstance(this, objectHandle);
  }

  /**
   * Copy an existing object. The source object and a template object are
   * given. Any value set in the template object will override the
   * corresponding value from the source object, when the new object is
   * created. See the PKCS#11 standard for details.
   *
   * @param sourceObject
   *          The source object of the copy operation.
   * @param templateObject
   *          A template object which's attribute values are used for the new
   *          object; i.e. they have higher priority than the attribute values
   *          from the source object. May be null; in that case the new object
   *          is just a one-to-one copy of the sourceObject.
   * @return The new object that is created by copying the source object and
   *         setting attributes to the values given by the templateObject.
   * @exception TokenException
   *              If copying the object fails for some reason.
   */
  public PKCS11Object copyObject(PKCS11Object sourceObject,
      PKCS11Object templateObject) throws TokenException {
    long sourceObjectHandle = sourceObject.getObjectHandle();
    CK_ATTRIBUTE[] ckAttributes = PKCS11Object.getSetAttributes(templateObject);
    long newObjectHandle;
    try {
      newObjectHandle = pkcs11Module.C_CopyObject(sessionHandle,
          sourceObjectHandle, ckAttributes);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }

    return PKCS11Object.getInstance(this, newObjectHandle);
  }

  /**
   * Gets all present attributes of the given template object an writes them
   * to the object to update on the token (or in the session). Both parameters
   * may refer to the same Java object. This is possible, because this method
   * only needs the object handle of the objectToUpdate, and gets the
   * attributes to set from the template. This means, an application can get
   * the object using createObject of findObject, then modify attributes of
   * this Java object and then call this method passing this object as both
   * parameters. This will update the object on the token to the values as
   * modified in the Java object.
   *
   * @param objectToUpdate
   *          The attributes of this object get updated.
   * @param templateObject
   *          This methods gets all present attributes of this template object
   *          and set this attributes at the objectToUpdate.
   * @exception TokenException
   *              If update of the attributes fails. All or no attributes are
   *              updated.
   */
  public void setAttributeValues(PKCS11Object objectToUpdate,
      PKCS11Object templateObject) throws TokenException {
    long objectToUpdateHandle = objectToUpdate.getObjectHandle();
    CK_ATTRIBUTE[] ckAttributesTemplates =
        PKCS11Object.getSetAttributes(templateObject);
    try {
      pkcs11Module.C_SetAttributeValue(sessionHandle,
          objectToUpdateHandle, ckAttributesTemplates);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Reads all the attributes of the given PKCS11Object from the token and
   * returns a new PKCS11Object that contains all these attributes. The
   * given objectToRead and the returned PKCS11Object are different Java
   * objects. This method just uses the object handle of the given object,
   * it does not modify anything in this object.
   *
   * @param objectToRead
   *          The object to newly read from the token.
   * @return A new PKCS11Object holding all attributes that this method just
   *         read from the token.
   * @exception TokenException
   *              If reading the attributes fails.
   */
  public PKCS11Object getAttributeValues(PKCS11Object objectToRead)
      throws TokenException {
    long objectHandle = objectToRead.getObjectHandle();
    return PKCS11Object.getInstance(this, objectHandle);
  }

  /**
   * Destroy a certain object on the token (or in the session). Give the
   * object that you want to destroy. This method uses only the internal
   * object handle of the given object to identify the object.
   *
   * @param object
   *          The object that should be destroyed.
   * @exception TokenException
   *              If the object could not be destroyed.
   */
  public void destroyObject(PKCS11Object object) throws TokenException {
    long objectHandle = object.getObjectHandle();
    try {
      pkcs11Module.C_DestroyObject(sessionHandle, objectHandle);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Get the size of the specified object in bytes. This size specifies how
   * much memory the object takes up on the token.
   *
   * @param object
   *          The object to get the size for.
   * @return The object's size bytes.
   * @exception TokenException
   *              If determining the size fails.
   */
  /*
  public long getObjectSize(PKCS11Object object)
    throws TokenException {
    long objectHandle = object.getObjectHandle();
    return pkcs11Module.C_GetObjectSize(sessionHandle, objectHandle);
  }*/

  /**
   * Initializes a find operations that provides means to find objects by
   * passing a template object. This method gets all set attributes of the
   * template object and searches for all objects on the token that match with
   * these attributes.
   *
   * @param templateObject
   *          The object that serves as a template for searching. If this
   *          object is null, the find operation will find all objects that
   *          this session can see. Notice, that only a user session will see
   *          private objects.
   * @exception TokenException
   *              If initializing the find operation fails.
   */
  public void findObjectsInit(PKCS11Object templateObject)
      throws TokenException {
    CK_ATTRIBUTE[] ckAttributes = PKCS11Object.getSetAttributes(templateObject);
    try {
      pkcs11Module.C_FindObjectsInit(sessionHandle, ckAttributes);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Finds objects that match the template object passed to findObjectsInit.
   * The application must call findObjectsInit before calling this method.
   * With maxObjectCount the application can specify how many objects to
   * return at once; i.e. the application can get all found objects by
   * subsequent calls to this method like maxObjectCount(1) until it receives
   * an empty array (this method never returns null!).
   *
   * @param maxObjectCount
   *          Specifies how many objects to return with this call.
   * @return An array of found objects. The maximum size of this array is
   *         maxObjectCount, the minimum length is 0. Never returns null.
   * @exception TokenException
   *              A plain TokenException if something during PKCS11 FindObject
   *              went wrong, a TokenException with a nested TokenException if
   *              the Exception is raised during object parsing.
   */
  public PKCS11Object[] findObjects(int maxObjectCount) throws TokenException {
    Vector<PKCS11Object> foundObjects = new Vector<>();
    long[] objectHandles;
    try {
      objectHandles = pkcs11Module.C_FindObjects(sessionHandle, maxObjectCount);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }

    try {
      for (int i = 0; i < objectHandles.length; i++) {
        PKCS11Object object = PKCS11Object.getInstance(this, objectHandles[i]);
        foundObjects.addElement(object);
      }
      PKCS11Object[] objectArray = new PKCS11Object[foundObjects.size()];
      foundObjects.copyInto(objectArray);

      return objectArray;
    } catch (TokenException e) {
      // encapsulate exception to signal a cause other than C_FindObjects
      throw new TokenException(e);
    }
  }

  /**
   * Finalizes a find operation. The application must call this method to
   * finalize a find operation before attempting to start any other operation.
   *
   * @exception TokenException
   *              If finalizing the current find operation was not possible.
   */
  public void findObjectsFinal() throws TokenException {
    try {
      pkcs11Module.C_FindObjectsFinal(sessionHandle);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Initializes a new encryption operation. The application must call this
   * method before calling any other encrypt* operation. Before initializing a
   * new operation, any currently pending operation must be finalized using
   * the appropriate *Final method (e.g. digestFinal()). There are exceptions
   * for dual-function operations. This method requires the mechanism to use
   * for encryption and the key for this operation. The key must have set its
   * encryption flag. For the mechanism the application may use a constant
   * defined in the Mechanism class. Notice that the key and the mechanism
   * must be compatible; i.e. you cannot use a DES key with the RSA mechanism.
   *
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.DES_CBC.
   * @param key
   *          The decryption key to use.
   * @exception TokenException
   *              If initializing this operation failed.
   */
  public void encryptInit(Mechanism mechanism, Key key) throws TokenException {
    try {
      CK_MECHANISM mech = toCkMechanism(mechanism);
      pkcs11Module.C_EncryptInit(sessionHandle, mech, key.getObjectHandle());
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Encrypts the given data with the key and mechanism given to the
   * encryptInit method. This method finalizes the current encryption
   * operation; i.e. the application need (and should) not call
   * encryptFinal() after this call. For encrypting multiple pieces of data
   * use encryptUpdate and encryptFinal.
   *
   * @param in
   *          buffer containing the to-be-encrypted data
   * @param inOfs
   *          buffer offset of the to-be-encrypted data
   * @param inLen
   *          length of the to-be-encrypted data
   * @param out
   *          buffer for the encrypted data
   * @param outOfs
   *          buffer offset for the encrypted data
   * @param outLen
   *          buffer size for the encrypted data
   * @return the length of encrypted data
   * @exception TokenException
   *              If encrypting failed.
   */
  public int encrypt(byte[] in, int inOfs, int inLen,
      byte[] out, int outOfs, int outLen) throws TokenException {
    Util.requireNonNull("in", in);
    Util.requireNonNull("out", out);
    try {
      if (encrypt0 != null) {
        return (int) encrypt0.invoke(pkcs11Module,
            sessionHandle, in, inOfs, inLen, out, outOfs, outLen);
      } else if (encrypt1 != null) {
        return (int) encrypt1.invoke(pkcs11Module,
            sessionHandle, 0, in, inOfs, inLen, 0, out, outOfs, outLen);
      } else {
        throw new IllegalStateException("could not find C_ENCRYPT method");
      }
    } catch (IllegalAccessException ex) {
      throw new TokenException("", ex);
    } catch (InvocationTargetException ex) {
      Throwable cause = ex.getCause();
      if (cause instanceof sun.security.pkcs11.wrapper.PKCS11Exception) {
        throw new PKCS11Exception(
            ((sun.security.pkcs11.wrapper.PKCS11Exception) cause)
                .getErrorCode());
      } else if (cause instanceof RuntimeException) {
        throw (RuntimeException) cause;
      } else {
        throw new TokenException("Error " + ex.getMessage(), ex);
      }
    }
  }

  /**
   * This method can be used to encrypt multiple pieces of data; e.g.
   * buffer-size pieces when reading the data from a stream. Encrypts the
   * given data with the key and mechanism given to the encryptInit method.
   * The application must call encryptFinal to get the final result of the
   * encryption after feeding in all data using this method.
   *
   * @param in
   *          buffer containing the to-be-encrypted data
   * @param inOfs
   *          buffer offset of the to-be-encrypted data
   * @param inLen
   *          length of the to-be-encrypted data
   * @param out
   *          buffer for the encrypted data
   * @param outOfs
   *          buffer offset for the encrypted data
   * @param outLen
   *          buffer size for the encrypted data
   * @return the length of encrypted data for this update
   * @exception TokenException
   *              If encrypting the data failed.
   */
  public int encryptUpdate(byte[] in, int inOfs, int inLen,
      byte[] out, int outOfs, int outLen) throws TokenException {
    Util.requireNonNull("in", in);
    Util.requireNonNull("out", out);

    try {
      return pkcs11Module.C_EncryptUpdate(sessionHandle, 0, in, inOfs,
          inLen, 0, out, outOfs, outLen);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * This method finalizes an encryption operation and returns the final
   * result. Use this method, if you fed in the data using encryptUpdate. If
   * you used the encrypt(byte[]) method, you need not (and shall not) call
   * this method, because encrypt(byte[]) finalizes the encryption itself.
   *
   * @param out
   *          buffer for the encrypted data
   * @param outOfs
   *          buffer offset for the encrypted data
   * @param outLen
   *          buffer size for the encrypted data
   * @return the length of the last part of the encrypted data
   * @exception TokenException
   *              If calculating the final result failed.
   */
  public int encryptFinal(byte[] out, int outOfs, int outLen)
      throws TokenException {
    Util.requireNonNull("out", out);

    try {
      return pkcs11Module.C_EncryptFinal(sessionHandle, 0,
          out, outOfs, outLen);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Initializes a new decryption operation. The application must call this
   * method before calling any other decrypt* operation. Before initializing a
   * new operation, any currently pending operation must be finalized using
   * the appropriate *Final method (e.g. digestFinal()). There are exceptions
   * for dual-function operations. This method requires the mechanism to use
   * for decryption and the key for this operation. The key must have set its
   * decryption flag. For the mechanism the application may use a constant
   * defined in the Mechanism class. Notice that the key and the mechanism
   * must be compatible; i.e. you cannot use a DES key with the RSA mechanism.
   *
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.DES_CBC.
   * @param key
   *          The decryption key to use.
   * @exception TokenException
   *              If initializing this operation failed.
   */
  public void decryptInit(Mechanism mechanism, Key key) throws TokenException {
    try {
      pkcs11Module.C_DecryptInit(sessionHandle, toCkMechanism(mechanism),
          key.getObjectHandle());
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Decrypts the given data with the key and mechanism given to the
   * decryptInit method. This method finalizes the current decryption
   * operation; i.e. the application need (and should) not call decryptFinal()
   * after this call. For decrypting multiple pieces of data use decryptUpdate
   * and decryptFinal.
   *
   * @param in
   *          buffer containing the to-be-decrypted data
   * @param inOfs
   *          buffer offset of the to-be-decrypted data
   * @param inLen
   *          length of the to-be-decrypted data
   * @param out
   *          buffer for the decrypted data
   * @param outOfs
   *          buffer offset for the decrypted data
   * @param outLen
   *          buffer size for the decrypted data
   * @return the length of decrypted data
   * @exception TokenException
   *              If decrypting failed.
   */
  public int decrypt(byte[] in, int inOfs, int inLen,
      byte[] out, int outOfs, int outLen) throws TokenException {
    Util.requireNonNull("in", in);
    Util.requireNonNull("out", out);

    try {
      if (decrypt0 != null) {
        return (int) decrypt0.invoke(pkcs11Module,
            sessionHandle, in, inOfs, inLen, out, outOfs, outLen);
      } else if (decrypt1 != null) {
        return (int) decrypt1.invoke(pkcs11Module,
            sessionHandle, 0, in, inOfs, inLen, 0, out, outOfs, outLen);
      } else {
        throw new IllegalStateException("could not find C_DECRYPT method");
      }
    } catch (IllegalAccessException ex) {
      throw new TokenException("", ex);
    } catch (InvocationTargetException ex) {
      Throwable cause = ex.getCause();
      if (cause instanceof sun.security.pkcs11.wrapper.PKCS11Exception) {
        throw new PKCS11Exception(
            ((sun.security.pkcs11.wrapper.PKCS11Exception) cause)
                .getErrorCode());
      } else if (cause instanceof RuntimeException) {
        throw (RuntimeException) cause;
      } else {
        throw new TokenException("Error " + ex.getMessage(), ex);
      }
    }
  }

  /**
   * This method can be used to decrypt multiple pieces of data; e.g.
   * buffer-size pieces when reading the data from a stream. Decrypts the
   * given data with the key and mechanism given to the decryptInit method.
   * The application must call decryptFinal to get the final result of the
   * encryption after feeding in all data using this method.
   *
   * @param in
   *          buffer containing the to-be-decrypted data
   * @param inOfs
   *          buffer offset of the to-be-decrypted data
   * @param inLen
   *          length of the to-be-decrypted data
   * @param out
   *          buffer for the decrypted data
   * @param outOfs
   *          buffer offset for the decrypted data
   * @param outLen
   *          buffer size for the decrypted data
   * @return the length of decrypted data for this update
   * @exception TokenException
   *              If decrypting the data failed.
   */
  public int decryptUpdate(byte[] in, int inOfs, int inLen,
      byte[] out, int outOfs, int outLen) throws TokenException {
    Util.requireNonNull("in", in);
    Util.requireNonNull("out", out);

    try {
      return pkcs11Module.C_DecryptUpdate(sessionHandle, 0, in, inOfs,
          inLen, 0, out, outOfs, outLen);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * This method finalizes a decryption operation and returns the final
   * result. Use this method, if you fed in the data using decryptUpdate. If
   * you used the decrypt(byte[]) method, you need not (and shall not) call
   * this method, because decrypt(byte[]) finalizes the decryption itself.
   *
   * @param out
   *          buffer for the decrypted data
   * @param outOfs
   *          buffer offset for the decrypted data
   * @param outLen
   *          buffer size for the decrypted data
   * @return the length of this last part of decrypted data
   * @exception TokenException
   *              If calculating the final result failed.
   */
  public int decryptFinal(byte[] out, int outOfs, int outLen)
      throws TokenException {
    Util.requireNonNull("out", out);

    try {
      return pkcs11Module.C_DecryptFinal(sessionHandle, 0,
          out, outOfs, outLen);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Initializes a new digesting operation. The application must call this
   * method before calling any other digest* operation. Before initializing a
   * new operation, any currently pending operation must be finalized using
   * the appropriate *Final method (e.g. digestFinal()). There are exceptions
   * for dual-function operations. This method requires the mechanism to use
   * for digesting for this operation. For the mechanism the application may
   * use a constant defined in the Mechanism class.
   *
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.SHA_1.
   * @exception TokenException
   *              If initializing this operation failed.
   */
  public void digestInit(Mechanism mechanism) throws TokenException {
    try {
      pkcs11Module.C_DigestInit(sessionHandle, toCkMechanism(mechanism));
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Digests the given data with the mechanism given to the digestInit method.
   * This method finalizes the current digesting operation; i.e. the
   * application need (and should) not call digestFinal() after this call. For
   * digesting multiple pieces of data use digestUpdate and digestFinal.
   *
   * @param in
   *          buffer containing the to-be-digested data
   * @param inOfs
   *          buffer offset of the to-be-digested data
   * @param inLen
   *          length of the to-be-digested data
   * @param digest
   *          buffer for the digested data
   * @param digestOfs
   *          buffer offset for the digested data
   * @param digestLen
   *          buffer size for the digested data
   * @return the length of digested data for this update
   * @exception TokenException
   *              If digesting the data failed.
   */
  public int digest(byte[] in, int inOfs, int inLen, byte[] digest,
      int digestOfs, int digestLen) throws TokenException {
    digestUpdate(in, inOfs, inLen);
    return digestFinal(digest, digestOfs, digestLen);
  }

  /**
   * This method digests data in a single part.
   *
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.SHA_1.
   * @param in
   *          buffer containing the to-be-digested data
   * @param inOfs
   *          buffer offset of the to-be-digested data
   * @param inLen
   *          length of the to-be-digested data
   * @param digest
   *          buffer for the digested data
   * @param digestOfs
   *          buffer offset for the digested data
   * @param digestLen
   *          buffer size for the digested data
   * @return the length of digested data for this update
   * @throws TokenException
   *              If digesting the data failed.
   */
  public int digestSingle(Mechanism mechanism, byte[] in, int inOfs,
      int inLen, byte[] digest, int digestOfs, int digestLen)
      throws TokenException {
    Util.requireNonNull("in", in);
    Util.requireNonNull("digest", digest);

    try {
      return pkcs11Module.C_DigestSingle(sessionHandle,
          toCkMechanism(mechanism),
          in, inOfs, inLen, digest, digestOfs, digestLen);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * This method can be used to digest multiple pieces of data; e.g.
   * buffer-size pieces when reading the data from a stream. Digests the given
   * data with the mechanism given to the digestInit method. The application
   * must call digestFinal to get the final result of the digesting after
   * feeding in all data using this method.
   *
   * @param part
   *          buffer containing the to-be-digested data
   * @param partOfs
   *          buffer offset of the to-be-digested data
   * @param partLen
   *          length of the to-be-digested data
   * @exception TokenException
   *              If digesting the data failed.
   */
  public void digestUpdate(byte[] part, int partOfs, int partLen)
      throws TokenException {
    Util.requireNonNull("part", part);

    try {
      pkcs11Module.C_DigestUpdate(sessionHandle, 0, part, partOfs, partLen);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * This method is similar to digestUpdate and can be combined with it during
   * one digesting operation. This method digests the value of the given
   * secret key.
   *
   * @param key
   *          The key to digest the value of.
   * @exception TokenException
   *              If digesting the key failed.
   */
  public void digestKey(SecretKey key) throws TokenException {
    try {
      pkcs11Module.C_DigestKey(sessionHandle, key.getObjectHandle());
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * This method finalizes a digesting operation and returns the final result.
   * Use this method, if you fed in the data using digestUpdate and/or
   * digestKey. If you used the digest(byte[]) method, you need not (and shall
   * not) call this method, because digest(byte[]) finalizes the digesting
   * itself.
   *
   * @param digest
   *          buffer for the message digest
   * @param digestOfs
   *          buffer offset for the message digest
   * @param digestLen
   *          buffer size for the message digest
   * @return the length of message digest
   * @exception TokenException
   *              If calculating the final message digest failed.
   */
  public int digestFinal(byte[] digest, int digestOfs, int digestLen)
      throws TokenException {
    Util.requireNonNull("digest", digest);

    try {
      return pkcs11Module.C_DigestFinal(sessionHandle,
          digest, digestOfs, digestLen);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Initializes a new signing operation. Use it for signatures and MACs. The
   * application must call this method before calling any other sign*
   * operation. Before initializing a new operation, any currently pending
   * operation must be finalized using the appropriate *Final method
   * (e.g. digestFinal()). There are exceptions for dual-function operations.
   * This method requires the mechanism to use for signing and the key for
   * this operation. The key must have set its sign flag. For the mechanism
   * the application may use a constant defined in the Mechanism class. Notice
   * that the key and the mechanism must be compatible; i.e. you cannot use a
   * DES key with the RSA mechanism.
   *
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.RSA_PKCS.
   * @param key
   *          The signing key to use.
   * @exception TokenException
   *              If initializing this operation failed.
   */
  public void signInit(Mechanism mechanism, Key key) throws TokenException {
    try {
      pkcs11Module.C_SignInit(sessionHandle, toCkMechanism(mechanism),
          key.getObjectHandle());
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Signs the given data with the key and mechanism given to the signInit
   * method. This method finalizes the current signing operation; i.e. the
   * application need (and should) not call signFinal() after this call. For
   * signing multiple pieces of data use signUpdate and signFinal.
   *
   * @param data
   *          The data to sign.
   * @return The signed data.
   * @exception TokenException
   *              If signing the data failed.
   */
  public byte[] sign(byte[] data) throws TokenException {
    Util.requireNonNull("data", data);

    try {
      return pkcs11Module.C_Sign(sessionHandle, data);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * This method can be used to sign multiple pieces of data; e.g. buffer-size
   * pieces when reading the data from a stream. Signs the given data with the
   * mechanism given to the signInit method. The application must call
   * signFinal to get the final result of the signing after feeding in all
   * data using this method.
   *
   * @param in
   *          buffer containing the to-be-signed data
   * @param inOfs
   *          buffer offset of the to-be-signed data
   * @param inLen
   *          length of the to-be-signed data
   * @exception TokenException
   *              If signing the data failed.
   */
  public void signUpdate(byte[] in, int inOfs, int inLen)
      throws TokenException {
    Util.requireNonNull("in", in);

    try {
      pkcs11Module.C_SignUpdate(sessionHandle, 0, in, inOfs, inLen);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * This method finalizes a signing operation and returns the final result.
   * Use this method, if you fed in the data using signUpdate. If you used the
   * sign(byte[]) method, you need not (and shall not) call this method,
   * because sign(byte[]) finalizes the signing operation itself.
   *
   * @param expectedLen
   *          expected length of the signature value.
   * @return The final result of the signing operation; i.e. the signature
   *         value.
   * @exception TokenException
   *              If calculating the final signature value failed.
   */
  public byte[] signFinal(int expectedLen) throws TokenException {
    try {
      return pkcs11Module.C_SignFinal(sessionHandle, expectedLen);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Initializes a new signing operation for signing with recovery. The
   * application must call this method before calling signRecover. Before
   * initializing a new operation, any currently pending operation must be
   * finalized using the appropriate *Final method (e.g. digestFinal()). There
   * are exceptions for dual-function operations. This method requires the
   * mechanism to use for signing and the key for this operation. The key must
   * have set its sign-recover flag. For the mechanism the application may use
   * a constant defined in the Mechanism class. Notice that the key and the
   * mechanism must be compatible; i.e. you cannot use a DES key with the RSA
   * mechanism.
   *
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.RSA_9796.
   * @param key
   *          The signing key to use.
   * @exception TokenException
   *              If initializing this operation failed.
   */
  public void signRecoverInit(Mechanism mechanism, Key key)
      throws TokenException {
    try {
      pkcs11Module.C_SignRecoverInit(sessionHandle,
          toCkMechanism(mechanism), key.getObjectHandle());
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Signs the given data with the key and mechanism given to the
   * signRecoverInit method. This method finalizes the current sign-recover
   * operation; there is no equivalent method to signUpdate for signing with
   * recovery.
   *
   * @param in
   *          buffer containing the to-be-signed data
   * @param inOfs
   *          buffer offset of the to-be-signed data
   * @param inLen
   *          length of the to-be-signed data
   * @param out
   *          buffer for the signed data
   * @param outOfs
   *          buffer offset for the signed data
   * @param outLen
   *          buffer size for the signed data
   * @return the length of signed data
   * @exception TokenException
   *              If signing the data failed.
   */
  public int signRecover(byte[] in, int inOfs,
      int inLen, byte[] out, int outOfs, int outLen) throws TokenException {
    Util.requireNonNull("in", in);
    Util.requireNonNull("out", out);

    try {
      return pkcs11Module.C_SignRecover(sessionHandle, in, inOfs, inLen,
          out, outOfs, outLen);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Initializes a new verification operation. You can use it for verifying
   * signatures and MACs. The application must call this method before calling
   * any other verify* operation. Before initializing a new operation, any
   * currently pending operation must be finalized using the appropriate
   * *Final method (e.g. digestFinal()). There are exceptions for
   * dual-function operations. This method requires the mechanism to use for
   * verification and the key for this operation. The key must have set its
   * verify flag. For the mechanism the application may use a constant defined
   * in the Mechanism class. Notice that the key and the mechanism must be
   * compatible; i.e. you cannot use a DES key with the RSA mechanism.
   *
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.RSA_PKCS.
   * @param key
   *          The verification key to use.
   * @exception TokenException
   *              If initializing this operation failed.
   */
  public void verifyInit(Mechanism mechanism, Key key) throws TokenException {
    try {
      pkcs11Module.C_VerifyInit(sessionHandle, toCkMechanism(mechanism),
          key.getObjectHandle());
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Verifies the given signature against the given data with the key and
   * mechanism given to the verifyInit method. This method finalizes the
   * current verification operation; i.e. the application need (and should)
   * not call verifyFinal() after this call. For verifying with multiple
   * pieces of data use verifyUpdate and verifyFinal. This method throws an
   * exception, if the verification of the signature fails.
   *
   * @param data
   *          The data that was signed.
   * @param signature
   *          The signature or MAC to verify.
   * @exception TokenException
   *              If verifying the signature fails. This is also the case, if
   *              the signature is forged.
   */
  public void verify(byte[] data, byte[] signature) throws TokenException {
    Util.requireNonNull("signature", signature);

    try {
      pkcs11Module.C_Verify(sessionHandle, data, signature);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * This method can be used to verify a signature with multiple pieces of
   * data; e.g. buffer-size pieces when reading the data from a stream. To
   * verify the signature or MAC call verifyFinal after feeding in all data
   * using this method.
   *
   * @param in
   *          buffer containing the to-be-verified data
   * @param inOfs
   *          buffer offset of the to-be-verified data
   * @param inLen
   *          length of the to-be-verified data
   * @exception TokenException
   *              If verifying (e.g. digesting) the data failed.
   */
  public void verifyUpdate(byte[] in, int inOfs, int inLen)
      throws TokenException {
    Util.requireNonNull("in", in);

    try {
      pkcs11Module.C_VerifyUpdate(sessionHandle, 0, in, inOfs, inLen);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * This method finalizes a verification operation. Use this method, if you
   * fed in the data using verifyUpdate. If you used the verify(byte[])
   * method, you need not (and shall not) call this method, because
   * verify(byte[]) finalizes the verification operation itself. If this
   * method verified the signature successfully, it returns normally. If the
   * verification of the signature fails, e.g. if the signature was forged or
   * the data was modified, this method throws an exception.
   *
   * @param signature
   *          The signature value.
   * @exception TokenException
   *              If verifying the signature fails. This is also the case, if
   *              the signature is forged.
   */
  public void verifyFinal(byte[] signature) throws TokenException {
    Util.requireNonNull("signature", signature);

    try {
      pkcs11Module.C_VerifyFinal(sessionHandle, signature);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Initializes a new verification operation for verification with data
   * recovery. The application must call this method before calling
   * verifyRecover. Before initializing a new operation, any currently pending
   * operation must be finalized using the appropriate *Final method (e.g.
   * digestFinal()). This method requires the mechanism to use for
   * verification and the key for this operation. The key must have set its
   * verify-recover flag. For the mechanism the application may use a constant
   * defined in the Mechanism class. Notice that the key and the mechanism
   * must be compatible; i.e. you cannot use a DES key with the RSA mechanism.
   *
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.RSA_9796.
   * @param key
   *          The verification key to use.
   * @exception TokenException
   *              If initializing this operation failed.
   */
  public void verifyRecoverInit(Mechanism mechanism, Key key)
      throws TokenException {
    try {
      pkcs11Module.C_VerifyRecoverInit(sessionHandle,
          toCkMechanism(mechanism), key.getObjectHandle());
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Signs the given data with the key and mechanism given to the
   * signRecoverInit method. This method finalizes the current sign-recover
   * operation; there is no equivalent method to signUpdate for signing with
   * recovery.
   *
   * @param in
   *          buffer containing the to-be-verified data
   * @param inOfs
   *          buffer offset of the to-be-verified data
   * @param inLen
   *          length of the to-be-verified data
   * @param out
   *          buffer for the verified data
   * @param outOfs
   *          buffer offset for the verified data
   * @param outLen
   *          buffer size for the verified data
   * @return the length of verified data
   * @exception TokenException
   *              If signing the data failed.
   */
  public int verifyRecover(byte[] in, int inOfs,
      int inLen, byte[] out, int outOfs, int outLen) throws TokenException {
    Util.requireNonNull("in", in);
    Util.requireNonNull("out", out);

    try {
      return pkcs11Module.C_VerifyRecover(sessionHandle,
          in, inOfs, inLen, out, outOfs, outLen);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Dual-function. Continues a multipart dual digest and encryption
   * operation. This method call can also be combined with calls to
   * digestUpdate, digestKey and encryptUpdate. Call digestFinal and
   * encryptFinal to get the final results.
   *
   * @param part
   *          The piece of data to digest and encrypt.
   * @return The intermediate result of the encryption.
   * @exception TokenException
   *              If digesting or encrypting the data failed.
   */
  /*
  public byte[] digestEncryptedUpdate(byte[] part)
    throws TokenException {
    return pkcs11Module.C_DigestEncryptUpdate(sessionHandle, part);
  }
  */

  /**
   * Dual-function. Continues a multipart dual decrypt and digest operation.
   * This method call can also be combined with calls to digestUpdate,
   * digestKey and decryptUpdate. It is the recovered plaintext that gets
   * digested in this method call, not the given encryptedPart. Call
   * digestFinal and decryptFinal to get the final results.
   *
   * @param part
   *          The piece of data to decrypt and digest.
   * @return The intermediate result of the decryption; the decrypted data.
   * @exception TokenException
   *              If decrypting or digesting the data failed.
   */
  /*
  public byte[] decryptDigestUpdate(byte[] part)
    throws TokenException {
    return pkcs11Module.C_DecryptDigestUpdate(sessionHandle, part);
  }
  */

  /**
   * Dual-function. Continues a multipart dual sign and encrypt operation.
   * Calls to this method can also be combined with calls to signUpdate and
   * encryptUpdate. Call signFinal and encryptFinal to get the final results.
   *
   * @param part
   *          The piece of data to sign and encrypt.
   * @return The intermediate result of the encryption; the encrypted data.
   * @exception TokenException
   *              If signing or encrypting the data failed.
   */
  /*
  public byte[] signEncryptUpdate(byte[] part)
    throws TokenException {
    return pkcs11Module.C_SignEncryptUpdate(sessionHandle, part);
  }
  */

  /**
   * Dual-function. Continues a multipart dual decrypt and verify operation.
   * This method call can also be combined with calls to decryptUpdate and
   * verifyUpdate. It is the recovered plaintext that gets verified in this
   * method call, not the given encryptedPart. Call decryptFinal and
   * verifyFinal to get the final results.
   *
   * @param encryptedPart
   *          The piece of data to decrypt and verify.
   * @return The intermediate result of the decryption; the decrypted data.
   * @exception TokenException
   *              If decrypting or verifying the data failed.
   */
  /*
  public byte[] decryptVerifyUpdate(byte[] encryptedPart)
    throws TokenException {
    return pkcs11Module.C_DecryptVerifyUpdate(sessionHandle,
        encryptedPart);
  }
  */

  /**
   * Generate a new secret key or a set of domain parameters. It uses the set
   * attributes of the template for setting the attributes of the new key
   * object. As mechanism the application can use a constant of the Mechanism
   * class.
   *
   * @param mechanism
   *          The mechanism to generate a key for; e.g. Mechanism.DES to
   *          generate a DES key.
   * @param template
   *          The template for the new key or domain parameters; e.g. a
   *          DESSecretKey object which has set certain attributes.
   * @return The newly generated secret key or domain parameters.
   * @exception TokenException
   *              If generating a new secret key or domain parameters failed.
   */
  public PKCS11Object generateKey(Mechanism mechanism, PKCS11Object template)
      throws TokenException {
    CK_ATTRIBUTE[] ckAttributes = PKCS11Object.getSetAttributes(template);

    long objectHandle;
    try {
      objectHandle = pkcs11Module.C_GenerateKey(sessionHandle,
          toCkMechanism(mechanism), ckAttributes);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }

    return PKCS11Object.getInstance(this, objectHandle);
  }

  /**
   * Generate a new public key - private key key-pair and use the set
   * attributes of the template objects for setting the attributes of the new
   * public key and private key objects. As mechanism the application can use
   * a constant of the Mechanism class.
   *
   * @param mechanism
   *          The mechanism to generate a key for; e.g. Mechanism.RSA to
   *          generate a new RSA key-pair.
   * @param publicKeyTemplate
   *          The template for the new public key part; e.g. a RSAPublicKey
   *          object which has set certain attributes (e.g. public exponent
   *          and verify).
   * @param privateKeyTemplate
   *          The template for the new private key part; e.g. a RSAPrivateKey
   *          object which has set certain attributes (e.g. sign and decrypt).
   * @return The newly generated key-pair.
   * @exception TokenException
   *              If generating a new key-pair failed.
   */
  public KeyPair generateKeyPair(Mechanism mechanism,
      PKCS11Object publicKeyTemplate, PKCS11Object privateKeyTemplate)
      throws TokenException {
    CK_ATTRIBUTE[] ckPublicKeyAttributes =
        PKCS11Object.getSetAttributes(publicKeyTemplate);
    CK_ATTRIBUTE[] ckPrivateKeyAttributes =
        PKCS11Object.getSetAttributes(privateKeyTemplate);

    long[] objectHandles;
    try {
      objectHandles = pkcs11Module.C_GenerateKeyPair(sessionHandle,
          toCkMechanism(mechanism), ckPublicKeyAttributes,
          ckPrivateKeyAttributes);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }

    PublicKey publicKey =
        (PublicKey) PKCS11Object.getInstance(this, objectHandles[0]);
    PrivateKey privateKey =
        (PrivateKey) PKCS11Object.getInstance(this, objectHandles[1]);

    return new KeyPair(publicKey, privateKey);
  }

  /**
   * Wraps (encrypts) the given key with the wrapping key using the given
   * mechanism.
   *
   * @param mechanism
   *          The mechanism to use for wrapping the key.
   * @param wrappingKey
   *          The key to use for wrapping (encrypting).
   * @param key
   *          The key to wrap (encrypt).
   * @return The wrapped key as byte array.
   * @exception TokenException
   *              If wrapping the key failed.
   */
  public byte[] wrapKey(Mechanism mechanism, Key wrappingKey, Key key)
      throws TokenException {
    try {
      return pkcs11Module.C_WrapKey(sessionHandle, toCkMechanism(mechanism),
          wrappingKey.getObjectHandle(), key.getObjectHandle());
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Unwraps (decrypts) the given encrypted key with the unwrapping key using
   * the given mechanism. The application can also pass a template key to set
   * certain attributes of the unwrapped key. This creates a key object after
   * unwrapping the key and returns an object representing this key.
   *
   * @param mechanism
   *          The mechanism to use for unwrapping the key.
   * @param unwrappingKey
   *          The key to use for unwrapping (decrypting).
   * @param wrappedKey
   *          The encrypted key to unwrap (decrypt).
   * @param keyTemplate
   *          The template for creating the new key object.
   * @return A key object representing the newly created key object.
   * @exception TokenException
   *              If unwrapping the key or creating a new key object failed.
   */
  public Key unwrapKey(Mechanism mechanism, Key unwrappingKey,
      byte[] wrappedKey, PKCS11Object keyTemplate)
      throws TokenException {
    Util.requireNonNull("wrappedKey", wrappedKey);

    CK_ATTRIBUTE[] ckAttributes = PKCS11Object.getSetAttributes(keyTemplate);

    long objectHandle;
    try {
      objectHandle = pkcs11Module.C_UnwrapKey(sessionHandle,
          toCkMechanism(mechanism), unwrappingKey.getObjectHandle(),
          wrappedKey, ckAttributes);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }

    return (Key) PKCS11Object.getInstance(this, objectHandle);
  }

  /**
   * Derives a new key from a specified base key using the given mechanism.
   * After deriving a new key from the base key, a new key object is created
   * and a representation of it is returned. The application can provide a
   * template key to set certain attributes of the new key object.
   *
   * @param mechanism
   *          The mechanism to use for deriving the new key from the base key.
   * @param baseKey
   *          The key to use as base for derivation.
   * @param template
   *          The template for creating the new key object.
   * @return A key object representing the newly derived (created) key object
   *         or null, if the used mechanism uses other means to return its
   *         values; e.g. the CKM_SSL3_KEY_AND_MAC_DERIVE mechanism.
   * @exception TokenException
   *              If deriving the key or creating a new key object failed.
   */
  public Key deriveKey(Mechanism mechanism, Key baseKey, Key template)
      throws TokenException {
    CK_MECHANISM ckMechanism = toCkMechanism(mechanism);
    Parameters params = mechanism.getParameters();
    CK_ATTRIBUTE[] ckAttributes = PKCS11Object.getSetAttributes(template);

    long objectHandle;
    try {
      objectHandle = pkcs11Module.C_DeriveKey(sessionHandle,
          toCkMechanism(mechanism), baseKey.getObjectHandle(), ckAttributes);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }

    /*
     * for certain mechanisms we must copy back the returned values to the
     * parameters object of the given mechanism
     */
    if ((ckMechanism.mechanism
          == PKCS11Constants.CKM_SSL3_MASTER_KEY_DERIVE
        || ckMechanism.mechanism
          == PKCS11Constants.CKM_TLS_MASTER_KEY_DERIVE)
        && (params instanceof SSL3MasterKeyDeriveParameters)) {
      /*
       * The SSL3MasterKeyDeriveParameters object need special handling
       * due to their deeper nesting of their data structure, which needs
       * to be copied back to get all the results.
       */
      // set the returned client version
      VersionParameters version =
          ((SSL3MasterKeyDeriveParameters) params).getVersion();
      version.setPKCS11ParamsObject(
          ((CK_SSL3_MASTER_KEY_DERIVE_PARAMS)
              (ckMechanism.pParameter)).pVersion);
      return (Key) PKCS11Object.getInstance(this, objectHandle);
    } else if ((ckMechanism.mechanism
          == PKCS11Constants.CKM_TLS12_MASTER_KEY_DERIVE)
        && (params instanceof TLS12MasterKeyDeriveParameters)) {
      // set the returned client version
      VersionParameters version =
          ((TLS12MasterKeyDeriveParameters) params).getVersion();
      CK_VERSION ckVersion =
          TLS12MasterKeyDeriveParameters.getPVersion(ckMechanism.pParameter);
      version.setPKCS11ParamsObject(ckVersion);
      return (Key) PKCS11Object.getInstance(this, objectHandle);
    } else if ((ckMechanism.mechanism
            == PKCS11Constants.CKM_SSL3_KEY_AND_MAC_DERIVE
          || ckMechanism.mechanism
            == PKCS11Constants.CKM_TLS_KEY_AND_MAC_DERIVE)
        && (params instanceof SSL3KeyMaterialParameters)) {
      /*
       * The SSL3KeyMaterialParameters object need special handling due to
       * their deeper nesting of their data structure, which needs to be
       * copied back to get all the results.
       */
      // set the returned secret keys and IVs
      ((SSL3KeyMaterialParameters) params).getReturnedKeyMaterial()
          .setPKCS11ParamsObject(
              ((CK_SSL3_KEY_MAT_PARAMS) ckMechanism.pParameter)
            .pReturnedKeyMaterial,
          this);
      /*
       * this mechanism returns its keys and values through the parameters
       * object of the mechanism, but it does not return a key
       */
      return null;
    } else if ((ckMechanism.mechanism
            == PKCS11Constants.CKM_TLS12_KEY_AND_MAC_DERIVE)
        && (params instanceof TLS12KeyMaterialParameters)) {
      // set the returned secret keys and IVs
      CK_SSL3_KEY_MAT_OUT pReturnedMaterial =
          TLS12KeyMaterialParameters.getPReturnedKeyMaterial(
              ckMechanism.pParameter);

      ((TLS12KeyMaterialParameters) params).getReturnedKeyMaterial()
          .setPKCS11ParamsObject(pReturnedMaterial, this);
      /*
       * this mechanism returns its keys and values through the parameters
       * object of the mechanism, but it does not return a key
       */
      return null;
    } else {
      return (Key) PKCS11Object.getInstance(this, objectHandle);
    }
  }

  /**
   * Mixes additional seeding material into the random number generator.
   *
   * @param seed
   *          The seed bytes to mix in.
   * @exception TokenException
   *              If mixing in the seed failed.
   */
  public void seedRandom(byte[] seed) throws TokenException {
    try {
      pkcs11Module.C_SeedRandom(sessionHandle, seed);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Generates a certain number of random bytes.
   *
   * @param numberOfBytesToGenerate
   *          The number of random bytes to generate.
   * @return An array of random bytes with length numberOfBytesToGenerate.
   * @exception TokenException
   *              If generating random bytes failed.
   */
  public byte[] generateRandom(int numberOfBytesToGenerate)
      throws TokenException {
    byte[] randomBytesBuffer = new byte[numberOfBytesToGenerate];
    try {
      pkcs11Module.C_GenerateRandom(sessionHandle, randomBytesBuffer);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    } // fill the buffer with random bytes
    return randomBytesBuffer;
  }

  /**
   * Legacy function that will normally throw an PKCS11Exception with the
   * error-code PKCS11Constants.CKR_FUNCTION_NOT_PARALLEL.
   *
   * @exception TokenException
   *              Throws always an PKCS11Excption.
   */
  /*
  public void getFunctionStatus()
    throws TokenException {
    pkcs11Module.C_GetFunctionStatus(sessionHandle);
  }*/

  /**
   * Legacy function that will normally throw an PKCS11Exception with the
   * error-code PKCS11Constants.CKR_FUNCTION_NOT_PARALLEL.
   *
   * @exception TokenException
   *              Throws always an PKCS11Excption.
   */
  /*
  public void cancelFunction()
    throws TokenException {
    pkcs11Module.C_CancelFunction(sessionHandle);
  }*/

  /**
   * Returns the string representation of this object.
   *
   * @return the string representation of this object
   */
  @Override
  public String toString() {
    return Util.concatObjectsCap(100,
        "Session Handle: 0x", Long.toHexString(sessionHandle),
        "\nToken: ", token);
  }

  private static CK_MECHANISM toCkMechanism(Mechanism mechanism) {
    long code = mechanism.getMechanismCode();
    Parameters params = mechanism.getParameters();
    if (params == null) {
      return new CK_MECHANISM(code);
    } else if (params instanceof AesCtrParameters) {
      return new CK_MECHANISM(code,
          ((AesCtrParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof DHPkcsDeriveParameters) {
      return new CK_MECHANISM(code,
          ((DHPkcsDeriveParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof EcDH1KeyDerivationParameters) {
      return new CK_MECHANISM(code,
          ((EcDH1KeyDerivationParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof EcDH2KeyDerivationParameters) {
//      return new CK_MECHANISM(code,
//          ((EcDH2KeyDerivationParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof ExtractParameters) {
      return new CK_MECHANISM(code,
          ((ExtractParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof InitializationVectorParameters) {
      return new CK_MECHANISM(code,
          ((InitializationVectorParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof MacGeneralParameters) {
      return new CK_MECHANISM(code,
          ((MacGeneralParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof ObjectHandleParameters) {
      return new CK_MECHANISM(code,
          ((ObjectHandleParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof OpaqueParameters) {
      return new CK_MECHANISM(code,
          ((OpaqueParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof PBEParameters) {
//      return new CK_MECHANISM(code,
//          ((PBEParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof PKCS5PBKD2Parameters) {
//      return new CK_MECHANISM(code,
//          ((PKCS5PBKD2Parameters) params).getPKCS11ParamsObject());
    } else if (params instanceof RSAPkcsOaepParameters) {
//      return new CK_MECHANISM(code,
//          ((RSAPkcsOaepParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof RSAPkcsPssParameters) {
      CK_MECHANISM mech = new CK_MECHANISM(code);
      CK_RSA_PKCS_PSS_PARAMS pParams =
          ((RSAPkcsPssParameters) params).getPKCS11ParamsObject();
      try {
        if (field_CK_MECHANISM_pParameter != null) {
          field_CK_MECHANISM_pParameter.set(mech, pParams);
        } else if (method_CK_MECHANISM_setParameter != null) {
          method_CK_MECHANISM_setParameter.invoke(mech, pParams);
        } else {
          throw new IllegalStateException(
              "could not construct CK_MECHANISM for RSAPkcsPssParams");
        }
      } catch (IllegalAccessException | InvocationTargetException ex) {
        throw new IllegalStateException(
            "could not construct CK_MECHANISM for RSAPkcsPssParams", ex);
      }
      return mech;
    } else if (params instanceof SSL3KeyMaterialParameters) {
      return new CK_MECHANISM(code,
          ((SSL3KeyMaterialParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof SSL3KeyMaterialParameters) {
      return new CK_MECHANISM(code,
          ((SSL3KeyMaterialParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof SSL3MasterKeyDeriveParameters) {
      return new CK_MECHANISM(code,
          ((SSL3MasterKeyDeriveParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof SSL3RandomDataParameters) {
//      return new CK_MECHANISM(code,
//          ((SSL3RandomDataParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof TLSPRFParameters) {
      return new CK_MECHANISM(code,
          ((TLSPRFParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof VersionParameters) {
      return new CK_MECHANISM(code,
          ((VersionParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof X942DH1KeyDerivationParameters) {
//      return new CK_MECHANISM(code,
//          ((X942DH1KeyDerivationParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof X942DH2KeyDerivationParameters) {
//      return new CK_MECHANISM(code,
//          ((X942DH2KeyDerivationParameters) params).getPKCS11ParamsObject());
    } else {
      Constructor<?> constructor;
      if (params instanceof CCMParameters) {
        constructor = constructor_CK_MECHANISM_CCM;
      } else if (params instanceof GCMParameters) {
        constructor = constructor_CK_MECHANISM_GCM;
      } else if (params instanceof TLS12KeyMaterialParameters) {
        constructor = constructor_CK_MECHANISM_TLS12KeyMat;
      } else if (params instanceof TLS12MasterKeyDeriveParameters) {
        constructor = constructor_CK_MECHANISM_TLS12MasterKeyDerive;
      } else if (params instanceof TLSMacParameters) {
        constructor = constructor_CK_MECHANISM_TLSMac;
      } else {
        constructor = null;
      }

      if (constructor == null) {
        throw new IllegalArgumentException("could not find constructor");
      }
      try {
        return (CK_MECHANISM) constructor.newInstance(
            code, params.getPKCS11ParamsObject());
      } catch (InstantiationException | IllegalAccessException
          | IllegalArgumentException | InvocationTargetException ex) {
        throw new IllegalArgumentException(
            "could not construct CK_MECHANISM", ex);
      }
    }

    throw new IllegalArgumentException(
        "Unsupported Parameters " + params.getClass().getName());
  }

}
