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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Map;

import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import sun.security.pkcs11.wrapper.CK_CREATEMUTEX;
import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import sun.security.pkcs11.wrapper.CK_DESTROYMUTEX;
import sun.security.pkcs11.wrapper.CK_INFO;
import sun.security.pkcs11.wrapper.CK_LOCKMUTEX;
import sun.security.pkcs11.wrapper.CK_UNLOCKMUTEX;
import sun.security.pkcs11.wrapper.PKCS11;
//FIXME: check if pkcs11module is not null.
/**
 * Objects of this class represent a PKCS#11 module. The application should
 * create an instance by calling getInstance and passing the name of the
 * PKCS#11 module of the desired token; e.g. "slbck.dll". The application
 * must give the full path of the PKCS#11 module unless the module is in the
 * system's search path or in the path of the java.library.path system
 * property.
 * <p/>
 * According to the specification, the application must call the initialize
 * method before calling any other method of the module.
 * This class contains slot and token management functions as defined by the
 * PKCS#11 standard.
 *
 * All applications using this library will contain the following code.
 * <pre><code>
 *      Module pkcs11Module = Module.getInstance("cryptoki.dll");
 *      pkcs11Module.initialize(null);
 *
 *      // ... work with the module
 *
 *      pkcs11Module.finalize(null);
 * </code></pre>
 * Instead of <code>cryptoki.dll</code>, the application will use the name of
 * the PKCS#11 module of the installed crypto hardware.
 * After the application initialized the module, it can get a list of all
 * available slots. A slot is an object that represents a physical or logical
 * device that can accept a cryptographic token; for instance, the card slot of
 * a smart card reader. The application can call
 * <pre><code>
 * Slot[] slots = pkcs11Module.getSlotList(Module.SlotRequirement.ALL_SLOTS);
 * </code></pre>
 * to get a list of all available slots or
 * <pre><code>
 * Slot[] slotsWithToken = pkcs11Module.getSlotList(
 *                             Module.SlotRequirement.TOKEN_PRESENT);
 * </code></pre>
 * to get a list of all those slots in which there is a currently a token
 * present.
 * <p/>
 * To wait for the insertion of a token, the application can use the
 * <code>waitForSlotEvent</code> method. For example, the method call
 * <pre><code>
 * Slot eventSlot = pkcs11Module.waitForSlotEvent(
 *                      Module.WaitingBehavior.DONT_BLOCK, null);
 * </code></pre>
 * will block until an event for any slot of this module occurred. Usually such
 * an event is the insertion of a token. However, the application should check
 * if the event occurred in the slot of interest and if there is really a token
 * present in the slot.
 *
 * @see iaik.pkcs.pkcs11.Info
 * @see iaik.pkcs.pkcs11.Slot
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (pkcs11Module <> null)
 */

public class Module {

  /**
   * This interface defines the required properties for a slot. The
   * application uses one of the defined constants as parameter when calling
   * getSlotList.
   *
   * @version 1.0
   * @invariants
   */
  public static interface SlotRequirement {

    /**
     * Causes getSlotList to return all slots of the system that the
     * respective module supports.
     */
    static boolean ALL_SLOTS = false;

    /**
     * Causes getSlotList to return only those slots in which there is
     * currently a token present; e.g. there is a smart card in the reader's
     * slot.
     */
    static boolean TOKEN_PRESENT = true;

  }

  /**
   * This interface defines the allowed constants for the wanted waiting
   * behavior when calling waitForSlotEvent.
   *
   * @version 1.0
   * @invariants
   */
  public static interface WaitingBehavior {

    /**
     * Tells waitForSlotEvent to block until an event occurs.
     */
    static final boolean BLOCK = false;

    /**
     * Tells waitForSlotEvent to return immediately.
     */
    static final boolean DONT_BLOCK = true;

  }

  /**
   * Interface to the underlying PKCS#11 module.
   */
  private PKCS11 pkcs11Module;

  private String pkcs11ModuleName;

  /**
   * Create a new module that uses the given PKCS11 interface to interact with
   * the token.
   *
   * @param pkcs11Module
   *          The interface to interact with the token.
   * @preconditions
   * @postconditions
   */
  public Module(String pkcs11ModuleName) {
    this.pkcs11ModuleName = pkcs11ModuleName;
  }

  /**
   * Get an instance of this class by giving the name of the PKCS#11 module;
   * e.g. "slbck.dll".
   *
   * @param pkcs11ModuleName
   *          The name of the module; e.g. "slbck.dll".
   * @return An instance of Module that is connected to the given PKCS#11
   *         module.
   * @exception IOException
   *              If connecting to the named module fails.
   * @preconditions (pkcs11ModuleName <> null)
   *                and (pkcs11ModuleName is a valid PKCS#11 module name)
   * @postconditions
   */
  public static Module getInstance(String pkcs11ModuleName) throws IOException {
    Util.requireNonNull("pkcs11ModuleName", pkcs11ModuleName);
    File file = new File(pkcs11ModuleName);
    if (!file.exists()) {
      throw new FileNotFoundException(
          "File " + pkcs11ModuleName + " does not exist");
    }
    if (!file.isFile()) {
      throw new IOException(pkcs11ModuleName + " is not a file");
    }
    if (!file.canRead()) {
      throw new IOException("Can not read file " + pkcs11ModuleName + "");
    }
    return new Module(pkcs11ModuleName);
  }

  /**
   * Get an instance of this class by giving the name of the PKCS#11 module,
   * e.g. "slbck.dll" and the absolute path to the PKCS#11-wrapper native
   * library.
   *
   * @param pkcs11ModuleName
   *          The name of the module; e.g. "slbck.dll".
   * @param pkcs11WrapperPath
   *          The absolute path to the PKCS#11-wrapper native library.
   * @return An instance of Module that is connected to the given PKCS#11
   *         module using the specified PKCS#11-wrapper native library.
   * @exception IOException
   *              If connecting to the named module fails.
   * @preconditions (pkcs11ModuleName <> null)
   *                and (pkcs11ModuleName is a valid PKCS#11 module name)
   * @postconditions
   */
  /*
  public static Module getInstance(String pkcs11ModuleName,
      String pkcs11WrapperPath)
    throws IOException {
    Util.requireNotNull("pkcs11ModuleName", pkcs11ModuleName);
    PKCS11 pkcs11Module = PKCS11Connector.connectToPKCS11Module(
      pkcs11ModuleName, pkcs11WrapperPath);

    return new Module(pkcs11Module);
  }*/

  /**
   * Gets information about the module; i.e. the PKCS#11 module behind.
   *
   * @return A object holding information about the module.
   * @exception TokenException
   *              If getting the information fails.
   * @preconditions
   * @postconditions (result <> null)
   */
  public Info getInfo() throws TokenException {
    assertInitialized();
    CK_INFO ckInfo;
    try {
      ckInfo = pkcs11Module.C_GetInfo();
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }

    return new Info(ckInfo);
  }

  /**
   * Initializes the module. The application must call this method before
   * calling any other method of the module.
   *
   * @param initArgs
   *          The initialization arguments for the module as defined in
   *          PKCS#11. May be null.
   * @exception TokenException
   *              If initialization fails.
   * @preconditions
   * @postconditions
   */
  public void initialize(InitializeArgs initArgs) throws TokenException {
    CK_C_INITIALIZE_ARGS wrapperInitArgs = null;
    if (initArgs != null) {
      InitializeArgs castedInitArgs = initArgs;
      final MutexHandler mutexHandler = castedInitArgs.getMutexHandler();
      wrapperInitArgs = new CK_C_INITIALIZE_ARGS();
      if (mutexHandler != null) {
        wrapperInitArgs.CreateMutex = new CK_CREATEMUTEX() {
          // CHECKSTYLE:SKIP
          public Object CK_CREATEMUTEX()
              throws sun.security.pkcs11.wrapper.PKCS11Exception {
            return mutexHandler.createMutex();
          }
        };
        wrapperInitArgs.DestroyMutex = new CK_DESTROYMUTEX() {
          // CHECKSTYLE:SKIP
          public void CK_DESTROYMUTEX(Object pMutex)
              throws sun.security.pkcs11.wrapper.PKCS11Exception {
            mutexHandler.destroyMutex(pMutex);
          }
        };
        wrapperInitArgs.LockMutex = new CK_LOCKMUTEX() {
          // CHECKSTYLE:SKIP
          public void CK_LOCKMUTEX(Object pMutex)
              throws sun.security.pkcs11.wrapper.PKCS11Exception {
            mutexHandler.lockMutex(pMutex);
          }
        };
        wrapperInitArgs.UnlockMutex = new CK_UNLOCKMUTEX() {
          // CHECKSTYLE:SKIP
          public void CK_UNLOCKMUTEX(Object pMutex)
              throws sun.security.pkcs11.wrapper.PKCS11Exception {
            mutexHandler.unlockMutex(pMutex);
          }
        };
      } else {
        wrapperInitArgs.CreateMutex = null;
        wrapperInitArgs.DestroyMutex = null;
        wrapperInitArgs.LockMutex = null;
        wrapperInitArgs.UnlockMutex = null;
      }

      if (castedInitArgs.isLibraryCantCreateOsThreads()) {
        wrapperInitArgs.flags |=
            PKCS11Constants.CKF_LIBRARY_CANT_CREATE_OS_THREADS;
      }
      if (castedInitArgs.isOsLockingOk()) {
        wrapperInitArgs.flags |= PKCS11Constants.CKF_OS_LOCKING_OK;
      }
      wrapperInitArgs.pReserved = castedInitArgs.getReserved();
    }
    // pReserved of CK_C_INITIALIZE_ARGS not used yet, just set to standard
    // conform UTF8

    final String functionList = "C_GetFunctionList";
    final boolean omitInitialize = false;
    try {
      pkcs11Module = PKCS11.getInstance(pkcs11ModuleName, functionList,
          wrapperInitArgs, omitInitialize);
    } catch (IOException ex) {
      throw new TokenException(ex.getMessage(), ex);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Gets a list of slots that can accept tokens that are compatible with this
   * module; e.g. a list of PC/SC smart card readers. The parameter determines
   * if the method returns all compatible slots or only those in which there
   * is a compatible token present.
   *
   * @param tokenPresent
   *          Can be SlotRequirement.ALL_SLOTS or
   *          SlotRequirement.TOKEN_PRESENT.
   * @return An array of Slot objects. May be an empty array but not null.
   * @exception TokenException
   *              If .
   * @preconditions
   * @postconditions (result <> null)
   */
  public Slot[] getSlotList(boolean tokenPresent) throws TokenException {
    assertInitialized();
    long[] slotIDs;
    try {
      slotIDs = pkcs11Module.C_GetSlotList(tokenPresent);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
    Slot[] slots = new Slot[slotIDs.length];
    for (int i = 0; i < slots.length; i++) {
      slots[i] = new Slot(this, slotIDs[i]);
    }

    return slots;
  }

  /**
   * Waits for an slot event. That can be that a token was inserted or
   * removed. It returns the Slot for which an event occurred. The dontBlock
   * parameter can have the value WaitingBehavior.BLOCK or
   * WaitingBehavior.DONT_BLOCK.
   * If there is no event present and the method is called with
   * WaitingBehavior.DONT_BLOCK this method throws an exception with the error
   * code PKCS11Constants.CKR_NO_EVENT (0x00000008).
   *
   * @param dontBlock
   *          Can be WaitingBehavior.BLOCK or WaitingBehavior.DONT_BLOCK.
   * @param reserved
   *          Should be null for this version.
   * @return The slot for which an event occurred.
   * @exception TokenException
   *              If the method was called with WaitingBehavior.DONT_BLOCK but
   *              there was no event available, or if an error occurred.
   * @preconditions (reserved == null)
   * @postconditions (result <> null)
   */
  /*
  public Slot waitForSlotEvent(boolean dontBlock, PKCS11Object reserved)
    throws TokenException {
    long flags = (dontBlock) ? PKCS11Constants.CKF_DONT_BLOCK : 0L;
    long slotID = pkcs11Module_.C_WaitForSlotEvent(flags, reserved);

    return new Slot(this, slotID);
  }*/

  /**
   * Gets the PKCS#11 module of the wrapper package behind this object.
   *
   * @return The PKCS#11 module behind this object.
   * @preconditions
   * @postconditions (result <> null)
   */
  // CHECKSTYLE:SKIP
  public PKCS11 getPKCS11Module() {
    assertInitialized();
    return pkcs11Module;
  }

  /**
   * Returns the string representation of this object.
   *
   * @return The string representation of object
   */
  public String toString() {
    return (pkcs11Module != null) ? pkcs11Module.toString() : null;
  }

  /**
   * <B>Caution:
   * Unlike the original PKCS#11 wrapper, we only call initialize() once per
   * native .so/.dll. Once finalize(Object) has been called, the module cannot
   * be initialized anymore.
   * </B>
   * <p/>
   * Finalizes this module. The application should call this method when it
   * finished using the module.
   * Note that this method is different from the <code>finalize</code> method,
   * which is the reserved Java method called by the garbage collector.
   * This method calls the <code>C_Finalize(PKCS11Object)</code> method of the
   * underlying PKCS11 module.
   *
   * @param args
   *          Must be null in version 2.x of PKCS#11.
   * @exception TokenException
   *              If finalization fails.
   * @preconditions (args == null)
   * @postconditions
   */
  public void finalize(Object args) throws TokenException {
    if (pkcs11Module == null) {
      return;
    }

    try {
      pkcs11Module.C_Finalize(args);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }

    if (Util.getJavaVersion() < 11) {
      try {
        Field field = PKCS11.class.getDeclaredField("moduleMap");
        field.setAccessible(true);
        @SuppressWarnings("unchecked")
        Map<String,PKCS11> moduleMap = (Map<String,PKCS11>) field.get(null);
        moduleMap.remove(pkcs11ModuleName);
      } catch (Throwable th) {
        throw new TokenException(
            "could not remove module " + pkcs11ModuleName + " from the moduleMap");
      }
    }

  }

  /**
   * Compares the pkcs11Module_ this object with the other object.
   * Returns only true, if those are equal in both objects.
   *
   * @param otherObject
   *          The other Module object.
   * @return True, if other is an instance of Module and the pkcs11Module_ of
   *         both objects are equal. False, otherwise.
   * @preconditions
   * @postconditions
   */
  @Override
  public boolean equals(Object otherObject) {
    if (this == otherObject) {
      return true;
    } else if (!(otherObject instanceof Module)) {
      return false;
    }

    Module other = (Module) otherObject;
    return Util.objEquals(this.pkcs11Module, other.pkcs11Module);
  }

  /**
   * The overriding of this method should ensure that the objects of this
   * class work correctly in a hashtable.
   *
   * @return The hash code of this object. Gained from the sessionHandle.
   * @preconditions
   * @postconditions
   */
  @Override
  public int hashCode() {
    return pkcs11Module == null ? 0 : pkcs11Module.hashCode();
  }

  private void assertInitialized() {
    if (pkcs11Module == null) {
      throw new IllegalStateException(
          "Module not initialized yet, please call initialize() first");
    }
  }

}
