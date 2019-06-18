// Copyright (c) 2002 Graz University of Technology. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
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
//    Technology" must not be used to endorse or promote products derived from this
//    software without prior written permission.
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

package demo.pkcs.pkcs11.wrapper.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.cert.X509CertificateHolder;

import demo.pkcs.pkcs11.wrapper.adapters.KeyAndCertificate;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.TokenInfo;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.PKCS11Object;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;

/**
 * This class contains only static methods. It is the place for all functions that are used by
 * several classes in this package.
 *
 * @author Karl Scheibelhofer
 */
public class Util {

  /**
   * Lists all available tokens of the given module and lets the user select one, if there is more
   * than one available.
   *
   * @param pkcs11Module
   *          The PKCS#11 module to use.
   * @param output
   *          The output stream to write the user prompts to.
   * @param input
   *          The input stream where to read user input from.
   * @return The selected token or null, if no token is available or the user canceled the action.
   * @exception TokenException
   *              If listing the tokens failed.
   * @exception IOException
   *              If writing a user prompt faild or if reading user input failed.
   * @preconditions (pkcs11Module <> null) and (output <> null) and (input <> null)
   *
   */
  public static Token selectToken(Module pkcs11Module, PrintWriter output,
      BufferedReader input) throws TokenException, IOException {
    return selectToken(pkcs11Module, output, input, null);
  }

  /**
   * Lists all available tokens of the given module and lets the user select one, if there is more
   * than one available. Supports token preselection.
   *
   * @param pkcs11Module
   *          The PKCS#11 module to use.
   * @param output
   *          The output stream to write the user prompts to.
   * @param input
   *          The input stream where to read user input from.
   * @return The selected token or null, if no token is available or the user canceled the action.
   * @exception TokenException
   *              If listing the tokens failed.
   * @exception IOException
   *              If writing a user prompt faild or if reading user input failed.
   * @preconditions (pkcs11Module <> null) and (output <> null) and (input <> null)
   *
   */
  public static Token selectToken(Module pkcs11Module, PrintWriter output,
      BufferedReader input, String slot) throws TokenException, IOException {
    if (pkcs11Module == null) {
      throw new NullPointerException("Argument \"pkcs11Module\" must not be null.");
    }
    if (output == null) {
      throw new NullPointerException("Argument \"output\" must not be null.");
    }
    if (input == null) {
      throw new NullPointerException("Argument \"input\" must not be null.");
    }

    output
        .println("################################################################################");
    output.println("getting list of all tokens");
    Slot[] slotsWithToken = pkcs11Module
        .getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
    HashMap<Long, Token> tokenIDtoToken = new HashMap<>(slotsWithToken.length);

    for (int i = 0; i < slotsWithToken.length; i++) {
      Token token = slotsWithToken[i].getToken();
      TokenInfo tokenInfo = token.getTokenInfo();
      if (!tokenInfo.isTokenInitialized()) {
        continue;
      }
      long tokenID = token.getTokenID();
      tokenIDtoToken.put(tokenID, token);
      output
        .println("________________________________________________________________________________");
      output.println("Token ID: " + tokenID);
      output.println(tokenInfo);
      output
          .println("________________________________________________________________________________");
    }
    output
        .println("################################################################################");

    output
        .println("################################################################################");
    Token token = null;
    Long selectedTokenID = null;
    int size = tokenIDtoToken.size(); 
    if (size == 0) {
      output.println("There is no slot with a present token.");
    } else if (size == 1) {
      selectedTokenID = tokenIDtoToken.keySet().iterator().next();
      output.println("Taking token with ID: " + selectedTokenID);
      token = tokenIDtoToken.get(selectedTokenID);
    } else {
      boolean gotTokenID = false;
      while (!gotTokenID) {
        output.print("Enter the ID of the token to use or 'x' to exit: ");
        output.flush();
        String tokenIDstring;
        if (null != slot) {
          tokenIDstring = slot;
          output.print(slot + "\n");
        } else
          tokenIDstring = input.readLine();

        if (tokenIDstring.equalsIgnoreCase("x")) {
          break;
        }
        try {
          selectedTokenID = Long.valueOf(tokenIDstring);
          token = (Token) tokenIDtoToken.get(selectedTokenID);
          if (token != null) {
            gotTokenID = true;
          } else {
            output.println("A token with the entered ID \"" + tokenIDstring
                + "\" does not exist. Try again.");
          }
        } catch (NumberFormatException ex) {
          output.println("The entered ID \"" + tokenIDstring
              + "\" is invalid. Try again.");
        }
      }
    }
    output
        .println("################################################################################");

    return token;
  }

  /**
   * Opens an authorized session for the given token. If the token requires the user to login for
   * private operations, the method loggs in the user.
   *
   * @param token
   *          The token to open a session for.
   * @param rwSession
   *          If the session should be a read-write session. This may be
   *          Token.SessionReadWriteBehavior.RO_SESSION or
   *          Token.SessionReadWriteBehavior.RW_SESSION.
   * @param output
   *          The output stream to write the user prompts to.
   * @param input
   *          The input stream where to read user input from.
   * @return The selected token or null, if no token is available or the user canceled the action.
   * @exception TokenException
   *              If listing the tokens failed.
   * @exception IOException
   *              If writing a user prompt faild or if reading user input failed.
   * @preconditions (token <> null) and (output <> null) and (input <> null)
   * @postconditions (result <> null)
   */
  public static Session openAuthorizedSession(Token token, boolean rwSession,
      PrintWriter output, BufferedReader input) throws TokenException, IOException {
    return openAuthorizedSession(token, rwSession, output, input, null);
  }

  /**
   * Opens an authorized session for the given token. If the token requires the user to login for
   * private operations, the method loggs in the user.
   *
   * @param token
   *          The token to open a session for.
   * @param rwSession
   *          If the session should be a read-write session. This may be
   *          Token.SessionReadWriteBehavior.RO_SESSION or
   *          Token.SessionReadWriteBehavior.RW_SESSION.
   * @param output
   *          The output stream to write the user prompts to.
   * @param input
   *          The input stream where to read user input from.
   * @return The selected token or null, if no token is available or the user canceled the action.
   * @exception TokenException
   *              If listing the tokens failed.
   * @exception IOException
   *              If writing a user prompt faild or if reading user input failed.
   * @preconditions (token <> null) and (output <> null) and (input <> null)
   * @postconditions (result <> null)
   */
  public static Session openAuthorizedSession(Token token, boolean rwSession,
      PrintWriter output, BufferedReader input, String pin) throws TokenException,
      IOException {
    if (token == null) {
      throw new NullPointerException("Argument \"token\" must not be null.");
    }
    if (output == null) {
      throw new NullPointerException("Argument \"output\" must not be null.");
    }
    if (input == null) {
      throw new NullPointerException("Argument \"input\" must not be null.");
    }

    output
        .println("################################################################################");
    output.println("opening session");
    Session session = token.openSession(Token.SessionType.SERIAL_SESSION, rwSession,
        null, null);

    TokenInfo tokenInfo = token.getTokenInfo();
    if (tokenInfo.isLoginRequired()) {
      if (tokenInfo.isProtectedAuthenticationPath()) {
        output.print("Please enter the user-PIN at the PIN-pad of your reader.");
        output.flush();
        session.login(Session.UserType.USER, null); // the token prompts the PIN by other means;
                                                    // e.g. PIN-pad
      } else {
        /*
        output.print("Enter user-PIN and press [return key]: ");
        output.flush();
        String userPINString;
        if (null != pin) {
          userPINString = pin;
          output.println(pin);
        } else
          userPINString = input.readLine();
          */
        String userPINString = "123456"; 
        session.login(Session.UserType.USER, userPINString.toCharArray());
      }
    }
    output
        .println("################################################################################");

    return session;
  }

  /**
   * Picks the first suitable key template. If there is a corresponding certificate for a key, this
   * method displays the certificate for this key.
   *
   * @param session
   *          The session to use for key and certificate searching.
   * @param keyTemplate
   *          The template for searching for keys.
   * @param output
   *          The output stream to write the user prompts to.
   * @param input
   *          The input stream where to read user input from.
   * @return The selected key or null, if there is no matching key or the user canceled the
   *         operation. The return object also contains a corresponding certificate, if there is one
   *         for the selected key.
   * @exception TokenException
   *              If searching for keys or certificates failed.
   * @exception IOException
   *              If writing a user prompt faild or if reading user input failed.
   * @preconditions (session <> null) and (keyTemplate <> keyTemplate) and (output <> null) and
   *                (input <> null)
   * @postconditions (result <> null)
   */
  public static KeyAndCertificate selectKeyAndCertificate(Session session,
      Key keyTemplate, PrintWriter output, BufferedReader input) throws TokenException,
      IOException {
    return selectKeyAndCertificate(session, keyTemplate, output, input, false);
  }

  /**
   * Lists all keys that match the given key template and lets the user choose one, if there is more
   * than one. If there is a corresponding certificate for a key, this method displays the
   * certificate for this key.
   *
   * @param session
   *          The session to use for key and certificate searching.
   * @param keyTemplate
   *          The template for searching for keys.
   * @param output
   *          The output stream to write the user prompts to.
   * @param input
   *          The input stream where to read user input from.
   * @param pick
   *          first suitable key if true
   * @return The selected key or null, if there is no matching key or the user canceled the
   *         operation. The return object also contains a corresponding certificate, if there is one
   *         for the selected key.
   * @exception TokenException
   *              If searching for keys or certificates failed.
   * @exception IOException
   *              If writing a user prompt faild or if reading user input failed.
   * @preconditions (session <> null) and (keyTemplate <> keyTemplate) and (output <> null) and
   *                (input <> null)
   * @postconditions (result <> null)
   */
  public static KeyAndCertificate selectKeyAndCertificate(Session session,
      Key keyTemplate, PrintWriter output, BufferedReader input, boolean pickFirstSuitable)
      throws TokenException, IOException {
    if (session == null) {
      throw new NullPointerException("Argument \"session\" must not be null.");
    }
    if (keyTemplate == null) {
      throw new NullPointerException("Argument \"keyTemplate\" must not be null.");
    }
    if (output == null) {
      throw new NullPointerException("Argument \"output\" must not be null.");
    }
    if (input == null) {
      throw new NullPointerException("Argument \"input\" must not be null.");
    }

    // holds the first suitable object handle if pickFirstSuitable is set true
    String botObjectHandle = null;

    output
        .println("################################################################################");
    output.println("searching for keys");

    Vector<PKCS11Object> keyList = new Vector<>(4);

    session.findObjectsInit(keyTemplate);
    PKCS11Object[] matchingKeys;

    while ((matchingKeys = session.findObjects(1)).length > 0) {
      keyList.addElement(matchingKeys[0]);
    }
    session.findObjectsFinal();

    // try to find the corresponding certificates for the signature keys
    Hashtable<PrivateKey, PKCS11Object> keyToCertificateTable = new Hashtable<>(4);
    Enumeration<PKCS11Object> keyListEnumeration = keyList.elements();
    while (keyListEnumeration.hasMoreElements()) {
      PrivateKey signatureKey = (PrivateKey) keyListEnumeration.nextElement();
      byte[] keyID = signatureKey.getId().getByteArrayValue();
      X509PublicKeyCertificate certificateTemplate = new X509PublicKeyCertificate();
      if (session.getModule().getInfo().getManufacturerID().indexOf("AEP") < 0) // AEP HSM can't
                                                                                // find certificate
                                                                                // IDs with
                                                                                // findObjects
        certificateTemplate.getId().setByteArrayValue(keyID);

      session.findObjectsInit(certificateTemplate);
      PKCS11Object[] correspondingCertificates = session.findObjects(1);

      if (correspondingCertificates.length > 0) {
        if (session.getModule().getInfo().getManufacturerID().indexOf("AEP") >= 0) { // check ID
                                                                                     // manually for
                                                                                     // AEP HSM
          while (correspondingCertificates.length > 0) {
            X509PublicKeyCertificate certObject = (X509PublicKeyCertificate) correspondingCertificates[0];
            if (Arrays.equals(certObject.getId().getByteArrayValue(), keyID)) {
              keyToCertificateTable.put(signatureKey, certObject);
              break;
            }
            correspondingCertificates = session.findObjects(1);
          }
        } else {
          keyToCertificateTable.put(signatureKey, correspondingCertificates[0]);
        }
      }
      session.findObjectsFinal();
    }

    Key selectedKey = null;
    X509PublicKeyCertificate correspondingCertificate = null;
    if (keyList.size() == 0) {
      output.println("Found NO matching key that can be used.");
    } else if (keyList.size() == 1) {
      // there is no choice, take this key
      selectedKey = (Key) keyList.elementAt(0);
      botObjectHandle = String.valueOf(selectedKey.getObjectHandle());
      // create a IAIK JCE certificate from the PKCS11 certificate
      correspondingCertificate = (X509PublicKeyCertificate) keyToCertificateTable
          .get(selectedKey);
      String correspondingCertificateString = toString(correspondingCertificate);
      output.println("Found just one private RSA signing key. This key will be used:");
      output.println(selectedKey);
      output
          .println("--------------------------------------------------------------------------------");
      output.println("The certificate for this key is:");
      output
          .println((correspondingCertificateString != null) ? correspondingCertificateString
              : "<no certificate found>");
    } else {
      // give the user the choice
      output.println("found these private RSA signing keys:");
      Hashtable<Long, PKCS11Object> objectHandleToObjectMap = new Hashtable<>(keyList.size());
      Enumeration<PKCS11Object> keyListEnumeration2 = keyList.elements();
      while (keyListEnumeration2.hasMoreElements()) {
        PKCS11Object signatureKey = keyListEnumeration2.nextElement();
        long objectHandle = signatureKey.getObjectHandle();
        objectHandleToObjectMap.put(Long.valueOf(objectHandle), signatureKey);
        correspondingCertificate = (X509PublicKeyCertificate) keyToCertificateTable
            .get(signatureKey);
        if (null == botObjectHandle
            && (null != correspondingCertificate || !keyListEnumeration2
                .hasMoreElements()))
          botObjectHandle = String.valueOf(objectHandle);
        String correspondingCertificateString = toString(correspondingCertificate);
        output
            .println("________________________________________________________________________________");
        output.println("RSA signature key with handle: " + objectHandle);
        output.println(signatureKey);
        output
            .println("--------------------------------------------------------------------------------");
        output.println("The certificate for this key is: ");
        output
            .println((correspondingCertificateString != null) ? correspondingCertificateString
                : "<no certificate found>");
        output
            .println("________________________________________________________________________________");
      }

      boolean gotObjectHandle = false;
      Long selectedObjectHandle;
      while (!gotObjectHandle) {
        output.print("Enter the handle of the key to use for signing or 'x' to exit: ");
        output.flush();

        String objectHandleString;
        if (pickFirstSuitable) {
          objectHandleString = botObjectHandle;
          output.println(objectHandleString);
        } else
          objectHandleString = input.readLine();

        if (objectHandleString.equalsIgnoreCase("x")) {
          break;
        }
        try {
          selectedObjectHandle = Long.valueOf(objectHandleString);
          selectedKey = (RSAPrivateKey) objectHandleToObjectMap.get(selectedObjectHandle);
          if (selectedKey != null) {
            correspondingCertificate = (X509PublicKeyCertificate) keyToCertificateTable
                .get(selectedKey);
            gotObjectHandle = true;
          } else {
            output.println("An object with the handle \"" + objectHandleString
                + "\" does not exist. Try again.");
          }
        } catch (NumberFormatException ex) {
          output.println("The entered handle \"" + objectHandleString
              + "\" is invalid. Try again.");
        }
      }
    }

    output
        .println("################################################################################");

    return (selectedKey != null) ? new KeyAndCertificate(selectedKey,
        correspondingCertificate) : null;
  }

  public static String toString(X509PublicKeyCertificate certificate) {
    String certificateString = null;

    if (certificate != null) {
      try {
        X509CertificateHolder correspondingCertificate = new X509CertificateHolder(
            certificate.getValue().getByteArrayValue());
        certificateString = correspondingCertificate.toString();
      } catch (Exception ex) {
        certificateString = certificate.toString();
      }
    }

    return certificateString;
  }

  public static String getCommontName(X500Principal name) {
    return getRdnValue(name, RFC4519Style.cn);
  }

  public static String getRdnValue(X500Principal name, ASN1ObjectIdentifier oid) {
    return getRdnValue(X500Name.getInstance(name.getEncoded()), oid);
  }

  public static String getCommontName(X500Name name) {
    return getRdnValue(name, RFC4519Style.cn);
  }

  public static String getRdnValue(X500Name name, ASN1ObjectIdentifier oid) {
    RDN[] rdns = name.getRDNs(oid);
    if (rdns == null || rdns.length == 0) {
      return null;
    }
    return IETFUtils.valueToString(rdns[0].getFirst().getValue());
  }
  
  public static boolean supports(Token token, long mechCode) throws TokenException {
    for (Mechanism mech : token.getMechanismList()) {
      if (mech.getMechanismCode() == mechCode) {
        return true;
      }
    }
    return false;
  }
  
}
