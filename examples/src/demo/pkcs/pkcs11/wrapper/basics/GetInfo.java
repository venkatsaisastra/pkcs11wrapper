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

package demo.pkcs.pkcs11.wrapper.basics;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

import org.junit.Test;

import demo.pkcs.pkcs11.wrapper.TestBase;
import iaik.pkcs.pkcs11.Info;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.MechanismInfo;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.SessionInfo;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.SlotInfo;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.TokenInfo;
import iaik.pkcs.pkcs11.objects.PKCS11Object;
import iaik.pkcs.pkcs11.objects.X509AttributeCertificate;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;

/**
 * This demo program lists information about a library, the available slots, the
 * available tokens and the objects on them. It takes the name of the module and
 * the absolute path to the shared library of the IAIK PKCS#11 Wrapper and
 * prompts the user PIN. If the user PIN is not available, the program will list
 * only public objects but no private objects; i.e. as defined in PKCS#11 for
 * public read-only sessions.
 */
public class GetInfo extends TestBase {

  @Test
  public void main() throws TokenException {
    println("##################################################");
    Module pkcs11Module = getModule();
    Info info = pkcs11Module.getInfo();
    println(info);
    println("##################################################");
    println("getting list of all slots");
    Slot[] slots = pkcs11Module.getSlotList(Module.SlotRequirement.ALL_SLOTS);

    for (int i = 0; i < slots.length; i++) {
      println("___________________________________________________");
      SlotInfo slotInfo = slots[i].getSlotInfo();
      print("Slot with ID: ");
      println(slots[i].getSlotID());
      println("--------------------------------------------------");
      println(slotInfo);
      println("___________________________________________________");
    }

    println("##################################################");
    println("getting list of all tokens");
    Slot[] slotsWithToken = pkcs11Module
        .getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
    Token[] tokens = new Token[slotsWithToken.length];

    for (int i = 0; i < slotsWithToken.length; i++) {
      println("___________________________________________________");
      tokens[i] = slotsWithToken[i].getToken();
      TokenInfo tokenInfo = tokens[i].getTokenInfo();
      print("Token in slot with ID: ");
      println(tokens[i].getSlot().getSlotID());
      println("--------------------------------------------------");
      println(tokenInfo);

      println("supported Mechanisms:");
      Mechanism[] supportedMechanisms = tokens[i].getMechanismList();
      for (int j = 0; j < supportedMechanisms.length; j++) {
        println("--------------------------------------------------");
        println("Mechanism Name: " + supportedMechanisms[j].getName());
        MechanismInfo mechanismInfo =
            tokens[i].getMechanismInfo(supportedMechanisms[j]);
        println(mechanismInfo);
        println("--------------------------------------------------");
      }
      println("___________________________________________________");
    }
    println("##################################################");

    println("##################################################");
    println("listing objects on tokens");
    for (int i = 0; i < tokens.length; i++) {
      println("___________________________________________________");
      println("listing objects for token: ");
      TokenInfo tokenInfo = tokens[i].getTokenInfo();
      println(tokenInfo);
      if (!tokenInfo.isTokenInitialized()) {
        println("token not initialized yet");
        continue;
      }

      Session session = openReadOnlySession(tokens[i]);
      try {
        main0(session);
      } finally {
        session.closeSession();
      }
    }
  }

  private void main0(Session session) throws TokenException {
    SessionInfo sessionInfo = session.getSessionInfo();
    println(" using session:");
    println(sessionInfo);

    int limit = 0, counter = 0;

    session.findObjectsInit(null);
    PKCS11Object[] objects = session.findObjects(1);
    if (0 < objects.length)
      counter++;

    CertificateFactory x509CertificateFactory = null;
    while (objects.length > 0 && (0 == limit || counter < limit)) {
      PKCS11Object object = objects[0];
      println("--------------------------------------------------");
      println("Object with handle: " + objects[0].getObjectHandle());
      println(object);
      if (object instanceof X509PublicKeyCertificate) {
        try {
          byte[] encodedCertificate = ((X509PublicKeyCertificate) object)
              .getValue().getByteArrayValue();
          if (x509CertificateFactory == null) {
            x509CertificateFactory = CertificateFactory.getInstance("X.509");
          }
          Certificate certificate = x509CertificateFactory.generateCertificate(
              new ByteArrayInputStream(encodedCertificate));
          println("..................................................");
          println("The decoded X509PublicKeyCertificate is:");
          println(certificate.toString());
          println("..................................................");
        } catch (Exception ex) {
          println("Could not decode this X509PublicKeyCertificate: "
                  + ex.toString());
        }
      } else if (object instanceof X509AttributeCertificate) {
        try {
          byte[] encodedCertificate = ((X509AttributeCertificate) object)
              .getValue().getByteArrayValue();
          if (x509CertificateFactory == null) {
            x509CertificateFactory = CertificateFactory.getInstance("X.509");
          }
          Certificate certificate = x509CertificateFactory.generateCertificate(
              new ByteArrayInputStream(encodedCertificate));
          println("..................................................");
          println("The decoded X509AttributeCertificate is:");
          println(certificate.toString());
          println("..................................................");
        } catch (Exception ex) {
          println("Could not decode this X509AttributeCertificate: "
                  + ex.toString());
        }
      }
      println("--------------------------------------------------");
      objects = session.findObjects(1);
      counter++;
    }
    session.findObjectsFinal();

    println("___________________________________________________");
    println("found " + counter + " objects on this token");
    println("___________________________________________________");
  }
}
