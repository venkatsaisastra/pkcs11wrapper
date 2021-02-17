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
    Module pkcs11Module = getModule();
    Info info = pkcs11Module.getInfo();
    LOG.info("##################################################");
    LOG.info("{}", info);
    LOG.info("##################################################");
    LOG.info("getting list of all slots");
    Slot[] slots = pkcs11Module.getSlotList(Module.SlotRequirement.ALL_SLOTS);

    for (int i = 0; i < slots.length; i++) {
      LOG.info("___________________________________________________");
      SlotInfo slotInfo = slots[i].getSlotInfo();
      LOG.info("Slot with ID: {}", slots[i].getSlotID());
      LOG.info("--------------------------------------------------");
      LOG.info("{}", slotInfo);
      LOG.info("___________________________________________________");
    }

    LOG.info("##################################################");
    LOG.info("getting list of all tokens");
    Slot[] slotsWithToken = pkcs11Module
        .getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
    Token[] tokens = new Token[slotsWithToken.length];

    for (int i = 0; i < slotsWithToken.length; i++) {
      LOG.info("___________________________________________________");
      tokens[i] = slotsWithToken[i].getToken();
      TokenInfo tokenInfo = tokens[i].getTokenInfo();
      LOG.info("Token in slot with ID: {}", tokens[i].getSlot().getSlotID());
      LOG.info("--------------------------------------------------");
      LOG.info("{}", tokenInfo);

      LOG.info("supported Mechanisms:");
      Mechanism[] supportedMechanisms = tokens[i].getMechanismList();
      for (int j = 0; j < supportedMechanisms.length; j++) {
        LOG.info("--------------------------------------------------");
        LOG.info("Mechanism Name: {}", supportedMechanisms[j].getName());
        MechanismInfo mechanismInfo =
            tokens[i].getMechanismInfo(supportedMechanisms[j]);
        LOG.info("{}", mechanismInfo);
        LOG.info("--------------------------------------------------");
      }
      LOG.info("___________________________________________________");
    }

    LOG.info("##################################################");
    LOG.info("listing objects on tokens");
    for (int i = 0; i < tokens.length; i++) {
      LOG.info("___________________________________________________");
      TokenInfo tokenInfo = tokens[i].getTokenInfo();
      LOG.info("listing objects for token: {}", tokenInfo);
      if (!tokenInfo.isTokenInitialized()) {
        LOG.info("token not initialized yet");
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
    LOG.info("using session: {}", sessionInfo);

    int limit = 0, counter = 0;

    session.findObjectsInit(null);
    iaik.pkcs.pkcs11.objects.Object[] objects = session.findObjects(1);
    if (0 < objects.length) {
      counter++;
    }

    while (objects.length > 0 && (0 == limit || counter < limit)) {
      iaik.pkcs.pkcs11.objects.Object object = objects[0];
      LOG.info("--------------------------------------------------");
      LOG.info("Object with handle: {}", object.getObjectHandle());
      LOG.info("{}", object);
      LOG.info("--------------------------------------------------");
      objects = session.findObjects(1);
      counter++;
    }
    session.findObjectsFinal();

    LOG.info("___________________________________________________");
    LOG.info("found {} objects on this token", counter);
    LOG.info("___________________________________________________");
  }
}
