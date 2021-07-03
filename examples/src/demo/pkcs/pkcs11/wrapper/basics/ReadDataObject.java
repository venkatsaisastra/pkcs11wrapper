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

import demo.pkcs.pkcs11.wrapper.TestBase;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.TokenInfo;
import iaik.pkcs.pkcs11.objects.Data;
import iaik.pkcs.pkcs11.objects.PKCS11Object;
import org.junit.Test;

/**
 * This demo program read a data object with a specific label from the token.
 */
public class ReadDataObject extends TestBase {

  @Test
  public void main() throws TokenException {
    Token token = getNonNullToken();
    TokenInfo tokenInfo = token.getTokenInfo();

    LOG.info("##################################################");
    LOG.info("Information of Token:\n{}", tokenInfo);
    LOG.info("##################################################");

    // open a read-write user session
    Session session = openReadWriteSession(token);
    try {
      main0(session);
    } finally {
      session.closeSession();
    }
  }

  private void main0(Session session) throws TokenException {
    LOG.info("##################################################");
    LOG.info(
        "searching for data object on the card using this search template... ");

    String label = "pkcs11demo-data-" + System.currentTimeMillis();

    // Create a new PKCS#11 object first
    Data newDataTemplate = new Data();
    newDataTemplate.getLabel().setCharArrayValue(label.toCharArray());
    newDataTemplate.getValue().setByteArrayValue("hello world".getBytes());
    PKCS11Object newData = session.createObject(newDataTemplate);

    try {
      // create certificate object template
      Data dataObjectTemplate = new Data();

      // we could also set the name that manages this data object
      // dataObjectTemplate.getApplication()
      //    .setCharArrayValue("Application Name");

      // set the data object's label
      dataObjectTemplate.getLabel().setCharArrayValue(label.toCharArray());

      // print template
      LOG.info("{}", dataObjectTemplate);

      // start find operation
      session.findObjectsInit(dataObjectTemplate);

      PKCS11Object[] foundDataObjects = session.findObjects(1); // find first

      Data dataObject;
      if (foundDataObjects.length > 0) {
        dataObject = (Data) foundDataObjects[0];
        LOG.info("___________________________________________________");
        LOG.info("found this data object with handle: {}",
            dataObject.getObjectHandle());
        LOG.info("{}", dataObject);
        LOG.info("___________________________________________________");
        // FIXME, there may be more than one that matches the given template,
        // the label is not unique in general
        // foundDataObjects = session.findObjects(1); //find next
      } else {
        dataObject = null;
      }

      session.findObjectsFinal();
    } finally {
      session.destroyObject(newData);
    }
  }

}
