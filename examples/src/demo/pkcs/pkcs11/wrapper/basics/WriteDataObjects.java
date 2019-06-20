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

package demo.pkcs.pkcs11.wrapper.basics;

import org.junit.Test;

import demo.pkcs.pkcs11.wrapper.TestBase;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Data;
import iaik.pkcs.pkcs11.objects.PKCS11Object;

/**
 * This demo program can be used to download data to the card.
 */
public class WriteDataObjects extends TestBase {

  @Test
  public void main() throws TokenException {
    Token token = getNonNullToken();
    Session session = openReadWriteSession(token);
    try {
      main0(session);
    } finally {
      session.closeSession();
    }
  }
  
  private void main0(Session session) throws TokenException {
    println("################################################################################");
    // read the data from the file
    byte[] data = "hello world".getBytes();
    println("################################################################################");
    println("creating data object on the card... ");

    // create certificate object template
    Data dataObjectTemplate = new Data();

    // we could also set the name that manages this data object
    // dataObjectTemplate.getApplication().setCharArrayValue("Application Name");

    // set the data object's label
    String label = "dummy-label-" + System.currentTimeMillis();
    dataObjectTemplate.getLabel().setCharArrayValue(label.toCharArray());

    // set the object's data content
    dataObjectTemplate.getValue().setByteArrayValue(data);

    // ensure that it is stored on the token and not just in this session
    dataObjectTemplate.getToken().setBooleanValue(Boolean.TRUE);

    // print template
    println(dataObjectTemplate);

    // create object
    PKCS11Object newObject = session.createObject(dataObjectTemplate);
    // destroy after the creation
    session.destroyObject(newObject);

    println("################################################################################");
  }

}
