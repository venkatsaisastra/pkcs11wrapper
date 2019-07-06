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

package iaik.pkcs.pkcs11.parameters;

import sun.security.pkcs11.wrapper.CK_SSL3_MASTER_KEY_DERIVE_PARAMS;
import sun.security.pkcs11.wrapper.CK_SSL3_RANDOM_DATA;
import sun.security.pkcs11.wrapper.CK_VERSION;

/**
 * This class encapsulates parameters for the Mechanism.SSL3_MASTER_KEY_DERIVE
 * mechanism and the Mechanism.TLS_MASTER_KEY_DERIVE.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 */
// CHECKSTYLE:SKIP
public class SSL3MasterKeyDeriveParameters
extends TLSMasterKeyDeriveParameters {

  /**
   * Create a new SSL3MasterKeyDeriveParameters object with the given
   * random info and version.
   *
   * @param randomInfo
   *          The client's and server's random data information.
   * @param version
   *          The SSL protocol version information.
   */
  public SSL3MasterKeyDeriveParameters(SSL3RandomDataParameters randomInfo,
      VersionParameters version) {
    super(randomInfo, version);
  }

  /**
   * Get this parameters object as a CK_SSL3_RANDOM_DATA object.
   *
   * @return This object as a CK_SSL3_RANDOM_DATA object.
   */
  @Override
  public CK_SSL3_MASTER_KEY_DERIVE_PARAMS getPKCS11ParamsObject() {
    CK_SSL3_MASTER_KEY_DERIVE_PARAMS params =
        new CK_SSL3_MASTER_KEY_DERIVE_PARAMS(
            (CK_SSL3_RANDOM_DATA) randomInfo.getPKCS11ParamsObject(),
            (CK_VERSION) version.getPKCS11ParamsObject());

    return params;
  }

}
