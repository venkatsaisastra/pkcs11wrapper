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

import iaik.pkcs.pkcs11.Util;
import sun.security.pkcs11.wrapper.CK_TLS_PRF_PARAMS;

import java.util.Arrays;

public class TLSPRFParameters implements Parameters {

  public byte[] seed;
  public byte[] label;
  public byte[] output;

  public TLSPRFParameters(byte[] seed, byte[] label, byte[] output) {
      this.seed = seed;
      this.label = label;
      this.output = output;
  }

  @Override
  public CK_TLS_PRF_PARAMS getPKCS11ParamsObject() {
    return new CK_TLS_PRF_PARAMS(seed, label, output);
  }

  @Override
  public String toString() {
    return Util.concatObjects(
        "seed", seed == null ? null : Util.toHex(seed),
        "\nlabel", label == null ? null : Util.toHex(label),
        "\noutput", output == null ? null : Util.toHex(output));
  }

  @Override
  public boolean equals(Object otherObject) {
    if (this == otherObject) {
      return true;
    } else if (!(otherObject instanceof TLSPRFParameters)) {
      return false;
    }

    TLSPRFParameters other = (TLSPRFParameters) otherObject;
    return Arrays.equals(seed, other.seed)
        && Arrays.equals(label, other.label)
        && Arrays.equals(output, other.output);
  }

  @Override
  public int hashCode() {
    return Util.hashCode(seed) ^ Util.hashCode(label) ^ Util.hashCode(output);
  }

}
