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

package demo.pkcs.pkcs11.wrapper.encryption;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import org.bouncycastle.util.encoders.Hex;

import demo.pkcs.pkcs11.wrapper.util.Util;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.MechanismInfo;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * This demo shows how to use a PKCS#11 token to decrypt a PKCS#7 encrypted object. It only supports
 * RSA decryption. This sample just decrypts the included symmetric key on the token and uses the
 * symmetric key to decrypt the content on the host, i.e. in software.
 *
 * Use util.EncryptPKCS7EnvelopedData for creating the necessary files.
 */
public class RSADecrypt {

  static PrintWriter output_;

  static BufferedReader input_;

  static {
    try {
      // output_ = new PrintWriter(new FileWriter("GetInfo_output.txt"), true);
      output_ = new PrintWriter(System.out, true);
      input_ = new BufferedReader(new InputStreamReader(System.in));
    } catch (Throwable thr) {
      thr.printStackTrace();
      output_ = new PrintWriter(System.out, true);
      input_ = new BufferedReader(new InputStreamReader(System.in));
    }
  }

  /**
   * Usage: DecryptPKCS7 PKCS#11-module PKCS#7-encrypted-data-file [slot-id] [pin] [decrypted
   * content data]
   */
  public static void main(String[] args) throws IOException, TokenException,
      CertificateException, NoSuchAlgorithmException, InvalidKeySpecException,
      InvalidKeyException, GeneralSecurityException {
    if (1 > args.length) {
      printUsage();
      throw new IOException("Missing argument!");
    }

    Module pkcs11Module = Module.getInstance(args[0]);
    pkcs11Module.initialize(null);

    Token token = Util.selectToken(pkcs11Module, output_, input_);
    if (token == null) {
      output_.println("We have no token to proceed. Finished.");
      output_.flush();
      throw new TokenException("No token found!");
    }

    // check, if this token can do RSA decryption
    if (!Util.supports(token, PKCS11Constants.CKM_RSA_PKCS)) {
      output_.print("This token does not support RSA!");
      output_.flush();
      throw new TokenException("RSA not supported!");
    } else {
      MechanismInfo rsaMechanismInfo = token.getMechanismInfo(Mechanism
          .get(PKCS11Constants.CKM_RSA_PKCS));
      if (!rsaMechanismInfo.isDecrypt()) {
        output_.print("This token does not support RSA decryption according to PKCS!");
        output_.flush();
        throw new TokenException("RSA decryption not supported!");
      }
    }

    Session session = Util.openAuthorizedSession(token,
          Token.SessionReadWriteBehavior.RW_SESSION, output_, input_, null);

    RSAPrivateKey privTemplate = new RSAPrivateKey();
    RSAPublicKey pubTemplate = new RSAPublicKey();
    privTemplate.getPrivate().setBooleanValue(true);
    privTemplate.getSensitive().setBooleanValue(true);
    privTemplate.getDecrypt().setBooleanValue(true);
    privTemplate.getExtractable().setBooleanValue(false);
    
    pubTemplate.getEncrypt().setBooleanValue(true);
    pubTemplate.getModulusBits().setLongValue(1024L);
    
    Mechanism keyGenMech = Mechanism.get(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN);
    if (!Util.supports(token, keyGenMech.getMechanismCode())) {
      output_.println("unsupported algorithm");
      return;
    }

    KeyPair keypair = session.generateKeyPair(keyGenMech, pubTemplate, privTemplate);
    
    PrivateKey privKey = keypair.getPrivateKey();
    PublicKey pubKey = keypair.getPublicKey();
    
    Mechanism encMech = Mechanism.get(PKCS11Constants.CKM_RSA_PKCS);
    
    byte[] sessionKey = new byte[16];
    byte[] buffer = new byte[1024 / 8 + 32];
    session.encryptInit(encMech, pubKey);
    int len = session.encrypt(sessionKey, 0, sessionKey.length, buffer, 0, buffer.length);
    byte[] encryptedSessionKey = Arrays.copyOf(buffer, len);
    Arrays.fill(buffer, (byte) 0); 
    System.out.println(encryptedSessionKey.length + " bytes: " + Hex.toHexString(encryptedSessionKey));
    
    // decrypt
    session.decryptInit(encMech, privKey);
    len = session.decrypt(encryptedSessionKey, 0, encryptedSessionKey.length,buffer, 0, buffer.length);
    byte[] decryptedSessionKey = Arrays.copyOf(buffer, len);
    Arrays.fill(buffer, (byte) 0);
    
    boolean equal = Arrays.equals(sessionKey, decryptedSessionKey);
    output_.println("decryption " + ((equal) ? "successful" : "FAILED"));

    output_.println("finished");

    session.closeSession();
    pkcs11Module.finalize(null);
  }

  public static void printUsage() {
    output_
        .println("Usage: DecryptPKCS7 <PKCS#11 module> <PKCS#7 encrypted data file> [<slot-id>] [<pin>] [<decrypted content data>]");
    output_
        .println(" e.g.: DecryptPKCS7 slbck.dll encryptedData.p7 decryptedContent.dat");
    output_.println("The given DLL must be in the search path of the system.");
  }

}
