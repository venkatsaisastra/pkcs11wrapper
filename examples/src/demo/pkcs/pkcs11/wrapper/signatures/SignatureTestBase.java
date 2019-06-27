package demo.pkcs.pkcs11.wrapper.signatures;

import java.security.Security;
import java.security.Signature;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;

import demo.pkcs.pkcs11.wrapper.TestBase;
import iaik.pkcs.pkcs11.objects.PublicKey;

public class SignatureTestBase extends TestBase {

  @BeforeClass
  public static void addProvider() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  protected void jceVerifySignature(String algorithm,  PublicKey publicKey,
      byte[] data, byte[] signatureValue) throws Exception {
    // verify with JCE
    java.security.PublicKey jcePublicKey = generateJCEPublicKey(publicKey);
    Signature signature = Signature.getInstance(algorithm, "BC");
    signature.initVerify(jcePublicKey);
    signature.update(data);
    signature.verify(signatureValue);
  }

}
