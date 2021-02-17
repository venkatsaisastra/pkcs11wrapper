package demo.pkcs.pkcs11.wrapper;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import demo.pkcs.pkcs11.wrapper.Platform.CPU;
import demo.pkcs.pkcs11.wrapper.Platform.OS;

class NativeLibraryInit {

  private NativeLibraryInit() {
  }
  
  public static void initNativeLibrary() throws IOException {
    Platform platform = Platform.getNativePlatform();
    OS os = platform.getOS();
    CPU cpu = platform.getCPU();
    String path = null;
    String name = null;
    if (os == OS.WINDOWS) {
      String arch;
      if (cpu == CPU.I386) {
        arch = "x86";
      } else if (cpu == CPU.X86_64) {
        arch = "x64";
      } else {
        throw new IllegalArgumentException("unknown CPU " + cpu);
      }
      path = "windows/win_" + arch;
      name = "PKCS11Wrapper.dll";
    } else if (os == OS.LINUX) {
      String arch;
      if (cpu == CPU.I386) {
        arch = "x86";
      } else if (cpu == CPU.X86_64) {
        arch = "x86_64";
      } else {
        throw new IllegalArgumentException("unknown CPU " + cpu);
      }
      path = "unix/linux_" + arch;
      name = "libpkcs11wrapper.so";
    }

    if (path == null) {
      throw new IllegalStateException("unsupported platform " + platform);
    }
    
    
    File nativeDir = new File("target/native");
    nativeDir.mkdirs();
    File targetFile = new File(nativeDir, name);

    if (targetFile.exists()) {
      return;
    }

    ZipFile zipFile = new ZipFile("binary-v1.3/pkcs11-wrapper-native-1.3.zip");
    ZipEntry zipEntry = zipFile.getEntry(path + "/" + name);
    InputStream is = null;
    try {
      is = zipFile.getInputStream(zipEntry);

      Files.copy(is, targetFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
    } finally {
      if (is != null) {
      is.close();
      }
      zipFile.close();
    }
    
  }

}
