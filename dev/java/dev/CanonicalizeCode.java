/*
 *
 * Copyright (c) 2016 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dev;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.StringTokenizer;

/**
 * This class do the following tasks.
 * <ul>
 *   <li>replace tab with 4 spaces</li>
 *   <li>delete trailing spaces</li>
 *   <li>reduce redundant empty lines</li>
 * </ul>
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CanonicalizeCode {

  private final String baseDir;

  private final int baseDirLen;

  private CanonicalizeCode(String baseDir) {
    this.baseDir = baseDir.endsWith(File.separator)
        ? baseDir : baseDir + File.separator;
    this.baseDirLen = this.baseDir.length();
  }

  public static void main(final String[] args) {
    try {
      //String baseDir = args[0];
      String baseDir = "/home/lliao/source/pkcs11wrapper";
      CanonicalizeCode canonicalizer = new CanonicalizeCode(baseDir);
      canonicalizer.canonicalize();
      canonicalizer.checkWarnings();
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }

  private void canonicalize() throws Exception {
    canonicalizeDir(new File(baseDir));
  }

  private void canonicalizeDir(final File dir) throws Exception {
    File[] files = dir.listFiles();
    if (files == null) {
      return;
    }

    for (File file : files) {
      String filename = file.getName();
      if (file.isDirectory()) {
        if (!"target".equals(filename)
            && !"tbd".equals(filename)
            && !"dev".equals(filename)) {
          canonicalizeDir(file);
        }
      } else {
        int idx = filename.lastIndexOf('.');
        String extension = (idx == -1)
            ? filename : filename.substring(idx + 1);
        extension = extension.toLowerCase();

        if ("java".equals(extension)) {
          canonicalizeFile(file);
        }
      }
    }
  } // method canonicalizeDir

  private void canonicalizeFile(final File file) throws Exception {
    byte[] newLine = detectNewline(file);

    BufferedReader reader = new BufferedReader(new FileReader(file));

    ByteArrayOutputStream writer = new ByteArrayOutputStream();

    try {
      String line;
      boolean lastLineEmpty = false;
      boolean licenseTextAdded = false;
      boolean skip = true;

      while ((line = reader.readLine()) != null) {
        if (line.trim().startsWith("package ")
            || line.trim().startsWith("import ")) {
          if (!licenseTextAdded) {
            writeLicenseHeader(writer, newLine);
            licenseTextAdded = true;
          }
          skip = false;
        }

        if (skip) {
          continue;
        }

        String canonicalizedLine = canonicalizeLine(line, newLine);
        boolean addThisLine = true;
        if (canonicalizedLine.isEmpty()) {
          if (!lastLineEmpty) {
            lastLineEmpty = true;
          } else {
            addThisLine = false;
          }
        } else {
          lastLineEmpty = false;
        }

        if (addThisLine) {
          writeLine(writer, newLine, canonicalizedLine);
        }
      } // end while
    } finally {
      writer.close();
      reader.close();
    }

    byte[] oldBytes = read(new FileInputStream(file));
    byte[] newBytes = writer.toByteArray();

    if (!Arrays.equals(oldBytes, newBytes)) {
      File newFile = new File(file.getPath() + "-new");
      save(file, newBytes);
      newFile.renameTo(file);
      System.out.println(file.getPath().substring(baseDirLen));
    }
  } // method canonicalizeFile

  /**
   * replace tab by 4 spaces, delete white spaces at the end.
   */
  private static String canonicalizeLine(String line, byte[] newLine) {
    if (line.trim().startsWith("//")) {
      // comments
      String nline = line.replace("\t", "    ");
      return removeTrailingSpaces(nline);
    }

    StringBuilder sb = new StringBuilder();
    int len = line.length();

    int lastNonSpaceCharIndex = 0;
    int index = 0;
    for (int i = 0; i < len; i++) {
      char ch = line.charAt(i);
      if (ch == '\t') {
        sb.append("    ");
        index += 4;
      } else if (ch == ' ') {
        sb.append(ch);
        index++;
      } else {
        sb.append(ch);
        index++;
        lastNonSpaceCharIndex = index;
      }
    }

    int numSpacesAtEnd = sb.length() - lastNonSpaceCharIndex;
    if (numSpacesAtEnd > 0) {
      sb.delete(lastNonSpaceCharIndex, sb.length());
    }

    return sb.toString();
  }

  private static String removeTrailingSpaces(final String line) {
    final int n = line.length();
    int idx;
    for (idx = n - 1; idx >= 0; idx--) {
      char ch = line.charAt(idx);
      if (ch != ' ') {
        break;
      }
    }
    return (idx == n - 1) ?  line : line.substring(0, idx + 1);
  } // method removeTrailingSpaces

  private static byte[] detectNewline(File file) throws IOException {
    InputStream is = new FileInputStream(file);
    byte[] bytes = new byte[200];
    int size;
    try {
      size = is.read(bytes);
    } finally {
      is.close();
    }

    for (int i = 0; i < size - 1; i++) {
      byte bb = bytes[i];
      if (bb == '\n') {
        return new byte[]{'\n'};
      } else if (bb == '\r') {
        if (bytes[i + 1] == '\n') {
          return new byte[]{'\r', '\n'};
        } else {
          return new byte[]{'\r'};
        }
      }
    }

    return new byte[]{'\n'};
  }

  private static void writeLine(OutputStream out, byte[] newLine, String line)
      throws IOException {
    if (line != null && !line.isEmpty()) {
      out.write(line.getBytes());
    }
    out.write(newLine);
  }

  public static void save(final File file, final byte[] content)
      throws IOException {
    FileOutputStream out = new FileOutputStream(file);
    try {
      out.write(content);
    } finally {
      out.close();
    }
  }

  public static byte[] read(final InputStream in) throws IOException {
    try {
      ByteArrayOutputStream bout = new ByteArrayOutputStream();
      int readed = 0;
      byte[] buffer = new byte[2048];
      while ((readed = in.read(buffer)) != -1) {
        bout.write(buffer, 0, readed);
      }

      return bout.toByteArray();
    } finally {
      try {
        in.close();
      } catch (IOException ex) {
        // Do nothing
      }
    }
  }

  private static void writeLicenseHeader(OutputStream out, byte[] newLine)
      throws IOException {
    writeLine(out, newLine,
        "// Copyright (c) 2002 Graz University of Technology. "
        + "All rights reserved.");
    writeLine(out, newLine,
        "//");
    writeLine(out, newLine,
        "// Redistribution and use in source and binary forms, "
        + "with or without");
    writeLine(out, newLine,
        "// modification, are permitted provided that the following "
        + "conditions are met:");
    writeLine(out, newLine,
        "//");
    writeLine(out, newLine,
        "// 1. Redistributions of source code must retain the above"
        + " copyright notice,");
    writeLine(out, newLine,
        "//    this list of conditions and the following disclaimer.");
    writeLine(out, newLine,
        "//");
    writeLine(out, newLine,
        "// 2. Redistributions in binary form must reproduce the above "
        + "copyright notice,");
    writeLine(out, newLine,
        "//    this list of conditions and the following disclaimer in "
        + "the documentation");
    writeLine(out, newLine,
        "//    and/or other materials provided with the distribution.");
    writeLine(out, newLine,
        "//");
    writeLine(out, newLine,
        "// 3. The end-user documentation included with the "
        + "redistribution, if any, must");
    writeLine(out, newLine,
        "//    include the following acknowledgment:");
    writeLine(out, newLine,
        "//");
    writeLine(out, newLine,
        "//    \"This product includes software developed by IAIK of Graz "
        + "University of");
    writeLine(out, newLine,
        "//     Technology.\"");
    writeLine(out, newLine,
        "//");
    writeLine(out, newLine,
        "//    Alternately, this acknowledgment may appear in the software "
        + "itself, if and");
    writeLine(out, newLine,
        "//    wherever such third-party acknowledgments normally appear.");
    writeLine(out, newLine,
        "//");
    writeLine(out, newLine,
        "// 4. The names \"Graz University of Technology\" and \"IAIK of "
        + "Graz University of");
    writeLine(out, newLine,
        "//    Technology\" must not be used to endorse or promote "
        + "products derived from");
    writeLine(out, newLine,
        "//    this software without prior written permission.");
    writeLine(out, newLine,
        "//");
    writeLine(out, newLine,
        "// 5. Products derived from this software may not be called "
        + "\"IAIK PKCS Wrapper\",");
    writeLine(out, newLine,
        "//    nor may \"IAIK\" appear in their name, without prior "
        + "written permission of");
    writeLine(out, newLine,
        "//    Graz University of Technology.");
    writeLine(out, newLine,
        "//");
    writeLine(out, newLine,
        "// THIS SOFTWARE IS PROVIDED \"AS IS\" AND ANY EXPRESSED OR IMPLIED");
    writeLine(out, newLine,
        "// WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED");
    writeLine(out, newLine,
        "// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR");
    writeLine(out, newLine,
        "// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE LICENSOR BE");
    writeLine(out, newLine,
        "// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,");
    writeLine(out, newLine,
        "// OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,");
    writeLine(out, newLine,
        "// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,");
    writeLine(out, newLine,
        "// OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON");
    writeLine(out, newLine,
        "// ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,");
    writeLine(out, newLine,
        "// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY");
    writeLine(out, newLine,
        "// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE");
    writeLine(out, newLine,
        "// POSSIBILITY OF SUCH DAMAGE.");

    writeLine(out, newLine,
        "");
  }

  private void checkWarnings() throws Exception {
    checkWarningsInDir(new File(baseDir));
  }

  private void checkWarningsInDir(final File dir) throws Exception {
    File[] files = dir.listFiles();
    if (files == null) {
      return;
    }

    for (File file : files) {
      if (file.isDirectory()) {
        if (!file.getName().equals("target")
            && !file.getName().equals("tbd")
            && !file.getName().equals("dev")) {
          checkWarningsInDir(file);
        }

        continue;
      } else {
        String filename = file.getName();
        int idx = filename.lastIndexOf('.');
        String extension = (idx == -1)
            ? filename : filename.substring(idx + 1);
        extension = extension.toLowerCase();

        if ("java".equals(extension)) {
          checkWarningsInFile(file);
        }
      }
    }
  } // method checkWarningsInDir

  private void checkWarningsInFile(final File file) throws Exception {
    if (file.getName().equals("package-info.java")) {
      return;
    }

    BufferedReader reader = new BufferedReader(new FileReader(file));

    List<Integer> lineNumbers = new LinkedList<>();

    int lineNumber = 0;
    try {
      String line;
      while ((line = reader.readLine()) != null) {
        lineNumber++;
        if (lineNumber == 1 && line.startsWith("// #THIRDPARTY")) {
          return;
        }

        if (line.length() > 80 && !line.contains("http")) {
          lineNumbers.add(lineNumber);
          continue;
        }

        String trimmedLine = line.trim();
        if (trimmedLine.startsWith("* @param ")) {
          StringTokenizer tokenizer =
              new StringTokenizer(trimmedLine, " ");
          if (tokenizer.countTokens() != 3) {
            lineNumbers.add(lineNumber);
            continue;
          }
        }

        if (trimmedLine.startsWith("* @exception ")) {
          StringTokenizer tokenizer =
              new StringTokenizer(trimmedLine, " ");
          if (tokenizer.countTokens() != 3) {
            lineNumbers.add(lineNumber);
            continue;
          }
        }

      } // end while
    } finally {
      reader.close();
    }

    if (!lineNumbers.isEmpty()) {
      System.out.println("Please check file "
          + file.getPath().substring(baseDirLen) + ": lines "
          + Arrays.toString(lineNumbers.toArray(new Integer[0])));
    }
  } // method checkWarningsInFile

}
