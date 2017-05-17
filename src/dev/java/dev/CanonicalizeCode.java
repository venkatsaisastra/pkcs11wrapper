/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
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

/**
 * This class do the following tasks
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
        this.baseDir = baseDir.endsWith(File.separator) ? baseDir : baseDir + File.separator;
        this.baseDirLen = this.baseDir.length();
    }

    public static void main(final String[] args) {
        try {
            String baseDir = args[0];
            CanonicalizeCode canonicalizer = new CanonicalizeCode(baseDir);
            canonicalizer.canonicalize();
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
                if (!"target".equals(filename) && !"tbd".equals(filename)) {
                    canonicalizeDir(file);
                }
            } else {
                int idx = filename.lastIndexOf('.');
                String extension = (idx == -1) ? filename : filename.substring(idx + 1);
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

            while ((line = reader.readLine()) != null) {
                String canonicalizedLine = canonicalizeLine(line);
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
    private static String canonicalizeLine(final String line) {
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

    public static void save(final File file, final byte[] content) throws IOException {
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
            }
        }
    }

}
