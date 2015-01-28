/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.denimgroup.threadfix;

import com.denimgroup.threadfix.exception.RestIOException;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;

/**
 * <p>Escapes and unescapes <code>String</code>s for
 * Java, Java Script, HTML, XML, and SQL.</p>
 *
 * <p>#ThreadSafe#</p>
 * @author Apache Software Foundation
 * @author Apache Jakarta Turbine
 * @author Purple Technology
 * @author <a href="mailto:alex@purpletech.com">Alexander Day Chaffee</a>
 * @author Antony Riley
 * @author Helge Tesgaard
 * @author <a href="sean@boohai.com">Sean Brown</a>
 * @author <a href="mailto:ggregory@seagullsw.com">Gary Gregory</a>
 * @author Phil Steitz
 * @author Pete Gieser
 * @since 2.0
 * @version $Id: StringEscapeUtils.java 1057072 2011-01-10 01:55:57Z niallp $
 */
public class StringEscapeUtils {

    /**
     * <p><code>StringEscapeUtils</code> instances should NOT be constructed in
     * standard programming.</p>
     *
     * <p>Instead, the class should be used as:
     * <pre>StringEscapeUtils.escapeJava("foo");</pre></p>
     *
     * <p>This constructor is public to permit tools that require a JavaBean
     * instance to operate.</p>
     */

    public StringEscapeUtils() {
        super();
    }

    /**
     * <p>Unescapes any Java literals found in the <code>String</code>.
     * For example, it will turn a sequence of <code>'\'</code> and
     * <code>'n'</code> into a newline character, unless the <code>'\'</code>
     * is preceded by another <code>'\'</code>.</p>
     *
     * @param str  the <code>String</code> to unescape, may be null
     * @return a new unescaped <code>String</code>, <code>null</code> if null string input
     */
    public static String unescapeUnicode(String str) {
        if (str == null) {
            return null;
        }
        try {
            StringWriter writer = new StringWriter(str.length());
            unescapeUnicode(writer, str);
            return writer.toString().replaceAll("\\n", "\\\\n").replaceAll("\\r", "\\\\r").replaceAll("\\t", "\\\\t");
        } catch (IOException ioe) {
            // this should never ever happen while writing to a StringWriter
            throw new RestIOException(ioe, "Encountered IOException while trying to escape data. Can't continue.");
        }
    }

    /**
     * <p>Unescapes any Java literals found in the <code>String</code> to a
     * <code>Writer</code>.</p>
     *
     * <p>For example, it will turn a sequence of <code>'\'</code> and
     * <code>'n'</code> into a newline character, unless the <code>'\'</code>
     * is preceded by another <code>'\'</code>.</p>
     *
     * <p>A <code>null</code> string input has no effect.</p>
     *
     * @param out  the <code>Writer</code> used to output unescaped characters
     * @param str  the <code>String</code> to unescape, may be null
     * @throws IllegalArgumentException if the Writer is <code>null</code>
     * @throws IOException if error occurs on underlying Writer
     */
    public static void unescapeUnicode(Writer out, String str) throws IOException {
        if(out == null) {
            throw new IllegalArgumentException("The Writer must not be null");
        } else if(str != null) {
            int sz = str.length();
            StringBuffer unicode = new StringBuffer(4);
            boolean hadSlash = false;
            boolean inUnicode = false;

            for(int i = 0; i < sz; ++i) {
                char ch = str.charAt(i);
                if(inUnicode) {
                    unicode.append(ch);
                    if(unicode.length() == 4) {
                        try {
                            int nfe = Integer.parseInt(unicode.toString(), 16);
                            out.write((char)nfe);
                            unicode.setLength(0);
                            inUnicode = false;
                            hadSlash = false;
                        } catch (NumberFormatException var9) {
                            throw new RuntimeException("Unable to parse unicode value: " + unicode, var9);
                        }
                    }
                } else if(hadSlash) {
                    hadSlash = false;

                    if (ch == 'u') {
                        inUnicode = true;
                    } else {
                        out.write(92);
                        out.write(ch);
                    }
                } else if(ch == 92) {
                    hadSlash = true;
                } else {
                    out.write(ch);
                }
            }

            if(hadSlash) {
                out.write(92);
            }

        }
    }




}
