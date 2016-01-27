////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.csv2ssl.util;

import java.io.*;

/**
 * Created by mcollins on 1/21/15.
 */
public class InteractionUtils {

    public static BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

    public static String getLine() {
        try {
            return reader.readLine();
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(1);
            return "";
        }
    }

    public static File getValidFileFromStdIn(String type) {
        File file;
        while (true) {
            System.out.println("Where is the " + type + " file?");
            String fileName = getLine();
            file = new File(fileName);

            if (file.exists() && file.isFile()) {
                break;
            } else {
                // Windows gives quoted paths to users; let's try to strip quotes for convenience.
                fileName = fileName.replaceAll("^\"|\"$", "");
                file = new File(fileName);

                if (file.exists() && file.isFile()) {
                    break;
                } else {
                    System.out.println("Invalid file name entered: " + fileName);
                }
            }
        }
        return file;
    }

    public static boolean getYNAnswer(String prompt) {
        String response;
        while (true) {
            System.out.println(prompt);
            response = getLine();
            if (response.trim().equalsIgnoreCase("y")) {
                return true;
            } else if (response.trim().equalsIgnoreCase("n")) {
                return false;
            } else {
                System.out.println(response + " wasn't one of y or n.");
            }
        }
    }
}
