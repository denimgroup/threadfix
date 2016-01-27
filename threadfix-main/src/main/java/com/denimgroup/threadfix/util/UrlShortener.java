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

// Source from http://stackoverflow.com/questions/742013/how-to-code-a-url-shortener
package com.denimgroup.threadfix.util;

public class UrlShortener
{
    private static final String ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final int    BASE     = ALPHABET.length();

    public static String encode(int num)
    {
        StringBuilder sb = new StringBuilder();

        while ( num > 0 )
        {
            sb.append( ALPHABET.charAt( num % BASE ) );
            num /= BASE;
        }

       return sb.reverse().toString();
    }

    public static int decode(String str)
    {
        int num = 0;

        for ( int i = 0, len = str.length(); i < len; i++ )
        {
            num = num * BASE + ALPHABET.indexOf( str.charAt(i) );
        }

        return num;
    }
}