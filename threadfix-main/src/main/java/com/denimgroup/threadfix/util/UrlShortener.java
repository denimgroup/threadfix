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