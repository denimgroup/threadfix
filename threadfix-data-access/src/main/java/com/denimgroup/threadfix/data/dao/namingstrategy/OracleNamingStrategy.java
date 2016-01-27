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
package com.denimgroup.threadfix.data.dao.namingstrategy;


import org.hibernate.cfg.DefaultComponentSafeNamingStrategy;

import java.util.StringTokenizer;

public class OracleNamingStrategy extends DefaultComponentSafeNamingStrategy {

    protected static String addUnderscores(String name) {
        if (name == null)
            return null;
        StringBuffer buf = new StringBuffer(name.replace('.', '_'));
        for (int i = 1; i < buf.length() - 1; i++) {
            if ((isLowerToUpper(buf, i)) || (isMultipleUpperToLower(buf, i))) {
                buf.insert(i++, '_');
            }
        }
        return buf.toString().toLowerCase();
    }

    private static boolean isMultipleUpperToLower(StringBuffer buf, int i) {
        return i > 1 && Character.isUpperCase(buf.charAt(i - 1))
                && Character.isUpperCase(buf.charAt(i - 2))
                && Character.isLowerCase(buf.charAt(i));
    }

    private static boolean isLowerToUpper(StringBuffer buf, int i) {
        return Character.isLowerCase(buf.charAt(i - 1))
                && Character.isUpperCase(buf.charAt(i));
    }

    @Override
    public String collectionTableName(String ownerEntity,
                                      String ownerEntityTable, String associatedEntity,
                                      String associatedEntityTable, String propertyName) {
        return abbreviateName(super.collectionTableName(
                addUnderscores(ownerEntity), addUnderscores(ownerEntityTable),
                addUnderscores(associatedEntity),
                addUnderscores(associatedEntityTable),
                addUnderscores(propertyName)));
    }

    @Override
    public String foreignKeyColumnName(String propertyName,
                                       String propertyEntityName, String propertyTableName,
                                       String referencedColumnName) {
        return abbreviateName(super.foreignKeyColumnName(
                addUnderscores(propertyName),
                addUnderscores(propertyEntityName),
                addUnderscores(propertyTableName),
                addUnderscores(referencedColumnName)));
    }

    @Override
    public String logicalCollectionColumnName(String columnName,
                                              String propertyName, String referencedColumn) {
        return abbreviateName(super.logicalCollectionColumnName(
                addUnderscores(columnName), addUnderscores(propertyName),
                addUnderscores(referencedColumn)));
    }

    @Override
    public String logicalCollectionTableName(String tableName,
                                             String ownerEntityTable, String associatedEntityTable,
                                             String propertyName) {
        return abbreviateName(super.logicalCollectionTableName(
                addUnderscores(tableName), addUnderscores(ownerEntityTable),
                addUnderscores(associatedEntityTable),
                addUnderscores(propertyName)));
    }

    @Override
    public String logicalColumnName(String columnName, String propertyName) {
        return abbreviateName(super.logicalColumnName(
                addUnderscores(columnName), addUnderscores(propertyName)));
    }

    @Override
    public String propertyToColumnName(String propertyName) {
        return abbreviateName(super
                .propertyToColumnName(addUnderscores(propertyName)));
    }

    private static final int MAX_LENGTH = 30;

    public static String abbreviateName(String someName) {
        if (someName.length() <= MAX_LENGTH)
            return someName;

        String[] tokens = splitName(someName);
        shortenName(someName, tokens);

        return assembleResults(tokens);
    }

    private static String[] splitName(String someName) {
        StringTokenizer toki = new StringTokenizer(someName, "_");
        String[] tokens = new String[toki.countTokens()];
        int i = 0;
        while (toki.hasMoreTokens()) {
            tokens[i] = toki.nextToken();
            i++;
        }
        return tokens;
    }

    private static void shortenName(String someName, String[] tokens) {
        int currentLength = someName.length();
        while (currentLength > MAX_LENGTH) {
            int tokenIndex = getIndexOfLongest(tokens);
            String oldToken = tokens[tokenIndex];
            tokens[tokenIndex] = abbreviate(oldToken);
            currentLength -= oldToken.length() - tokens[tokenIndex].length();
        }
    }

    private static String assembleResults(String[] tokens) {
        StringBuilder result = new StringBuilder(tokens[0]);
        for (int j = 1; j < tokens.length; j++) {
            result.append("_").append(tokens[j]);
        }
        return result.toString();
    }

    private static String abbreviate(String token) {
        final String VOWELS = "AEIOUaeiou";
        boolean vowelFound = false;
        for (int i = token.length() - 1; i >= 0; i--) {
            if (!vowelFound)
                vowelFound = VOWELS.contains(String.valueOf(token.charAt(i)));
            else if (!VOWELS.contains(String.valueOf(token.charAt(i))))
                return token.substring(0, i + 1);
        }
        return "";
    }

    private static int getIndexOfLongest(String[] tokens) {
        int maxLength = 0;
        int index = -1;
        for (int i = 0; i < tokens.length; i++) {
            String string = tokens[i];
            if (maxLength < string.length()) {
                maxLength = string.length();
                index = i;
            }
        }
        return index;
    }

    @Override
    public String classToTableName(String aClassName) {

        return abbreviateName(super
                .classToTableName(addUnderscores(aClassName)));
    }
}