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
package com.denimgroup.threadfix.util;

import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.apache.commons.lang3.ArrayUtils;

import javax.annotation.Nullable;
import javax.validation.constraints.NotNull;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * Created by mcollins on 8/25/15.
 */
public class SimilarityCalculator {

    private SimilarityCalculator(){}

    private static final SanitizedLogger LOG = new SanitizedLogger(SimilarityCalculator.class);

    public static int calculateSimilarity(@NotNull String filePath1, @NotNull String filePath2) {

        String cleaned1 = filePath1.replaceAll("\\\\", "/");
        String cleaned2 = filePath2.replaceAll("\\\\", "/");

        String[] filePath1Split = cleaned1.split("/");
        String[] filePath2Split = cleaned2.split("/");

        if (cleaned1.equals(cleaned2)) {
            return filePath1Split.length;
        }

        ArrayUtils.reverse(filePath1Split);
        ArrayUtils.reverse(filePath2Split);

        int index = 0;
        for (; index < filePath1Split.length; index++) {
            if (index > filePath2Split.length - 1) {
                break;
            }

            if (!filePath1Split[index].equals(filePath2Split[index])) {
                break;
            }
        }

        return index;
    }

    @Nullable
    public static String findMostSimilarFilePath(@NotNull String filePath,
                                                 @NotNull Iterable<String> candidates) {
        int current = 0;
        List<String> currentTiedPaths = list();

        for (String candidate : candidates) {
            int score = calculateSimilarity(filePath, candidate);
            LOG.debug("Candidate " + candidate + " scored " + score);

            if (score > current) {
                currentTiedPaths.clear();
                currentTiedPaths.add(candidate);
                current = score;
            } else if (score == current && current != 0) {
                currentTiedPaths.add(candidate);
            }
        }

        if (currentTiedPaths.size() == 0) {
            LOG.debug("No path found.");
            return null;
        } else if (currentTiedPaths.size() > 1) {
            LOG.debug("Multiple paths found: " + currentTiedPaths);
            LOG.debug("Returning " + currentTiedPaths.get(0));
            return currentTiedPaths.get(0);
        } else {
            LOG.debug("Got single answer with score " + current);
            return currentTiedPaths.get(0);
        }
    }

}
