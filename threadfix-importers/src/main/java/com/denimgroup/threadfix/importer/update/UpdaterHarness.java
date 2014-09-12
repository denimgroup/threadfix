////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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
package com.denimgroup.threadfix.importer.update;

import com.denimgroup.threadfix.importer.util.ResourceUtils;
import com.denimgroup.threadfix.logging.SanitizedLogger;

import java.io.*;
import java.util.Calendar;

/**
 * Created by mac on 9/12/14.
 */
final class UpdaterHarness {

    private final Calendar lastUpdatedTime;

    public UpdaterHarness(Calendar lastUpdatedTime) {
        this.lastUpdatedTime = lastUpdatedTime;
    }

    private static final SanitizedLogger LOG = new SanitizedLogger(UpdaterHarness.class);

    public Calendar executeUpdates(Updater updater) {
        return processFilesInternal(updater, true);
    }

    public Calendar findMostRecentDate(Updater updater) {
        return processFilesInternal(updater, false);
    }

    private Calendar processFilesInternal(Updater updater, boolean doUpdates) {
        Iterable<File> defectTrackersFiles = ResourceUtils.getFilesFromResourceFolder(updater.getFolder());

        Calendar latestUpdateDate = lastUpdatedTime;

        for (File defectTrackersFile : defectTrackersFiles) {
            try (BufferedReader bufferedReader = new BufferedReader(new FileReader(defectTrackersFile))) {
                Calendar fileDate = UpdaterUtils.getCalendarFromFirstLine(bufferedReader);

                if (doUpdates && (lastUpdatedTime == null || fileDate.after(lastUpdatedTime))) {
                    updater.doUpdate(defectTrackersFile.getName(), bufferedReader);
                }

                if (latestUpdateDate == null || fileDate.after(latestUpdateDate)) {
                    latestUpdateDate = fileDate;
                }

            } catch (FileNotFoundException e) {
                LOG.error("Received FileNotFoundException for file " + defectTrackersFile.getName());
                throw new IllegalStateException(
                        "Can't continue without mappings file " + defectTrackersFile.getName(), e);
            } catch (IOException e) {
                LOG.error("Received IOException for file " + defectTrackersFile.getName());
                throw new IllegalStateException(
                        "Can't continue without mappings file " + defectTrackersFile.getName(), e);
            }
        }

        return latestUpdateDate;
    }

}
