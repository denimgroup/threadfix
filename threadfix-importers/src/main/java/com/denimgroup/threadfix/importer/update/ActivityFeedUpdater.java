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

import com.denimgroup.threadfix.data.dao.ActivityFeedTypeDao;
import com.denimgroup.threadfix.data.dao.ActivityTypeDao;
import com.denimgroup.threadfix.data.entities.ActivityFeedType;
import com.denimgroup.threadfix.data.entities.ActivityType;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;

/**
 * Created by mac on 11/6/14.
 */
@Service
class ActivityFeedUpdater implements Updater {

    enum State {
        BASE, FEED_TYPE, ACTIVITY_TYPE
    }

    private static final SanitizedLogger LOG = new SanitizedLogger(ActivityFeedUpdater.class);

    State state = State.BASE;

    @Autowired
    private ActivityFeedTypeDao activityFeedTypeDao;
    @Autowired
    private ActivityTypeDao     activityTypeDao;

    @Override
    public void doUpdate(String fileName, BufferedReader bufferedReader) throws IOException {
        String line;

        LOG.info("Starting event model updates");

        while ((line = bufferedReader.readLine()) != null) {
            if (line.equals("section.activityFeedType")) {
                state = State.FEED_TYPE;
            } else if (line.equals("section.activityType")) {
                state = State.ACTIVITY_TYPE;
            } else if (state == State.FEED_TYPE) {
                processFeedType(line);
            } else if (state == State.ACTIVITY_TYPE) {
                processActivityType(line);
            }
        }
    }

    private void processFeedType(String line) {
        ActivityFeedType feedType = activityFeedTypeDao.retrieveByName(line);

        if (feedType == null) {
            ActivityFeedType type = new ActivityFeedType();
            type.setName(line);
            activityFeedTypeDao.saveOrUpdate(type);

            LOG.info("Creating new activity feed type " + line);
        } else {
            LOG.debug("Already found activity feed type " + line);
        }
    }

    private void processActivityType(String line) {
        String[] lineSplit = line.split(",");
        if (lineSplit.length != 2) {
            throw new IllegalStateException("ActivityType lines must have two sections separated by a comma, not " + line);
        }

        ActivityType activityType = activityTypeDao.retrieveByName(lineSplit[0]);

        if (activityType == null) {
            ActivityType type = new ActivityType();
            type.setName(lineSplit[0]);
            type.setFormatString(lineSplit[1]);
            activityTypeDao.saveOrUpdate(type);

            LOG.info("Created new activity type " + lineSplit[0]);
        } else {
            if (activityType.getFormatString() == null || !activityType.getFormatString().equals(lineSplit[1])) {
                activityType.setFormatString(lineSplit[1]);
                activityTypeDao.saveOrUpdate(activityType);
                LOG.info("Updated format string for activity type " + lineSplit[0]);
            } else {
                LOG.debug("No change for activity type " + line);
            }
        }
    }

    @Override
    public String getFolder() {
        return UpdaterConstants.EVENT_MODEL_FOLDER;
    }
}
