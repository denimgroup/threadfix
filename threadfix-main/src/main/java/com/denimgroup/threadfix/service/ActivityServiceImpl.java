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
package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.dao.*;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.data.enums.ActivityFeedTypeName;
import com.denimgroup.threadfix.data.enums.ActivityTypeName;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.listOf;

/**
 * Created by mac on 11/6/14.
 */
@Service
public class ActivityServiceImpl
        extends AbstractGenericObjectService<Activity>
        implements ActivityService {

    private static final SanitizedLogger LOG = new SanitizedLogger(ActivityServiceImpl.class);

    @Autowired
    private ActivityDao         activityDao;
    @Autowired
    private ActivityTypeDao     activityTypeDao;
    @Autowired
    private ActivityFeedDao     activityFeedDao;
    @Autowired
    private ActivityFeedTypeDao activityFeedTypeDao;
    @Autowired
    private UserService         userService;
    @Autowired
    private VulnerabilityDao vulnerabilityDao;

    @Override
    GenericObjectDao<Activity> getDao() {
        return activityDao;
    }

    public Activity createActivityForScan(Scan scan) {
        if (scan == null) {
            throw new IllegalArgumentException("Can't create event for null scan.");
        }

        Integer appId = scan.getApplication().getId(),
                teamId = scan.getApplication().getOrganization().getId(),
                scanId = scan.getId(),
                numberNew = scan.getNumberNewVulnerabilities(),
                numberClosed = scan.getNumberClosedVulnerabilities();

        Activity activity = new Activity();

        activity.setObjectId(scan.getId());

        activity.setUser(userService.getCurrentUser());

        ActivityType type = activityTypeDao.retrieveByName(ActivityTypeName.UPLOADED_SCAN);
        activity.setActivityType(type);

        List<ActivityFeed> activityFeeds = getFeedsForScan(teamId, appId);
        activity.setActivityFeedList(activityFeeds);

        String scannerType = scan.getApplicationChannel().getChannelType().getName();
        activity.setDetails(scannerType + " scan with " + numberNew + " new and " + numberClosed + " closed vulnerabilities.");

        activity.setLinkText("View Scan");
        activity.setLinkPath(getPathForScan(teamId, appId, scanId));

        activityDao.saveOrUpdate(activity);

        // I would prefer foreach but it throws ConcurrentModificationException for this code
        addActivityToFeeds(activity, activityFeeds);

        LOG.info("Created activity log for new scan.");

        return activity;
    }

    private String getPathForScan(Integer teamId, Integer appId, Integer scanId) {
        return "/organizations/" + teamId + "/applications/" + appId + "/scans/" + scanId;
    }

    private List<ActivityFeed> getFeedsForScan(Integer teamId, Integer appId) {
        List<ActivityFeed> feeds = list();

        feeds.add(getOrCreateFeed(ActivityFeedTypeName.TEAM, teamId));
        feeds.add(getOrCreateFeed(ActivityFeedTypeName.APPLICATION, appId));

        return feeds;
    }

    // entities created before the feed system was implemented won't have feed entries
    private ActivityFeed getOrCreateFeed(ActivityFeedTypeName name, Integer objectId) {
        ActivityFeed feed = activityFeedDao.retrieveByTypeAndObjectId(name, objectId);

        if (feed != null) {
            return feed;
        } else {
            ActivityFeed newFeed = new ActivityFeed();
            newFeed.setActivityFeedType(activityFeedTypeDao.retrieveByName(name));
            newFeed.setObjectId(objectId);
            newFeed.setActivityList(listOf(Activity.class));
            activityFeedDao.saveOrUpdate(newFeed);
            return newFeed;
        }
    }

    @Override
    public Activity createActivityForComment(VulnerabilityComment vulnerabilityComment, Integer vulnerabilityId) {
        if (vulnerabilityComment == null) {
            throw new IllegalArgumentException("Can't create event for null scan.");
        }

        Vulnerability vulnerability = vulnerabilityDao.retrieveById(vulnerabilityId);

        Integer appId = vulnerability.getApplication().getId(),
                teamId = vulnerability.getApplication().getOrganization().getId();

        Activity activity = new Activity();

        // TODO fix this probably
//        activity.setObjectId(vulnerabilityComment.getId());

        activity.setParentId(vulnerabilityId);

        activity.setUser(userService.getCurrentUser());

        ActivityType type = activityTypeDao.retrieveByName(ActivityTypeName.SUBMITTED_COMMENT);
        activity.setActivityType(type);

        List<ActivityFeed> activityFeeds = getFeedsForComment(teamId, appId, vulnerabilityId);
        activity.setActivityFeedList(activityFeeds);

        activity.setDetails(vulnerabilityComment.getComment());

        activity.setLinkText("View Vulnerability");
        activity.setLinkPath(getPathForVulnerability(teamId, appId, vulnerabilityId));

        activityDao.saveOrUpdate(activity);
        addActivityToFeeds(activity, activityFeeds);

        LOG.info("Created activity log for new scan.");

        return activity;
    }

    private void addActivityToFeeds(Activity activity, List<ActivityFeed> activityFeeds) {
        // I would prefer foreach but it throws ConcurrentModificationException for this code
        for (int i = 0; i < activityFeeds.size(); i++) {
            ActivityFeed feed = activityFeeds.get(i);
            feed.getActivityList().add(activity);
            activityFeedDao.saveOrUpdate(feed);
        }
    }

    private List<ActivityFeed> getFeedsForComment(Integer teamId, Integer appId, Integer vulnerabilityId) {
        List<ActivityFeed> feeds = list();

        feeds.add(getOrCreateFeed(ActivityFeedTypeName.TEAM, teamId));
        feeds.add(getOrCreateFeed(ActivityFeedTypeName.APPLICATION, appId));
        feeds.add(getOrCreateFeed(ActivityFeedTypeName.VULNERABILITY, vulnerabilityId));

        return feeds;    }

    private String getPathForVulnerability(Integer teamId, Integer appId, Integer vulnerabilityId) {
        return "/organizations/" + teamId + "/applications/" + appId + "/vulnerabilities/" + vulnerabilityId;
    }

}
