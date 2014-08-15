package com.denimgroup.threadfix.data.dao;

import com.denimgroup.threadfix.data.entities.ScheduledJob;

/**
 * Created by zabdisubhan on 8/15/14.
 */
public interface ScheduledJobDao<S extends ScheduledJob> extends GenericObjectDao<S> {

    public void delete(S scheduledJob);

}
