package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.entities.ScheduledJob;
import org.springframework.validation.BindingResult;

import java.util.List;

/**
 * Created by zabdisubhan on 8/14/14.
 */

public interface ScheduledJobService<S extends ScheduledJob> {

    public List<S> loadAll();

    public int save(S scheduledJob);

    public String delete(S scheduledJob);

    public S loadById(int scheduledJobId);

    public void validateDate(S scheduledJob, BindingResult result);
}
