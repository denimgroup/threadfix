package com.denimgroup.threadfix.data.entities;

/**
 * Created by zabdisubhan on 8/14/14.
 */

import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name="ScheduledRemoteProviderImport")
public class ScheduledRemoteProviderImport extends ScheduledJob {

    private static final long serialVersionUID = 1223869621339558275L;

}
