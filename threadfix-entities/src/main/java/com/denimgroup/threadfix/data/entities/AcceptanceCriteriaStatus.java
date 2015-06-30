////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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

package com.denimgroup.threadfix.data.entities;

import com.fasterxml.jackson.annotation.JsonView;

import javax.persistence.*;

/**
 * @author zabdisubhan
 */
@Entity
@Table(name = "AcceptanceCriteriaStatus")
public class AcceptanceCriteriaStatus extends AuditableEntity {

    private boolean passing = false;
    private Application application;
    private AcceptanceCriteria acceptanceCriteria;

    public boolean isPassing() {
        return passing;
    }

    public void setPassing(boolean passing) {
        this.passing = passing;
    }

    @ManyToOne
    @JsonView(Object.class)
    @JoinColumn(name = "Application_Id", nullable = false)
    public Application getApplication() {
        return application;
    }

    public void setApplication(Application application) {
        this.application = application;
    }

    @ManyToOne
    @JsonView(Object.class)
    @JoinColumn(name = "AcceptanceCriteria_Id", nullable = false)
    public AcceptanceCriteria getAcceptanceCriteria() {
        return acceptanceCriteria;
    }

    public void setAcceptanceCriteria(AcceptanceCriteria acceptanceCriteria) {
        this.acceptanceCriteria = acceptanceCriteria;
    }
}
