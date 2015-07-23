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

import com.denimgroup.threadfix.data.enums.TagType;
import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonView;
import org.hibernate.validator.constraints.NotEmpty;

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.util.HashSet;
import java.util.Set;

/**
 * Created by stran on 10/13/2014.
 */

@Entity
@Table(name = "Tag")
public class Tag extends AuditableEntity {
    private static final long serialVersionUID = 6892872482302897120L;
    private static final int NAME_LENGTH = 60;

    @NotEmpty(message = "{errors.required}")
    @Size(max = NAME_LENGTH, message = "{errors.maxlength} " + NAME_LENGTH + ".")
    private String name;

    private Boolean enterpriseTag = false;
    private Boolean tagForComment = false;
    private String defaultJsonFilter;
    private TagType type;

    private Set<Application> applications = new HashSet<Application>(0);
    private Set<VulnerabilityComment> vulnerabilityComments = new HashSet<VulnerabilityComment>(0);
    private Set<Vulnerability> vulnerabilities = new HashSet<Vulnerability>(0);

    @Column(length = NAME_LENGTH, nullable = false)
    @JsonView(Object.class)
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @ManyToMany(mappedBy = "tags")
    @JsonIgnore
    public Set<Application> getApplications() {
        return applications;
    }

    public void setApplications(Set<Application> applications) {
        this.applications = applications;
    }

    @ManyToMany(fetch = FetchType.LAZY, mappedBy = "tags")
    @JsonIgnore
    public Set<VulnerabilityComment> getVulnerabilityComments() {
        return vulnerabilityComments;
    }

    public void setVulnerabilityComments(Set<VulnerabilityComment> vulnerabilityComments) {
        this.vulnerabilityComments = vulnerabilityComments;
    }

    @ManyToMany(fetch = FetchType.LAZY, mappedBy = "tags")
    @JsonIgnore
    public Set<Vulnerability> getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(Set<Vulnerability> vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    @Column(nullable = true)
    @JsonView(AllViews.TableRow.class)
    public Boolean getEnterpriseTag() {
        return enterpriseTag;
    }

    public void setEnterpriseTag(Boolean enterpriseTag) {
        this.enterpriseTag = enterpriseTag;
    }

    @Column(length = 1024, nullable = true)
    @JsonView(AllViews.VulnSearchApplications.class)
    public String getDefaultJsonFilter() {
        return defaultJsonFilter;
    }

    public void setDefaultJsonFilter(String defaultJsonFilter) {
        this.defaultJsonFilter = defaultJsonFilter;
    }

    @Transient
    @JsonIgnore
    public int getVulnCommentsCount() {
        int numVulnComments = 0;
        for (VulnerabilityComment comment: vulnerabilityComments) {
            if (comment.getVulnerability() != null
                    && comment.getVulnerability().getApplication() != null
                    && comment.getVulnerability().getApplication().isActive())
                numVulnComments++;
        }
        return numVulnComments;

    }
    @Transient
    public boolean getDeletable() {
        if (enterpriseTag == null)
            enterpriseTag = false;
        return applications.size()==0
                && getVulnCommentsCount()==0
                && vulnerabilities.size() == 0
                && !enterpriseTag;
    }

    @Column(nullable = true)
    @JsonIgnore
    public Boolean getTagForComment() {
        return (tagForComment != null && tagForComment) || getType() == TagType.COMMENT;
    }

    public void setTagForComment(Boolean tagForComment) {
        this.tagForComment = tagForComment;
    }

    @Column(nullable = true)
    @JsonView(Object.class)
    public TagType getType() {
        return type != null ? type : TagType.APPLICATION;
    }

    public void setType(TagType type) {
        this.type = type;
    }
    String encodedName = null;
    @JsonView(AllViews.VulnSearchApplications.class)
    @Transient
    public String getEncodedName() {
        return encodedName;
    }

    public void setEncodedName(String name) {
        encodedName = name;
    }
}
