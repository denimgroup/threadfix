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

package com.denimgroup.threadfix.service.defects.utils.hpqc.infrastructure;

import javax.xml.bind.annotation.*;
import java.util.ArrayList;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * Created by stran on 3/14/14.
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlRootElement(name = "Domains")
public class Domains {
    @XmlElement(name="Domain")
    List<Domain> domains;

    public List<Domain> getDomains() {
        return domains;
    }

    public void setDomains(List<Domain> domains) {
        this.domains = domains;
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class Domain {
        @XmlAttribute(name="Name")
        String name;
        @XmlElement(name="Projects")
        Domain.Projects projects;

        public Domain.Projects getProjects() {
            return projects;
        }

        public String getName() {
            return name;
        }


        public void setName(String name) {
            this.name = name;
        }


        public void setProjects(Projects projects) {
            this.projects = projects;
        }

        @XmlAccessorType(XmlAccessType.FIELD)
        public static class Projects {
            @XmlElement(name="Project")
            List<Project> project;

            public Projects() {}
            public Projects(Projects projects) {
                this.project = new ArrayList<>(projects.getProject());
            }

            public List<Project> getProject() {
                if (project == null) {
                    project = list();
                }
                return this.project;
            }

            public void setProject(List<Project> projects) {
                this.project = projects;
            }

            @XmlAccessorType(XmlAccessType.FIELD)
            public static class Project {
                @XmlAttribute(name="Name")
                String projectName;

                public String getProjectName() {
                    return projectName;
                }


                public void setProjectName(String value) {
                    this.projectName = value;
                }
            }

        }
    }
}
