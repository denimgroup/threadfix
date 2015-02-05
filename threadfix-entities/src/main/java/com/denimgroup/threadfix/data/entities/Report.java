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

import org.hibernate.validator.constraints.NotEmpty;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.validation.constraints.Size;

/**
 * @author zabdisubhan
 *
 */
@Entity
@Table(name = "Report")
public class Report extends BaseEntity {

    private static final long serialVersionUID = -1612233741957801615L;

    public final static int NAME_LENGTH = 60;
    public final static int FILE_PATH_LENGTH = 255;

    private Boolean available;
    private Boolean nativeReport;
    private String displayName;
    private String shortName;
    private String jspFilePath;
    private String jsFilePath;


    public Boolean getAvailable() {
        return available != null && available;
    }

    public void setAvailable(Boolean available) {
        this.available = available;
    }

    public Boolean getNativeReport() {
        return nativeReport != null && nativeReport;
    }

    public void setNativeReport(Boolean nativeReport) {
        this.nativeReport = nativeReport;
    }

    @Column(nullable = false)
    @Size(max = NAME_LENGTH, message = "{errors.maxlength} " + NAME_LENGTH + ".")
    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    @Column(nullable = false)
    @Size(max = NAME_LENGTH, message = "{errors.maxlength} " + NAME_LENGTH + ".")
    public String getShortName() {
        return shortName;
    }

    public void setShortName(String shortName) {
        this.shortName = shortName;
    }

    @Column(nullable = false)
    @NotEmpty(message = "{errors.required}")
    @Size(max = FILE_PATH_LENGTH, message = "{errors.maxlength} " + FILE_PATH_LENGTH + ".")
    public String getJspFilePath() {
        return jspFilePath;
    }

    public void setJspFilePath(String jspFilePath) {
        this.jspFilePath = jspFilePath;
    }

    @Column(nullable = true)
    @Size(max = FILE_PATH_LENGTH, message = "{errors.maxlength} " + FILE_PATH_LENGTH + ".")
    public String getJsFilePath() {
        return jsFilePath;
    }

    public void setJsFilePath(String jsFilePath) {
        this.jsFilePath = jsFilePath;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Report)) return false;

        Report that = (Report) o;

        return shortName.equals(that.shortName);
    }

    @Override
    public int hashCode() {
        return shortName.hashCode();
    }
}
