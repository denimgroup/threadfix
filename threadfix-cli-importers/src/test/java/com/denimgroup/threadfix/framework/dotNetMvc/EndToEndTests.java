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
package com.denimgroup.threadfix.framework.dotNetMvc;

import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.framework.engine.ThreadFixInterface;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabase;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabaseFactory;
import com.denimgroup.threadfix.importer.utils.ParserUtils;
import org.junit.Test;

import java.io.File;
import java.util.Set;

/**
 * Created by mac on 8/18/14.
 */
public class EndToEndTests {

    @Test
    public void testDynamicScanHasXSSVuln() {
        Scan scan = ParserUtils.getScan("SBIR/contoso.xml");

        boolean succeeded = false;

        for (Finding finding : scan) {
            Integer genericId = finding.getChannelVulnerability().getGenericVulnerability().getId();
            if (genericId != null && genericId.equals(79)) {
                succeeded = true;
                System.out.println("Got it");
            } else {
                System.out.println("Got " + genericId);
            }
        }

        assert succeeded : "Didn't find 79.";
    }

    private EndpointDatabase getContosoEndpointDatabase(Scan inputScan) {
        return EndpointDatabaseFactory.getDatabase(
                getContosoLocation(),
                ThreadFixInterface.toPartialMappingList(inputScan)
        );
    }

    private File getContosoLocation() {
        String root = System.getProperty("PROJECTS_ROOT");
        assert root != null && new File(root).exists() : "Projects root didn't exist or was invalid.";

        String total = root + "ASP.NET MVC/ASP.NET MVC Application Using Entity Framework Code First";

        assert new File(total).exists() : "Contoso project didn't exist at " + total;

        return new File(total);
    }

    @Test
    public void testDynamicDatabaseLookups() {
        Scan scan = ParserUtils.getScan("SBIR/contoso.xml");

        EndpointDatabase database = getContosoEndpointDatabase(scan);

        assert database != null : "Database was null, can't continue";

        boolean succeededStudent = false, succeededCreate = false;

        for (Finding finding : scan) {
            Integer genericId = finding.getChannelVulnerability().getGenericVulnerability().getId();
            if (genericId != null && genericId.equals(79)) {
                Set<Endpoint> endpointList = database.findAllMatches(ThreadFixInterface.toEndpointQuery(finding));
                if (!endpointList.isEmpty()) {
                    String path = finding.getSurfaceLocation().getPath();
                    if (path.equals("/contoso/Student/Create")) {
                        for (Endpoint endpoint : endpointList) {
                            if (endpoint.getFilePath().endsWith("StudentController.cs")) {
                                succeededCreate = true;
                            }
                        }
                    } else if (path.equals("/contoso/Student")) {
                        for (Endpoint endpoint : endpointList) {
                            if (endpoint.getFilePath().endsWith("StudentController.cs")) {
                                succeededStudent = true;
                            }
                        }
                    }
                }
            } else {
                System.out.println("Got " + genericId);
            }
        }

        assert succeededCreate : "Didn't find /Student/Create.";
        assert succeededStudent : "Didn't find /Student.";
    }

    private String getExpectedPath(Finding finding) {
        String returnValue = null;
        for (DataFlowElement dataFlowElement : finding.getDataFlowElements()) {
            returnValue = getExpectedPath(dataFlowElement.getSourceFileName(), dataFlowElement.getLineNumber());
            if (returnValue != null) {
                break;
            }
        }
        return returnValue;
    }

    // This is basically the model we're trying to create
    private String getExpectedPath(String fileName, int lineNumber) {
        if (fileName.endsWith("Controller.cs")) {
            String shorterName = fileName.substring(fileName.lastIndexOf('/') + 1);

            switch (shorterName) {
                case "CourseController.cs":
                    if (lineNumber >= 20 && lineNumber <= 32) {
                        return "/Course";
                    } else if (lineNumber >= 35 && lineNumber <= 47) {
                        return "/Course/Details/{variable}";
                    } else if (lineNumber >= 49 && lineNumber <= 76) {
                        return "/Course/Create";
                    } else if (lineNumber >= 78 && lineNumber <= 114) {
                        return "/Course/Edit/{variable}";
                    } else if (lineNumber >= 125 && lineNumber <= 138) {
                        return "/Course/Delete/{variable}";
                    } else if (lineNumber >= 140 && lineNumber <= 148) {
                        return "/Course/DeleteConfirmed/{variable}";
                    } else if (lineNumber >= 150 && lineNumber <= 163) {
                        return "/Course/UpdateCourseCredits";
                    }
                    break;
                case "DepartmentController.cs":
                    if (lineNumber >= 21 && lineNumber <= 25) {
                        return "/Department";
                    } else if (lineNumber >= 28 && lineNumber <= 56) {
                        return "/Department/Details/{variable}";
                    } else if (lineNumber >= 59 && lineNumber <= 82) {
                        return "/Department/Create";
                    } else if (lineNumber >= 85 && lineNumber <= 165) {
                        return "/Department/Edit/{variable}";
                    } else if (lineNumber >= 189 && lineNumber <= 248) {
                        return "/Department/Delete/{variable}";
                    }
                    break;
                case "HomeController.cs":
                    if (lineNumber >= 15 && lineNumber <= 18) {
                        return "/Home";
                    } else if (lineNumber >= 20 && lineNumber <= 39) {
                        return "/Home/About";
                    } else if (lineNumber >= 41 && lineNumber <= 46) {
                        return "/Home/Contact";
                    }
                    break;
                case "InstructorController.cs":
                    if (lineNumber >= 21 && lineNumber <= 55) {
                        return "/Instructor";
                    } else if (lineNumber >= 58 && lineNumber <= 70) {
                        return "/Instructor/Details/{variable}";
                    } else if (lineNumber >= 72 && lineNumber <= 102) {
                        return "/Instructor/Create";
                    } else if (lineNumber >= 105 && lineNumber <= 122) {
                        return "/Instructor/Edit/{variable}";
                    } else if (lineNumber >= 141 && lineNumber <= 184) {
                        return "/Instructor/Edit/{variable}";
                    } else if (lineNumber >= 216 && lineNumber <= 253) {
                        return "/Instructor/Delete/{variable}";
                    }
                    break;
                case "StudentController.cs":
                    if (lineNumber >= 21 && lineNumber <= 69) {
                        return "/Student";
                    } else if (lineNumber >= 71 && lineNumber <= 75) {
                        return "/Student/XssPage";
                    } else if (lineNumber >= 78 && lineNumber <= 90) {
                        return "/Student/Details/{variable}";
                    } else if (lineNumber >= 93 && lineNumber <= 97) {
                        return "/Student/Create";
                    } else if (lineNumber >= 85 && lineNumber <= 165) {
                        return "/Student/Edit/{variable}";
                    } else if (lineNumber >= 189 && lineNumber <= 248) {
                        return "/Student/Delete/{variable}";
                    }
                    break;
                default:
                    assert false: "Failed on unknown controller at " + fileName;
            }
        }

        return null;
    }


    @Test
    public void testStaticDatabaseLookups() {
        Scan scan = ParserUtils.getScan("SBIR/contoso.fpr");

        EndpointDatabase database = getContosoEndpointDatabase(scan);

        assert database != null : "Database was null, can't continue";

        for (Finding finding : scan) {

            System.out.println(finding);

            Set<Endpoint> endpointList = database.findAllMatches(ThreadFixInterface.toEndpointQuery(finding));
            if (!endpointList.isEmpty()) {
                String expected = getExpectedPath(finding);
                if (expected != null) {
                    String firstPath = endpointList.iterator().next().getUrlPath();
                    assert expected.equals(firstPath) :
                            "Failed for Finding : " + finding +
                                    ", was expecting the path " + expected +
                                    " but got " + firstPath + ".";
                }

            }
        }

    }

}
