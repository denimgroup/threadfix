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
package com.denimgroup.threadfix.framework.impl.dotNet;

import com.denimgroup.threadfix.framework.ResourceManager;
import org.junit.Test;

import java.util.Collection;

/**
 * Created by mac on 8/27/14.
 */
public class ViewModelParsingTests {

    String[] models = {
            "ExternalLoginConfirmationViewModel",
            "ManageUserViewModel",
            "LoginViewModel",
            "RegisterViewModel"
    };

    int[] expectedSizes = { 1, 3, 3, 3 };

    @Test
    public void testBasicModelParsing() {
        ViewModelParser parser = ViewModelParser.parse(ResourceManager.getDotNetMvcFile("AccountViewModels.cs"));

        assert parser.map.size() == 4 :
                "Map had " + parser.map.size() + " entries instead of 3.";

        for (String model : models) {
            assert parser.map.containsKey(model) :
                    "Map didn't have an entry for " + model;
        }

        for (int i = 0; i < models.length; i++) {
            int actualSize = parser.map.get(models[i]).size();
            int expected = expectedSizes[i];

            assert actualSize == expected :
                    models[i] + " had " + actualSize + " but was expecting " + expected;
        }
    }

    @Test
    public void testDirectorySpidering() {
        DotNetModelMappings mappings = getDotNetModelMappings();

        Collection<String> parameters = mappings.getPossibleParametersForModelType("Course").getPossibleParameters();
        int courseFieldSize = parameters.size();

        assert courseFieldSize > 0 : "Got 0 fields for Course.";

        assert parameters.contains("Title") : "Fields didn't contain 'Title'";
    }

    private DotNetModelMappings getDotNetModelMappings() {
        return new DotNetModelMappings(ContosoUtilities.getContosoLocation());
    }

    @Test
    public void testFieldSpidering() {
        DotNetModelMappings mappings = getDotNetModelMappings();

        Collection<String> parameters = mappings.getPossibleParametersForModelType("Course").getPossibleParameters();
        int courseFieldSize = parameters.size();

        assert courseFieldSize > 0 : "Got 0 fields for Course.";

        System.out.println("Got parameters " + parameters);

        assert parameters.contains("Department.Name") : "Fields didn't contain 'Department.Name'";
    }

    @Test
    public void testStudentParsing() {
        ViewModelParser parser = ViewModelParser.parse(ResourceManager.getDotNetMvcFile("Student.cs"));

        assert parser.map.size() == 1 :
                "Map had " + parser.map.size() + " entries instead of 1.";

        assert parser.map.containsKey("Student") :
                "Map didn't contain the 'Student' key.";

        assert parser.superClassMap.size() == 1 :
                "Superclass not found.";

        assert parser.superClassMap.containsKey("Student") :
                "Didn't have Student key in " + parser.superClassMap;

        assert parser.superClassMap.get("Student").equals("Person") :
                "Student's superclass was " + parser.superClassMap.get("Student");
    }

    @Test
    public void testProblemParsing() {
        ViewModelParser parser = ViewModelParser.parse(ResourceManager.getDotNetMvcFile("ProblemEntity.cs"));

        assert parser.map.size() == 1 :
                "Map had " + parser.map.size() + " entries instead of 1.";

        assert parser.map.containsKey("TestApplication") :
                "Map didn't contain the 'TestApplication' key.";
    }

    @Test
    public void testMultiValueProperty() {
        DotNetModelMappings mappings = getDotNetModelMappings();

        Collection<String> parameters = mappings.getPossibleParametersForModelType("Student").getPossibleParameters();
        int courseFieldSize = parameters.size();

        assert courseFieldSize > 0 : "Got 0 fields for Course.";

        System.out.println("Got parameters " + parameters);

        assert !parameters.contains("Enrollments.EnrollmentID") : "Enrollments.EnrollmentID was found. This is impossible to bind to.";

        assert parameters.contains("Enrollments[0].EnrollmentID") : "Enrollments[0].EnrollmentID";
    }
}