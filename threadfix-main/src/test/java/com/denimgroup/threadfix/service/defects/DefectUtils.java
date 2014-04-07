package com.denimgroup.threadfix.service.defects;

import com.denimgroup.threadfix.data.entities.Defect;
import com.denimgroup.threadfix.data.entities.GenericSeverity;
import com.denimgroup.threadfix.data.entities.GenericVulnerability;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import org.apache.commons.exec.util.StringUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class DefectUtils {

    private DefectUtils(){}

    public static List<Defect> getDefectList(String... nativeIds) {

        List<Defect> defects = new ArrayList<>();

        for (String nativeId : nativeIds) {
            Defect defect = new Defect();
            defect.setNativeId(nativeId);
            defects.add(defect);
        }

        return defects;
    }

    public static List<Vulnerability> getSampleVulnerabilities() {
        Vulnerability vulnerability = new Vulnerability();

        vulnerability.setGenericSeverity(new GenericSeverity());
        vulnerability.getGenericSeverity().setName("Critical");

        vulnerability.setGenericVulnerability(new GenericVulnerability());
        vulnerability.getGenericVulnerability().setName("XSS");

        return Arrays.asList(vulnerability);
    }

    public static DefectMetadata getBasicMetadata(ProjectMetadata projectMetadata) {
        return new DefectMetadata("Dummy Description", "simple preamble",
                projectMetadata.getComponents().get(0),
                projectMetadata.getVersions().get(0),
                projectMetadata.getSeverities().get(0),
                projectMetadata.getPriorities().get(0),
                projectMetadata.getStatuses().get(0));
    }

    public static List<String> getProductsFromString(String projects) {
        return Arrays.asList(StringUtils.split(projects, ","));
    }

}
