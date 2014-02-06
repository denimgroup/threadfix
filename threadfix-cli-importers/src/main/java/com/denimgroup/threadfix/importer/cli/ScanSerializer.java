package com.denimgroup.threadfix.importer.cli;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;

/**
 * Created by mac on 2/6/14.
 */
public class ScanSerializer {

    // Format is channel vuln code, channel vuln name, CWE, severity, file, path, parameter
    // TODO make this more configurable.
    public String toCSVString(Scan scan) {
        StringBuilder builder = new StringBuilder();

        for (Finding finding : scan) {
            builder.append(finding.getChannelVulnerability().getCode()).append(',');
            builder.append(finding.getChannelVulnerability().getName()).append(',');
            builder.append(finding.getChannelVulnerability().getGenericVulnerability().getName()).append(',');
            builder.append(finding.getChannelSeverity().getName()).append(',');
            builder.append(finding.getSourceFileLocation()).append(',');
            builder.append(finding.getSurfaceLocation().getPath()).append(',');
            builder.append(finding.getSurfaceLocation().getParameter());
            builder.append("\n");
        }

        return builder.toString();
    }
}
