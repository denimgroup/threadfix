package com.denimgroup.threadfix.framework.engine;

import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.SurfaceLocation;
import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.data.enums.InformationSourceType;
import com.denimgroup.threadfix.framework.engine.full.EndpointQuery;
import com.denimgroup.threadfix.framework.engine.full.EndpointQueryBuilder;
import com.denimgroup.threadfix.framework.engine.partial.PartialMapping;
import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by mac on 1/22/14.
 */
public class ThreadFixInterface {

    private ThreadFixInterface(){}

    public static EndpointQuery toEndpointQuery(Finding finding) {
        EndpointQueryBuilder builder = EndpointQueryBuilder.start();

        SurfaceLocation location = finding.getSurfaceLocation();

        if (location != null) {
            if (location.getHttpMethod() != null) {
                builder.setHttpMethod(location.getHttpMethod());
            }

            if (location.getPath() != null) {
                builder.setDynamicPath(location.getPath());
            }

            if (location.getParameter() != null) {
                builder.setParameter(location.getParameter());
            }
        }


        if (finding.getIsStatic()) {
            builder.setInformationSourceType(InformationSourceType.STATIC);
        } else {
            builder.setInformationSourceType(InformationSourceType.DYNAMIC);
        }

        if (finding.getSourceFileLocation() != null) {
            builder.setStaticPath(finding.getSourceFileLocation());
        }

        if (finding.getDataFlowElements() != null && !finding.getDataFlowElements().isEmpty()) {
            builder.setCodePoints(toCodePoints(finding.getDataFlowElements()));
        }

        return builder.generateQuery();
    }

    public static List<CodePoint> toCodePoints(List<DataFlowElement> elements) {
        List<CodePoint> results = new ArrayList<>();

        if (elements != null) {
            for (DataFlowElement element : elements) {
                results.add(toCodePoint(element));
            }
        }

        return results;
    }

    public static CodePoint toCodePoint(DataFlowElement e) {
        return new DefaultCodePoint(e.getSourceFileName(), e.getLineNumber(), e.getLineText());
    }

    public static PartialMapping toPartialMapping(final Finding finding) {
        return new PartialMapping() {

            @Override
            public String getStaticPath() {
                return finding.getSourceFileLocation();
            }

            @Override
            public String getDynamicPath() {
                if (finding.getStaticPathInformation() != null) {
                    return finding.getStaticPathInformation().getValue();
                } else if (finding.getSurfaceLocation() != null && finding.getSurfaceLocation().getPath() != null){
                    return finding.getSurfaceLocation().getPath();
                } else {
                    return null;
                }
            }

            @NotNull
            @Override
            public FrameworkType guessFrameworkType() {
                return FrameworkType.NONE;
            }

        };
    }

    public static List<PartialMapping> toPartialMappingList(Scan scan) {
        List<PartialMapping> results = new ArrayList<PartialMapping>();

        if (scan.getFindings() != null) {
            for (Finding finding : scan.getFindings()) {
                results.add(toPartialMapping(finding));
            }
        }

        return results;
    }
}
