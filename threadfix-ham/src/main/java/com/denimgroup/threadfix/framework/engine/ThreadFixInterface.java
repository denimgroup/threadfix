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
import javax.annotation.Nonnull;

import java.util.ArrayList;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

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
        List<CodePoint> results = list();

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

            @Nonnull
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
