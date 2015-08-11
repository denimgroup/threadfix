<%@ include file="/common/taglibs.jsp"%>

<head>
    <title>Customize ThreadFix Vulnerability Types</title>
    <cbs:cachebustscript src="/scripts/vulnerability-filters-controller.js"/>
    <cbs:cachebustscript src="/scripts/modal-controller-with-config.js"/>
    <cbs:cachebustscript src="/scripts/custom-cwe-text-controller.js"/>
</head>

<body>
    <c:if test="${ canManageVulnFilters and canManageCustomCweText }">
        <h2>Customize ThreadFix Vulnerability Types</h2>

        <tabset>
            <tab heading="Severity Mappings">
                <%@ include file="/WEB-INF/views/angular-init.jspf"%>

                <%@ include file="cweToSeverity.jsp" %>
            </tab>
            <tab heading="Custom Text">
                <%@ include file="/WEB-INF/views/angular-init.jspf"%>

                <%@ include file="cweCustomText.jsp" %>
            </tab>
        </tabset>
    </c:if>

    <c:if test="${ canManageVulnFilters }">
        <c:if test="${ not canManageCustomCweText }">
            <%@ include file="/WEB-INF/views/angular-init.jspf"%>

            <h2>Customize Severities for ThreadFix Vulnerability Types (CWE)</h2>

            <%@ include file="cweToSeverity.jsp" %>
        </c:if>
    </c:if>

    <c:if test="${ canManageCustomCweText }">
        <c:if test="${ not canManageVulnFilters }">
            <h2>Set Custom Text for ThreadFix Vulnerability Types (CWE)</h2>

            <%@ include file="/WEB-INF/views/angular-init.jspf"%>

            <%@ include file="cweCustomText.jsp" %>
        </c:if>
    </c:if>

</body>
