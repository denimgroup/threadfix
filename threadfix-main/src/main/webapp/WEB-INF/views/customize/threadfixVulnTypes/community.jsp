<%@ include file="/common/taglibs.jsp"%>

<head>
    <title>Customize ThreadFix Vulnerability Types</title>
    <cbs:cachebustscript src="/scripts/vulnerability-filters-controller.js"/>
    <cbs:cachebustscript src="/scripts/modal-controller-with-config.js"/>
    <cbs:cachebustscript src="/scripts/custom-cwe-text-controller.js"/>
</head>

<body>
    <%--<%@ include file="/WEB-INF/views/angular-init.jspf"%>--%>

    <h2>Customize ThreadFix Vulnerability Types</h2>

    <tabset>
        <tab heading="Severity Mappings">
            <%@ include file="cweToSeverity.jsp" %>
        </tab>
        <tab heading="Custom Text">
            <%@ include file="cweCustomText.jsp" %>
        </tab>
    </tabset>

</body>
