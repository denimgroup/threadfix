<%@ include file="/common/taglibs.jsp"%>

<head>
    <title>Custom Severity Names</title>
    <cbs:cachebustscript src="/scripts/custom-severity-text-controller.js"/>
</head>

<body id="config" ng-controller="CustomSeverityTextController">
    <%@ include file="/WEB-INF/views/angular-init.jspf"%>

    <%@ include file="/WEB-INF/views/successMessage.jspf" %>
    <%@ include file="/WEB-INF/views/errorMessage.jspf"%>

    <%@ include file="/WEB-INF/views/filters/severityFilterForm.jsp"%>
</body>