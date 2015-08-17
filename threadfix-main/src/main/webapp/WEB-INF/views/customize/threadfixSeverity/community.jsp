<%@ include file="/common/taglibs.jsp"%>

<head>
    <title>Customize ThreadFix Severities</title>
    <cbs:cachebustscript src="/scripts/community-severity-text-controller.js"/>
</head>

<body id="config" ng-controller="CommunitySeverityTextController">
    <%@ include file="/WEB-INF/views/angular-init.jspf"%>

    <%@ include file="/WEB-INF/views/successMessage.jspf" %>
    <%@ include file="/WEB-INF/views/errorMessage.jspf"%>

    <h2>Show and Hide</h2>

    <%@ include file="/WEB-INF/views/filters/severityFilterForm.jsp" %>
</body>