<%@ include file="/common/taglibs.jsp"%>

<head>
    <title>Customize Scanner Severities</title>
    <cbs:cachebustscript src="/scripts/scan-result-filters-controller.js"/>
    <cbs:cachebustscript src="/scripts/modal-controller-with-config.js"/>
</head>

<body>
    <%@ include file="/WEB-INF/views/angular-init.jspf"%>

    <%@ include file="/WEB-INF/views/successMessage.jspf" %>
    <%@ include file="/WEB-INF/views/errorMessage.jsp" %>
    <%@ include file="newForm.jsp" %>
    <%@ include file="editForm.jsp" %>

    <%@ include file="ignoreResults.jspf" %>
</body>