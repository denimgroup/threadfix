<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Finding Details</title>
	<meta name="heading" content="<fmt:message key='mainMenu.heading'/>" />
	<cbs:cachebustscript src="/scripts/finding-controller.js"/>
</head>

<body id="apps" ng-controller="FindingController">
	<%@ include file="/WEB-INF/views/scans/finding/findingHeader.jsp" %>
	<%@ include file="/WEB-INF/views/angular-init.jspf"%>
	<%@ include file="/WEB-INF/views/scans/finding/detail.jsp" %>
</body>
