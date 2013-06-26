<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>System error</title>
</head>

<h2>System error</h2>

<c:if test="${ not empty uuid }">
	A system error occurred and has been logged to the database with id <c:out value="${ uuid }"/>.
	<security:authorize ifAnyGranted="ROLE_CAN_VIEW_ERROR_LOGS">
		<spring:url value="/configuration/logs/{logId}" var="logUrl">
			<spring:param name="logId" value="${ logId }"/>	
		</spring:url>
		<a href="${ logUrl }"> View Error Log</a>
	</security:authorize>
</c:if>

<c:if test="${ empty uuid }">
	A system error occurred.
</c:if>

<br/><br/>

<spring:url value="/" var="homeUrl"/>
<a href="<c:out value="${homeUrl}"/>">Back to Home Page</a>
