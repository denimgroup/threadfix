<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>System error</title>
</head>

<h2>System error</h2>

<c:if test="${ not empty time }">
	A system error occurred and has been logged to the database at <span ng-non-bindable><c:out value="${ time }"/></span>.
	<security:authorize ifAnyGranted="ROLE_CAN_VIEW_ERROR_LOGS">
		<spring:url value="/configuration/logs/{logId}" var="logUrl">
			<spring:param name="logId" value="${ logId }"/>	
		</spring:url>
		<a ng-non-bindable href="<c:out value="${ logUrl }"/>"> View Error Log</a>
	</security:authorize>
</c:if>

<c:if test="${ empty time }">
	A system error occurred.
</c:if>

<br/><br/>

<spring:url value="/" var="homeUrl"/>
<a ng-non-bindable href="<c:out value="${ homeUrl }"/>">Back to Home Page</a>
