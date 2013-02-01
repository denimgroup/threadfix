<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>System error</title>
</head>

<h2>System error</h2>

<c:if test="${ not empty id }">
	A system error occurred and has been logged to the database with id <c:out value="${ id }"/>.
</c:if>

<c:if test="${ empty id }">
	A system error occurred.
</c:if>

<br/><br/>

<spring:url value="/" var="homeUrl"/>
<a href="<c:out value="${homeUrl}"/>">Back to Home Page</a>
