<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>System error</title>
</head>

<h2>System error</h2>

A system error occurred.

<c:out value="${ exception }"/>

<br/><br/><!-- error.jsp -->

<spring:url value="/" var="homeUrl"/>
<a href="<c:out value="${homeUrl}"/>">Home</a>

