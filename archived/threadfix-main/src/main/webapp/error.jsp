<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>System error</title>
</head>

<h2>System error</h2>

A system error occurred.

<span ng-non-bindable><c:out value="${ exception }"/></span>

<br/><br/><!-- error.jsp -->

<spring:url value="/" var="homeUrl"/>
<a ng-non-bindable href="<c:out value="${homeUrl}"/>">Home</a>

