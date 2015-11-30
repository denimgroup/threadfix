<%@ include file="/common/taglibs.jsp"%>

<head>
<title><fmt:message key="mainMenu.title" /></title>
<meta name="heading" content="<fmt:message key='mainMenu.heading'/>" />
<meta name="menu" content="MainMenu" />
</head>

<div class="separator"></div>

<c:if test="${ urlsUsedPresent }">
	<br/><br/>
	These URLs were found and successfully matched to applications:
	<c:forEach var="url" items="${ urlsUsed }">
		<br/><span ng-non-bindable><c:out value="${ url }"/></span>
	</c:forEach>
</c:if>

<c:if test="${ urlsNotUsedPresent }">
	<br/><br/>
	These URLs were found but could not be matched to an application:
	<c:forEach var="url" items="${ urlsNotUsed }">
		<br/><span ng-non-bindable><c:out value="${ url }"/></span>
	</c:forEach>
</c:if>

<a href="<c:url value="../editorganization/detail.html?orgId=${ org.id }"/>">Home</a>