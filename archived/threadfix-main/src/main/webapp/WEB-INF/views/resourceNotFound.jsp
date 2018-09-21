<%@ include file="/common/taglibs.jsp"%>

<head>
    <title><spring:message code="404.title"/></title>
    <meta name="heading" content="<spring:message code="404.title"/>"/>
</head>
<h2>Resource Not Found</h2>
<br/>
<spring:url value="/" var="homeUrl"/>
<p>
    We were unable to find the resource that you requested. 
    This could be because the requested item never existed or because it was deleted.<br><br>
    You may want to <a href="#" onclick="history.back();return false">go back a page</a> or 
    <a ng-non-bindable href="<c:out value="${homeUrl}"/>">go to the Home page.</a>
</p>
