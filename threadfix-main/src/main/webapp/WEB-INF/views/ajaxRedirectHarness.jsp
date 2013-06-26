<%@ include file="/common/taglibs.jsp"%>

<spring:url value="${ contentPage }" var="targetUrl"></spring:url>

{ "isJSONRedirect" : true, "redirectURL" : "<c:out value='${ targetUrl }'/>" }