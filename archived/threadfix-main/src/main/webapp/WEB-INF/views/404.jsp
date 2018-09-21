<%@ include file="/common/taglibs.jsp"%>

<head>
  <title><spring:message code="404.title"/></title>
  <meta name="heading" content="<spring:message code="404.title"/>"/>
</head>
<h2>Error</h2>
<br/>
<p>
  <spring:url value="/" var="homeUrl"/>
  <spring:message code="404.message" arguments="${ homeUrl }" />
</p>