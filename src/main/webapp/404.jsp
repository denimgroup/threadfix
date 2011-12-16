<%@ include file="/common/taglibs.jsp"%>

<page:applyDecorator name="default">
<head>
    <title><spring:message code="404.title"/></title>
    <meta name="heading" content="<spring:message code="404.title"/>"/>
</head>
<h2>Error</h2>
<br/>
<p>
    <spring:message code="404.message" arguments="/threadfix/organizations" />
</p>
</page:applyDecorator>