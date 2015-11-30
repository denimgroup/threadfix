<%@ include file="/common/taglibs.jsp"%>

<head>
    <title>Application Limit Reached</title>
    <meta name="heading" content="Application Limit Reached"/>
</head>
<h2>Application Limit Reached</h2>
<br/>
<p ng-non-bindable>
    Your application has reached its maximum of <c:out value="${ numApplications }"/> applications.
    To create more, please contact Denim Group to upgrade your license.
</p>
