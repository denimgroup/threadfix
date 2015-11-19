<%@ include file="/common/taglibs.jsp"%>

<head>
	<title ng-non-bindable><c:out value="${ application.name }"/> Scan Upload Confirmation</title>
</head>

<body id="apps">
	<h2 ng-non-bindable><c:out value="${ application.name }"/> Empty Scan Upload Confirmation</h2>

	You have uploaded an empty scan. Click yes to continue, and no to go back to the scan page.
	<br/><br/>
	<spring:url value="upload/{scanId}/confirm" var="confirmationUrl">
		<spring:param name="scanId" value="${ scanId }"/>
	</spring:url>
	<a href="${ fn:escapeXml(confirmationUrl) }">Yes</a>
	
	<spring:url value="upload/{scanId}/cancel" var="cancelUrl">
		<spring:param name="scanId" value="${ scanId }"/>
	</spring:url>
	<a href="${ fn:escapeXml(cancelUrl) }">No</a>
				
</body>