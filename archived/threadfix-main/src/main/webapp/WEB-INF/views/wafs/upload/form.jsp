<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Upload WAF Log</title>
</head>

<body id="wafs">
	<h2>Upload WAF Log</h2>
	
<spring:url value="upload" var="uploadUrl"></spring:url>	
<form:form method="post" action="${ fn:escapeXml(uploadUrl) }" enctype="multipart/form-data">
	<form:errors path="*" cssClass="errors" />
	<table class="dataTable">
		<tbody>
			<tr>
				<td>Log File:</td>
				<td class="inputValue">
					<input type="file" name="file" size="50" id="logField" />
				</td>
			</tr>
		</tbody>
	</table>
	<br />
	<input type="submit" value="Upload File" id="uploadLogButton"/>
	<span style="padding-left: 10px"><a href="<spring:url value="/wafs"/>">Cancel</a></span>
</form:form>
</body>