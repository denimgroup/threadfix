<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Remote Providers</title>
	
	<script type="text/javascript">
	$(document).ready(function(){ 
		$("#orgSelect").change(function() {
			$("#appSelect").html('');
			$("#appSelect").append('<option value="-1"></option>');
			var options = '';
			
			<c:forEach var="organization" items="${organizationList}">
			    if("${organization.id}" == $("#orgSelect").val()) {
					<c:forEach var="application" items="${ organization.activeApplications}">
						options += '<option value="${ application.id}"><c:out value="${ application.name }"/></option>';
					</c:forEach>
			    }
			</c:forEach>

			$("#appSelect").append(options);
		});
	});
	</script>
</head>

<body>
	<h2>Edit Mapping for <c:out value="${ remoteProviderApplication.nativeId }"/></h2>

	<spring:url value="" var="emptyUrl"></spring:url>	
	<form:form modelAttribute="remoteProviderApplication" action="${ fn:escapeXml(emptyUrl) }">
	
	<table style="border-spacing:10" class="dataTable">
		<tbody>
			<tr>
				<td>Team:</td>
				<td>
					<form:select path="application.organization.id" id="orgSelect">
						<option value="-1">Pick a Team</option>
						<c:forEach var="organization" items="${ organizationList }">
							<c:if test="${ organization.active }">
							<option value="${ organization.id }">
								<c:out value="${ organization.name }"/>
							</option>
							</c:if>
						</c:forEach>
					</form:select>
				</td>
				<td style="padding-left:5px">
					<form:errors path="application.organization.id" cssClass="errors" />
				</td>
			</tr>
			<tr>
				<td style="padding-right:10px">Application:</td>
				<td>
					<form:select path="application.id" id="appSelect">
						<option value="-1"></option>
					</form:select>
				</td>
				<td style="padding-left:5px">
					<form:errors path="application.id" cssClass="errors" />
				</td>
			</tr>
		</tbody>
	</table>
	
	<button style="margin-top:13px" id="submitButton" class="btn btn-primary" type="submit">Update Application</button>
	<span style="padding-left: 10px"><a id="backToIndexLink" href="<spring:url value="/configuration/remoteproviders/"/>">Back to Remote Provider Index</a></span>
	</form:form>
	
</body>