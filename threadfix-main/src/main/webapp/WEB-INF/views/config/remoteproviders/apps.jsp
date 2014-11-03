<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Remote Providers</title>
	
	<script type="text/javascript">
	$(document).ready(function(){ 
		$("#orgSelect").change(function() {
            var $appSelect = $("#appSelect");
			$appSelect.html('');
            $appSelect.append('<option value="-1"></option>');
			var options = '';
			
			<c:forEach var="organization" items="${organizationList}">
			    if("${organization.id}" == $("#orgSelect").val()) {
					<c:forEach var="application" items="${ organization.activeApplications}">
						options += '<option value="${ application.id}"><c:out value="${ application.name }"/></option>';
					</c:forEach>
			    }
			</c:forEach>

            $appSelect.append(options);
		});
	});
	</script>
</head>

<body id="config">

	<spring:url value="" var="emptyUrl"/>
	<form:form modelAttribute="remoteProviderType" action="${ fn:escapeXml(emptyUrl) }">
	<table class="table table-striped">
		<thead>
			<tr>
				<td>Name / ID</td>
				<td>Organization</td>
				<td>Application</td>
			</tr>
		</thead>
		<tbody>
			<c:forEach var="application" varStatus="vs" items="${ remoteProviderType.remoteProviderApplications }">
				<tr class="bodyRow">
					<td><c:out value="${ application.nativeName }"/></td>
					<td>
						<script type="text/javascript">
							$(document).ready(function(){ 
								$("#orgSelect${vs.index}").change(function() {
									alert('hi');
									$("#appSelect${vs.index}").html('');
									$("#appSelect${vs.index}").append('<option value="-1"></option>');
									var options = '';
									
									<c:forEach var="organization" items="${organizationList}">
									    if("${organization.id}" == $("#orgSelect${vs.index}").val()) {
											<c:forEach var="application" items="${ organization.activeApplications}">
												options += '<option value="${ application.id}"><c:out value="${ application.name }"/></option>';
											</c:forEach>
									    }
									</c:forEach>
						
									$("#appSelect${vs.index}").append(options);
								});
							});
						</script>
						<select id="orgSelect${vs.index}">
							<option value="-1"></option>
							<c:forEach var="organization" items="${ organizationList }">
								<c:if test="${ organization.active }">
								<option value="${ organization.id }">
									<c:out value="${ organization.name }"/>
								</option>
								</c:if>
							</c:forEach>
						</select>
					</td>
					<td>
						<form:select path="remoteProviderApplications[${vs.index}].application.id" id="appSelect${vs.index}">
							<option value="-1"></option>
						</form:select>
					</td>
				</tr>
			</c:forEach>
		</tbody>
	</table>
	<button id="submitButton" class="btn btn-primary" type="submit">Update Applications</button>
	</form:form>
	
</body>