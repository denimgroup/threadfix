<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Reports</title>
	
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/ajax_replace.js"></script>
	<script type="text/javascript">
	$(document).ready(function(){ 
		$("#orgSelect").change(function() {
			$("#appSelect").html('');
			$("#appSelect").append('<option value="-1">All</option>');
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

<body id="reports">
	<div style="float:left" id="formDiv">
	
	<h2>Reports</h2>
	
	<c:if test="${ not empty error }">
		<center class="errors" ><c:out value="${ error }"/></center>
	</c:if>
	
	<div id="helpText">This page is used to generate various reports.
	<br/>Please note that the Portfolio Report does not filter on a Team / Application basis and is only available in the HTML format.</div>
	
	<c:if test="${ empty organizationList }"> 
		<br>No reports can be generated because no teams are available. 
	</c:if>
	
	<c:if test="${ not empty organizationList }">
		<spring:url value="/reports/ajax" var="emptyUrl"></spring:url>	
		<form:form id="reportForm" modelAttribute="reportParameters" action="${ fn:escapeXml(emptyUrl) }">
			<table class="dataTable">
				<tbody>
					<tr>
						<td>Report</td>
						<td style="padding-none;" class="inputValue">
							<div id="rptDrowDown">
								<form:select style="margin-bottom:0px;" path="reportId">
									<option value="1">Trending Report</option>
									<option value="2">Point in Time Report</option>
									<option value="3">Vulnerability Progress By Type</option>
									<option value="4">Channel Comparison By Vulnerability Types</option>
									<option value="5">Channel Comparison Summary</option>
									<option value="6">Channel Comparison Detail</option>
									<option value="7">Monthly Progress Report</option>
									<option value="8">Portfolio Report</option>
								</form:select>
							</div>
						</td>
					</tr>
					<tr>
						<td>Team</td>
						<td style="padding-none;" class="inputValue">
							<div id="orgDropDown">
								<form:select style="margin-bottom:0px;" path="organizationId" id="orgSelect">
									<option value="-1">All</option>
									<c:forEach var="organization" items="${ organizationList }">
										<c:if test="${ organization.active }">
										<option value="${ organization.id }">
											<c:out value="${ organization.name }"/>
										</option>
										</c:if>
									</c:forEach>
								</form:select>
							</div>
						</td>
					</tr>
					<tr>
						<td>Application</td>
						<td style="padding-none;" class="inputValue">
							<div id="appDropDown">
								<form:select style="margin-bottom:0px;" path="applicationId" id="appSelect">
									<option value="-1">All</option>
								</form:select>
								<form:errors path="applicationId"/>
							</div>
						</td>
					</tr>
					<tr>
						<td>Format</td>
						<td style="padding-none;" class="inputValue">
							<div id="formatDropDown">
								<form:select style="margin-bottom:0px;" path="formatId">
									<option value="1">HTML</option>
									<option value="2">CSV</option>
									<option value="3">PDF</option>
								</form:select>
								<form:errors path="formatId"/>
							</div>
						</td>
					</tr>
				</tbody>
			</table>
			<br />
			<a id="submitTeamModal" class="btn btn-primary" onclick="javascript:submitAjax('<c:out value="${ emptyUrl }"/>', '#reportForm', '#formDiv', '#successDiv');return false;">Run Report</a>
		</form:form>
	</c:if>
	
	</div>
	
	<div style="float:left" id="successDiv"></div>
</body>
