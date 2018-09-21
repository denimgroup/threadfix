<script type="text/ng-template" id="detailApplicationModal.html">

	<div class="modal-header">
		<h4 id="myModalLabel">Application Detail

		</h4>
	</div>

	<div class="modal-body">
		<table class="left-align">
			<tr class="left-align">
				<td style="padding:5px;">Name</td> 
				<td ng-non-bindable style="padding:5px;">
					<c:out value="${ application.name }"/>
				</td>
			</tr>
			<tr class="left-align">
				<td style="padding:5px;">URL</td>
				<td ng-non-bindable style="padding:5px;">
					<c:out value="${ application.url }"/>
			  	</td>
			</tr>
			<tr class="left-align">
				<td style="padding:5px;">Unique ID</td>
				<td ng-non-bindable style="padding:5px;">
					<c:out value="${ application.uniqueId }"/>
			  	</td>
			</tr>
			<tr class="left-align">
				<td style="padding:5px;">Team</td>
				<td ng-non-bindable style="padding:5px;">
					<c:out value="${ application.organization.name }"/>
				</td>																
			</tr>
			<tr class="left-align">
				<td style="padding:5px;">Criticality</td>
				<td ng-non-bindable style="padding:5px;">
					<c:out value="${ application.applicationCriticality.name }"/>
				</td>
			</tr>

            <tr>
                <td style="padding:5px;">Application Type</td>
                <td ng-non-bindable style="padding:5px;">
                    <c:out value="${ application.frameworkType }"/>
                </td>
            </tr>
            <tr>
                <td style="padding:5px;">Source Code URL</td>
                <td ng-non-bindable style="padding:5px;">
                    <c:out value="${ application.repositoryUrl }"/>
                </td>
            </tr>
            <tr>
                <td style="padding:5px;">Source Code Revision</td>
                <td ng-non-bindable style="padding:5px;">
                    <c:out value="${ application.repositoryBranch }"/>
                </td>
            </tr>
            <tr>
                <td style="padding:5px;">Source Code Folder</td>
                <td ng-non-bindable style="padding:5px;">
                    <c:out value="${ application.repositoryFolder }"/>
                </td>
            </tr>

			<tr class="left-align">
				<td style="padding:5px;">Defect Tracker</td>
				<td ng-non-bindable style="padding:5px;">
					<c:out value="${ application.defectTracker.name }"/>  
					<em><a href="<spring:url value="${ fn:escapeXml(application.defectTracker.url) }" />">
						<c:out value="${ fn:escapeXml(application.defectTracker.url) }"/></a></em> 
				</td>				
			</tr>
			<tr class="left-align" id="appWafDiv">
				<td style="padding:5px;">WAF</td>
				<td ng-non-bindable style="padding:5px;">
					<spring:url value="/wafs/{wafId}" var="wafUrl">
						<spring:param name="wafId" value="${ application.waf.id }"/>
					</spring:url>
					<security:authorize ifAllGranted="ROLE_CAN_MANAGE_WAFS">
						<em><a id="wafText"
							href="${ fn:escapeXml(wafUrl) }">
							<c:out value="${ application.waf.name }"/>
						</a></em>
					</security:authorize>
					<security:authorize ifNotGranted="ROLE_CAN_MANAGE_WAFS">
						<em>
							<c:out value="${ application.waf.name }"/>
						</em>
					</security:authorize>
					<c:out value="${ application.waf.wafType.name }"/>
				</td>				
			</tr>
            <tr>
                <td style="padding:5px;">
                    Disable Vulnerability Merging
                </td>
                <td ng-non-bindable style="padding:5px;">
                    <c:out value="${ application.skipApplicationMerge }"/>
                </td>
            </tr>
		</table>
	</div>
	<div class="modal-footer">
		<button class="btn" data-dismiss="modal" aria-hidden="true" ng-click="cancel()">Close</button>
		
	</div>
</script>