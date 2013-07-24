<%@ include file="/common/taglibs.jsp"%>

	<div class="modal-header">
		<h4 id="myModalLabel">Application Detail

		</h4>
	</div>

	<form:form style="margin-bottom:0px;" id="viewAppForm" modelAttribute="application" autocomplete="off">
	<div class="modal-body">
		<table>
			<tr class="left-align">
				<td style="padding:5px;">Name</td> 
				<td style="padding:5px;">
					<c:out value="${ application.name }"/>
				</td>
			</tr>
			<tr class="left-align">
				<td style="padding:5px;">URL</td>
				<td style="padding:5px;">
					<c:out value="${ application.url }"/>
			  	</td>
			</tr>
			<tr class="left-align">
				<td style="padding:5px;">Unique ID</td>
				<td style="padding:5px;">
					<c:out value="${ application.uniqueId }"/>
			  	</td>
			</tr>
			<tr class="left-align">
				<td style="padding:5px;">Team</td>
				<td style="padding:5px;">
					<c:out value="${ application.organization.name }"/>
				</td>																
			</tr>
			<tr class="left-align">
				<td style="padding:5px;">Criticality</td>
				<td style="padding:5px;">
					<c:out value="${ application.applicationCriticality.name }"/>
				</td>
			</tr>
			<tr class="left-align">
				<td style="padding:5px;">Defect Tracker</td>
				<td style="padding:5px;">
					<c:out value="${ application.defectTracker.name }"/>  
					<em><a href="<spring:url value="${ fn:escapeXml(application.defectTracker.url) }" />">
						<c:out value="${ fn:escapeXml(application.defectTracker.url) }"/></a></em> 
				</td>				
			</tr>
			<tr class="left-align" id="appWafDiv">
				<td style="padding:5px;">WAF</td>
				<td style="padding:5px;">
					<spring:url value="/wafs/{wafId}" var="wafUrl">
						<spring:param name="wafId" value="${ application.waf.id }"/>
					</spring:url>
					<em><a id="wafText"
						href="${ fn:escapeXml(wafUrl) }">
						<c:out value="${ application.waf.name }"/>
					</a></em>  
					  <c:out value="${ application.waf.wafType.name }"/>
				</td>				
			</tr>			
		</table>
	</div>
	<div class="modal-footer">
		<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
		
	</div>
</form:form>
