<%@ include file="/common/taglibs.jsp"%>

<div class="span6">
  <h4>Recent Uploads</h4>
  <table class="table table-bordered thick-borders">
    <thead>
    <tr>
      <th class="thick-left">Date</th>
      <th colspan="2">Application</th>
    </tr>
    </thead>
    <tbody id="wafTableBody">
    <c:if test="${ empty recentScans }">
      <tr class="bodyRow">
        <td class="thick-left" colspan="4" style="text-align:center;">No scans found.</td>
      </tr>
    </c:if>
    <c:forEach var="scan" items="${ recentScans }" varStatus="status">
      <tr class="bodyRow">
        <td class="thick-left">
          <fmt:formatDate value="${ scan.importTime.time }" type="both" pattern="MM/dd/yy"/><br>
        </td>
        <spring:url value="/organizations/{orgId}/applications/{appId}" var="appUrl">
          <spring:param name="orgId" value="${ scan.application.organization.id }"/>
          <spring:param name="appId" value="${ scan.application.id }"/>
        </spring:url>
        <td class="no-left-border" id="application${ status.count }">
          <div style="width:240px;" class="ellipsis">
            <a ng-non-bindable style="text-decoration:underline;" id="scanApplicationLink${ status.count }" href="${ fn:escapeXml(appUrl) }">
              <c:out value="${ scan.applicationChannel.application.name }"/>
            </a>
          </div>
        </td>
        <td class="no-left-border" id="channelType${ status.count }">
          <spring:url value="/organizations/{orgId}/applications/{appId}/scans/{scanId}" var="detailUrl">
            <spring:param name="orgId" value="${ scan.application.organization.id }"/>
            <spring:param name="appId" value="${ scan.application.id }"/>
            <spring:param name="scanId" value="${ scan.id }"/>
          </spring:url>
          <div style="float:right;width:70px;">
            <a id="scanLink${ status.count }" id="importTime${ status.count }" href="${ fn:escapeXml(detailUrl) }">
              View Scan
            </a>
          </div>
        </td>
      </tr>
      <tr class="no-top-border">
        <td ng-non-bindable class="thick-left" colspan="3">
          <span style="font-weight:bold;color:red;"><c:out value="${ scan.numberTotalVulnerabilities }"/></span> Vulnerabilities from
          <c:out value="${ scan.applicationChannel.channelType.name }"/> <c:if test="${ not empty scan.scannerType }">(<c:out value="${ scan.scannerType }"/>)</c:if>
        </td>
      </tr>
    </c:forEach>
    </tbody>
  </table>
</div>