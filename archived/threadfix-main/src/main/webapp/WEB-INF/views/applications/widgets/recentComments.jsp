<%@ include file="/common/taglibs.jsp"%>

<div class="span6">
  <h4>Recent Comments</h4>
  <table class="table table-bordered thick-borders">
    <thead>
    <tr>
      <th class="thick-left">Application</th>
      <th colspan="2">Vulnerability</th>
    <tr>
    </thead>
    <tbody>
    <c:if test="${ empty recentComments }">
      <tr>
        <td style="text-align:center" class="thick-left" colspan="3">No comments found.</td>
      </tr>
    </c:if>
    <c:forEach var="comment" items="${ recentComments }" varStatus="status">
      <c:if test="${ not comment.vulnerability.hidden and
                                                        comment.vulnerability.active and
                                                        comment.vulnerability.application.active }">
        <tr class="bodyRow">
          <td class="thick-left" id="commentUser${ status.count }">
            <spring:url value="/organizations/{orgId}/applications/{appId}" var="appUrl">
              <spring:param name="orgId" value="${ comment.vulnerability.application.organization.id }"/>
              <spring:param name="appId" value="${ comment.vulnerability.application.id }"/>
            </spring:url>
            <div style="width:142px;" class="ellipsis">
              <a ng-non-bindable style="text-decoration:underline;" href="<c:out value="${ appUrl }"/>">
                <c:out value="${ comment.vulnerability.application.name }" />
              </a>
            </div>
          </td>
          <td class="no-left-border" id="commentVulnId${ status.count }">
            <div ng-non-bindable style="width:197px;" class="ellipsis">
              <c:out value="${ comment.vulnerability.genericVulnerability.name }" />
            </div>
          </td>
          <td class="no-left-border" id="viewMoreLink${ status.count }">
            <spring:url value="/organizations/{orgId}/applications/{appId}/vulnerabilities/{vulnId}" var="vulnUrl">
              <spring:param name="orgId" value="${ comment.vulnerability.application.organization.id }" />
              <spring:param name="appId" value="${ comment.vulnerability.application.id }" />
              <spring:param name="vulnId" value="${ comment.vulnerability.id }" />
            </spring:url>
            <div style="float:right;width:35px;">
              <a href="${ fn:escapeXml(vulnUrl) }#commentDiv${ comment.vulnerability.id }">
                View
              </a>
            </div>
          </td>
        </tr>
        <tr class="no-top-border">
          <td class="thick-left" colspan="3" id="commentText${ status.count }">
            <div ng-non-bindable class="vuln-comment-word-wrap ellipsis">
              <c:out value="${ comment.comment }" />
            </div>
          </td>
        </tr>
      </c:if>
    </c:forEach>
    </tbody>
  </table>
</div>