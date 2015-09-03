<%@ include file="/common/taglibs.jsp"%>

<div class="span6" ng-controller="RightReportController" ng-init="csrfToken = '${ csrfToken }'">
  <c:if test="${ canGenerateReports }">

    <h4>{{ rightReportTitle }}

      <security:authorize ifAnyGranted="CAN_GENERATE_REPORTS">
      <span style="font-size:12px;float:right;">
        <a id="rightViewMore" ng-href="{{ urlRoot }}/reports/10{{ seeMoreExtension }}{{ csrfToken }}">View More</a>
      </span>
      </security:authorize>
    </h4>


    <div id="rightTileReport">
      <div ng-show="topAppsData" class="team-report-wrapper report-image">
        <d3-hbars data="topAppsData" label = "label" width="422" height="250" margin="rightMargin"></d3-hbars>
      </div>
      <div ng-hide="empty || topAppsData || rightReportFailed" class="team-report-wrapper report-image">
        <div style="float:right;padding-top:120px" class="modal-loading"><div><span class="spinner dark"></span>Loading...</div></div>
      </div>
      <div ng-show="rightReportFailed" class="team-report-wrapper report-image">
        <div class="text">
          Report Failed
        </div>
      </div>
      <div ng-show="empty && !topAppsData" class="team-report-wrapper report-image">
        <div class="text">
          No Data Found
        </div>
      </div>
    </div>
  </c:if>
</div>