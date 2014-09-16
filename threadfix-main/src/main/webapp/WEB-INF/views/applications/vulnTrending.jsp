<%@ include file="/common/taglibs.jsp"%>
<div ng-init="csrfToken = '<c:out value="${ emptyUrl }"/>'">

<c:if test="${ canGenerateReports }">
    <div class="row-fluid">
        <div class="span6">
            <h4>Vulnerability Trending<span style="font-size:12px;float:right;">
                    <a id="leftViewMore" ng-href="{{ urlRoot }}/reports/9{{ seeMoreExtension }}{{ csrfToken }}">View More</a></span>
            </h4>
            <div id="leftTileReport">
                <div ng-show="leftReport" tf-bind-html-unsafe="leftReport" class="tableReportDiv report-image"></div>
                <div ng-hide="empty || leftReport || leftReportFailed" class="team-report-wrapper report-image">
                    <div style="float:right;padding-top:120px" class="modal-loading"><div><span class="spinner dark"></span>Loading...</div></div>
                </div>
                <div ng-show="leftReportFailed" class="team-report-wrapper report-image">
                    <div class="text">
                        Report Failed
                    </div>
                </div>
                <div ng-show="empty" class="team-report-wrapper report-image">
                    <div class="text">
                        No Data Found
                    </div>
                </div>
            </div>
        </div>
    </div>
</c:if>
</div>
