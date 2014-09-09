<div ng-init="csrfToken = '<c:out value="${ emptyUrl }"/>'">
    <c:if test="${ canGenerateReports }">
        <div class="row-fluid">
            <div class="span6">
                <h4>10 Most Occurring Vulnerabilities<span style="font-size:12px;float:right;">
                    <a id="rightViewMore" ng-href="{{ urlRoot }}/reports/10{{ seeMoreExtension }}{{ csrfToken }}">View More</a></span>
                </h4>
                <div id="rightTileReport">
                    <div ng-show="rightReport" tf-bind-html-unsafe="rightReport" class="tableReportDiv report-image"></div>
                    <div ng-hide="empty || rightReport || rightReportFailed" class="team-report-wrapper report-image">
                        <div style="float:right;padding-top:120px" class="modal-loading"><div><span class="spinner dark"></span>Loading...</div></div>
                    </div>
                    <div ng-show="rightReportFailed" class="team-report-wrapper report-image">
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
