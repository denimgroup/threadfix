<div id="vulnSearchFilterDiv" class="filter-controls" ng-controller="ReportFilterController">
    <h3>Filters</h3>

    <tabset ng-init="showFilterSections = true" ng-hide="remediationEnterpriseActive">
        <tab heading="Filters" ng-click="$parent.showFilterSections = true; $parent.showSavedFilters = false">
        </tab>
        <tab heading="Load Filters" ng-click="$parent.showFilterSections = false; $parent.showSavedFilters = true">
        </tab>
    </tabset>

    <div ng-show="showFilterSections">
        <%@ include file="/WEB-INF/views/vulnerabilities/filterSections.jsp" %>
    </div>

    <div ng-show="showSavedFilters && !remediationEnterpriseActive">
        <%@ include file="/WEB-INF/views/vulnerabilities/savedFilters.jsp" %>
    </div>
</div>
