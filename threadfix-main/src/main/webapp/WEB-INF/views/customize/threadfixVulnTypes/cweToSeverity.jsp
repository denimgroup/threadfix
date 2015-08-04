
<div ng-controller="VulnerabilityFiltersController">

    <div ng-show="initialized">
        <%@ include file="/WEB-INF/views/filters/form.jsp"%>

        <h2>Severity Mappings</h2>

        <div id="vulnFiltersSuccessMessage" ng-show="successMessage" class="alert alert-success">
            <button class="close" ng-click="successMessage = undefined" type="button">&times;</button>
            {{ successMessage }}
        </div>

        <a id="createNewKeyModalButton" ng-click="showNewFilterModal()" class="btn">Create New Mapping</a>

        <div id="tableDiv">
            <%@ include file="/WEB-INF/views/filters/table.jsp" %>
        </div>
    </div>
</div>