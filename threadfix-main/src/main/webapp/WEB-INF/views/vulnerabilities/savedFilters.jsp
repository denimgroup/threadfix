<!-- Saved Filters section -->

<h3>Save</h3>
<div id="saveFilterSuccessMessage" ng-show="saveFilterSuccessMessage" class="alert alert-success">
    <button id="closeSaveFilterSuccessMessage" class="close" ng-click="saveFilterSuccessMessage = undefined" type="button">&times;</button>
    {{ saveFilterSuccessMessage }}
</div>
<div id="saveFilterErrorMessage" ng-show="saveFilterErrorMessage" class="alert alert-success">
    <button id="closeSaveFilterErrorMessage" class="close" ng-click="saveFilterErrorMessage = undefined" type="button">&times;</button>
    {{ saveFilterErrorMessage }}
</div>
<input id="filterNameInput" style="width: 180px;" placeholder="Enter a name for the filter" ng-model="$parent.currentFilterNameInput" type="text"/>
<a id="saveFilterButton" style="margin-bottom:10px" class="btn btn-primary" ng-hide="savingFilter" ng-disabled="!currentFilterNameInput" ng-click="saveCurrentFilters()">Save Current Filters</a>
<button id="savingFilterButton"
        ng-show="savingFilter"
        disabled="disabled"
        class="btn btn-primary">
    <span class="spinner"></span>
    Saving
</button>

<h3>Load</h3>

<div id="deleteFilterSuccessMessage" ng-show="deleteFilterSuccessMessage" class="alert alert-success">
    <button id="closeDeleteFilterSuccessMessage" class="close" ng-click="deleteFilterSuccessMessage = undefined" type="button">&times;</button>
    {{ deleteFilterSuccessMessage }}
</div>

<a class="btn" style="width: 168px; margin-bottom: 5px;" ng-click="loadFilter(filter)" ng-disabled="$parent.selectedFilter === filter" ng-repeat="filter in savedFilters">
    {{ filter.name }}
</a>
<a id="deleteFilterButton" ng-show="savedFilters && savedFilters.length > 0" class="btn btn-danger" ng-disabled="!selectedFilter" ng-click="deleteCurrentFilter()">Delete Selected Filter</a>
<button id="deletingFilterButton"
        ng-show="deletingFilter"
        disabled="disabled"
        class="btn btn-primary">
    <span class="spinner"></span>
    Deleting
</button>