<!-- Saved Filters section -->

<div class="saved-filters-tab">
    <h3>Save</h3>
    <div id="saveFilterSuccessMessage" ng-show="saveFilterSuccessMessage" class="alert alert-success">
        <button id="closeSaveFilterSuccessMessage"
                class="close"
                ng-click="saveFilterSuccessMessage = undefined"
                type="button">&times;</button>
        {{ saveFilterSuccessMessage }}
    </div>
    <div id="saveFilterErrorMessage" ng-show="saveFilterErrorMessage" class="alert alert-success">
        <button id="closeSaveFilterErrorMessage"
                class="close"
                ng-click="saveFilterErrorMessage = undefined"
                type="button">&times;</button>
        {{ saveFilterErrorMessage }}
    </div>
    <input id="filterNameInput"
           placeholder="Enter a name for the filter"
           ng-model="$parent.currentFilterNameInput"
           type="text"/>

    <!-- Save button and save button with spinner. -->
    <a id="saveFilterButton"
       class="btn btn-primary"
       ng-hide="savingFilter"
       ng-disabled="!currentFilterNameInput"
       ng-click="saveCurrentFilters()">
        Save Current Filters
    </a>
    <button id="savingFilterButton"
            ng-show="savingFilter"
            disabled="disabled"
            class="btn btn-primary">
        <span class="spinner"></span>
        Saving
    </button>

    <h3>Load</h3>

    <div id="deleteFilterSuccessMessage" ng-show="deleteFilterSuccessMessage" class="alert alert-success">
        <button id="closeDeleteFilterSuccessMessage"
                class="close"
                ng-click="deleteFilterSuccessMessage = undefined"
                type="button">&times;</button>
        {{ deleteFilterSuccessMessage }}
    </div>

    <!-- Iterate through filters and make buttons. -->
    <a class="btn"
       ng-click="loadFilter(filter)"
       ng-disabled="$parent.selectedFilter === filter"
       ng-repeat="filter in savedFilters">
        {{ filter.name }}
    </a>

    <div ng-show="savedFilters && savedFilters.length > 0">
        <hr>

        <!-- Delete button and delete button with spinner. -->
        <a id="deleteFilterButton"
           class="btn btn-danger"
           ng-disabled="!selectedFilter"
           ng-click="deleteCurrentFilter()">
            Delete Selected Filter
        </a>
        <button id="deletingFilterButton"
                ng-show="deletingFilter"
                disabled="disabled"
                class="btn btn-primary">
            <span class="spinner"></span>
            Deleting
        </button>

        <a id="clearFiltersButtonSavedTab"
           class="btn"
           ng-disabled="!selectedFilter"
           ng-click="resetFiltersIfEnabled()">
            Clear Filter
        </a>
    </div>
</div>