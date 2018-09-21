<!-- Saved Filters section -->
<div class="saved-filters-tab" ng-show="savedFilters && savedFilters.length > 0">

    <div id="deleteFilterSuccessMessage" ng-show="deleteFilterSuccessMessage" class="alert alert-success">
        <button id="closeDeleteFilterSuccessMessage"
                class="close"
                ng-click="deleteFilterSuccessMessage = undefined"
                type="button">&times;</button>
        {{ deleteFilterSuccessMessage }}
    </div>

    <select id="filterSelect" style="width: 220px;" ng-model="selectedFilter" ng-change="loadFilter(selectedFilter)" ng-options="filter.name for filter in savedFilters">
        <option>Select a Filter</option>
    </select>

    <div ng-show="savedFilters && savedFilters.length > 0">
        <hr>

        <a id="copyFilterButton"
           class="btn"
           ng-disabled="!selectedFilter"
           ng-click="copyCurrentFilter()">
            Copy Selected Filter
        </a>

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