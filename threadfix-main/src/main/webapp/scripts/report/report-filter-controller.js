var module = angular.module('threadfix');

module.controller('ReportFilterController', function($scope, $rootScope, filterService) {

    $scope.parameters = undefined;

    $scope.resetFiltersIfEnabled = function() {
        if ($scope.selectedFilter) {
            $scope.reset();
        }
    };

    $scope.reset = function() {
        $scope.$parent.resetFilters();
        $scope.parameters = $scope.$parent.parameters;
        $scope.selectedFilter = $scope.$parent.savedDefaultTrendingFilter ? $scope.$parent.savedDefaultTrendingFilter : undefined;
        $rootScope.$broadcast("resetParameters", $scope.parameters)
    };

    $scope.$on('loadTrendingReport', function() {
        if (!$scope.parameters) {
            $scope.$parent.resetFilters();
            $scope.parameters = $scope.$parent.parameters;
        }
        $scope.showFullControls = true;

    });

    $scope.$on('loadComparisonReport', function() {
        if (!$scope.parameters) {
            $scope.$parent.resetFilters();
            $scope.parameters = $scope.$parent.parameters;
        }

        $scope.showFullControls = false;

    });

    $scope.$on('loadSnapshotReport', function() {

        if (!$scope.parameters) {
            $scope.$parent.resetFilters();
            $scope.parameters = $scope.$parent.parameters;
        }

        $scope.showFullControls = false;
    });

    $scope.toggleAllFilters = function() {
        if ($scope.showTeamAndApplicationControls
            || $scope.showSaveFilter
            || $scope.showDetailsControls
            || $scope.showDateControls
            || $scope.showDateRange
            || $scope.showTagControls) {
            $scope.showTeamAndApplicationControls = false;
            $scope.showDetailsControls = false;
            $scope.showDateControls = false;
            $scope.showDateRange = false;
            $scope.showSaveFilter = false;
            $scope.showTagControls = false;
        } else {
            $scope.showTeamAndApplicationControls = true;
            $scope.showDetailsControls = true;
            $scope.showDateControls = true;
            $scope.showDateRange = true;
            $scope.showSaveFilter = true;
            $scope.showTagControls = true;
        }
    };

    $scope.maxDate = new Date();

    $scope.openEndDate = function($event) {
        resetAging();
        $event.preventDefault();
        $event.stopPropagation();

        $scope.endDateOpened = true;
    };

    $scope.openStartDate = function($event) {
        resetAging();
        $event.preventDefault();
        $event.stopPropagation();

        $scope.startDateOpened = true;
    };

    var resetAging = function() {
        $scope.parameters.daysOldModifier = undefined;
    };


    $scope.refreshScans = function(){
        $rootScope.$broadcast("resetParameters", $scope.parameters);
    };

    $scope.refresh = function() {
        $rootScope.$broadcast("updateDisplayData", $scope.parameters);
    };

    $scope.$on('updateBackParameters', function(event, parameters) {
        $scope.parameters = angular.copy(parameters);
    });

    $scope.addNew = function(collection, name) {
        var found = false;

        collection.forEach(function(item) {
            if (item && item.name === name) {
                found = true;
            }
        });

        if (!found) {
            collection.push({name: name});

            $rootScope.$broadcast("resetParameters", $scope.parameters);

        }
    };

    $scope.remove = function(collection, index) {
        collection.splice(index, 1);

        $rootScope.$broadcast("resetParameters", $scope.parameters);

    };

    $scope.setDaysOld = function(days) {
        resetDateRange();
        if ($scope.parameters.daysOldModifier === days) {
            $scope.parameters.daysOldModifier = undefined;
        } else {
            $scope.parameters.daysOldModifier = days;

        }
        $rootScope.$broadcast("resetParameters", $scope.parameters);

    };

    $scope.deleteCurrentFilter = function() {
        filterService.deleteCurrentFilter($scope, filterSavedFilters);
    };

    $scope.loadFilter = function(filter) {

        $scope.selectedFilter = filter;
        $scope.parameters = JSON.parse($scope.selectedFilter.json);
        if (!filter.defaultTrending) {
            $scope.parameters.defaultTrending = false;
        }
        if ($scope.parameters.startDate)
            $scope.parameters.startDate = new Date($scope.parameters.startDate);
        if ($scope.parameters.endDate)
            $scope.parameters.endDate = new Date($scope.parameters.endDate);

        $rootScope.$broadcast("resetParameters", $scope.parameters);
        $scope.lastLoadedFilterName = $scope.selectedFilter.name;
//        $scope.currentFilterNameInput = $scope.selectedFilter.name;
    };

    $scope.saveCurrentFilters = function() {
        if ($scope.$parent.trendingActive)
            $scope.parameters.filterType = {isTrendingFilter : true};
        else if ($scope.$parent.snapshotActive)
            $scope.parameters.filterType = {isSnapshotFilter : true};
        filterService.saveCurrentFilters($scope, filterSavedFilters);

    };

    var filterSavedFilters = function(filter){
        var parameters = JSON.parse(filter.json);
        if (!parameters.filterType)
            return false;
        else {
            if ($scope.$parent.snapshotActive)
                return (parameters.filterType.isSnapshotFilter);
            else if ($scope.$parent.trendingActive)
                return (parameters.filterType.isTrendingFilter);
            else
                return false;
        }
    }

    var resetDateRange = function(){
        // Reset Date Range
        $scope.parameters.startDate = null;
        $scope.startDateOpened = false;
        $scope.parameters.endDate = null;
        $scope.endDateOpened = false;
    };

});
