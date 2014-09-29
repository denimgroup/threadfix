var module = angular.module('threadfix');

module.controller('ReportFilterController', function($scope, $rootScope) {

    $scope.parameters = undefined;

    $scope.reset = function() {
        $scope.$parent.resetFilters();
        $scope.parameters = $scope.$parent.parameters;
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
            || $scope.showDetailsControls
            || $scope.showDateControls
            || $scope.showDateRange) {
            $scope.showTeamAndApplicationControls = false;
            $scope.showDetailsControls = false;
            $scope.showDateControls = false;
            $scope.showDateRange = false;
        } else {
            $scope.showTeamAndApplicationControls = true;
            $scope.showDetailsControls = true;
            $scope.showDateControls = true;
            $scope.showDateRange = true;
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
        $scope.parameters.daysOld = undefined;
    };


    $scope.refreshScans = function(){
        $rootScope.$broadcast("resetParameters", $scope.parameters);
    };

    $scope.refresh = function() {

        $rootScope.$broadcast("updateDisplayData", $scope.parameters);

    };


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
        if ($scope.parameters.daysOld === days) {
            $scope.parameters.daysOld = undefined;
        } else {
            $scope.parameters.daysOld = days;

        }
        $rootScope.$broadcast("resetParameters", $scope.parameters);

    };

    var resetDateRange = function(){
        // Reset Date Range
        $scope.parameters.startDate = null;
        $scope.startDateOpened = false;
        $scope.parameters.endDate = null;
        $scope.endDateOpened = false;
    };

});
