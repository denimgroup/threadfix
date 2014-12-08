var module = angular.module('threadfix');

module.controller('VulnSearchController', function($scope, $rootScope, $window, $http, tfEncoder, $modal, $log, vulnSearchParameterService, vulnTreeTransformer, threadfixAPIService, filterService) {

    $scope.parameters = {};

    $scope.loadingTree = true;

    $scope.resetFilters = function() {
        $scope.parameters = {
            teams: [],
            applications: [],
            tags: [],
            scanners: [],
            genericVulnerabilities: [],
            severities: {},
            numberVulnerabilities: 10,
            showOpen: true,
            showClosed: false,
            showFalsePositive: false,
            showHidden: false,
            showDefectPresent: false,
            showDefectNotPresent: false,
            showDefectOpen: false,
            showDefectClosed: false
        };

        $scope.endDate = undefined;
        $scope.selectedFilter = undefined;
        $scope.startDate = undefined;
    };

    $scope.$watch(function() { return $scope.parameters; }, $scope.refresh, true);

    $scope.maxDate = new Date();

    $scope.$on('application', function($event, application) {
        $scope.treeApplication = application;
        $scope.parameters.applications = [ application ];
    });

    $scope.$on('team', function($event, team) {
        $scope.treeTeam = team;
        $scope.parameters.teams = [ team ];
    });

    $scope.$on('loadVulnerabilitySearchTable', function(event) {
        if (!$scope.$parent.filterParameters) {
            threadfixAPIService.getVulnSearchParameters()
                .success(function(data, status, headers, config) {
                    if (data.success) {
                        $scope.teams = data.object.teams;
                        $scope.tags = data.object.tags;
                        $scope.scanners = data.object.scanners;
                        $scope.genericVulnerabilities = data.object.vulnTypes;
                        $scope.searchApplications = data.object.applications;
                        $scope.savedFilters = data.object.savedFilters;
                        $scope.savedFilters = $scope.savedFilters.filter(function(filter){
                            var parameters = JSON.parse(filter.json);
                            return (!parameters.filterType || parameters.filterType.isVulnSearchFilter);
                        });
                        $scope.filterParameters = data.object.filterParameters;
                    }
                    if ($scope.filterParameters) {

                        $scope.$parent.showVulnTab = true;
                        $scope.$parent.showAppsTab = false;
                        $scope.resetFilters();

                        vulnSearchParameterService.convertFromSpringToAngular($scope, $scope.filterParameters);
                        $scope.refresh();

                    } else {
                        $scope.resetFilters();
                        $scope.refresh();
                    }
                }).
                error(function(data, status, headers, config) {
                    $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
                    $scope.loadingTree = false;
                });
        } else {

            // If it was navigated from other page then display vuln search tab
            $scope.$parent.showVulnTab = true;
            if ($scope.$parent.tabs) {
                $scope.$parent.tabs.forEach(function(tab){
                    tab.active = false;
                });
            };

            // Remove the element team of All in vuln search page
            if ($scope.$parent.teams) {
                var index = -1;
                $scope.$parent.teams.forEach(function(team, i) {
                    if (team.id == -1 && team.name == "All") {
                        index = i;
                    }
                });
                if (index > -1) {
                    $scope.$parent.teams.splice(index, 1);
                }
            };

            $scope.filterParameters = $scope.$parent.filterParameters;
            $scope.resetFilters();
            vulnSearchParameterService.convertFromSpringToAngular($scope, $scope.filterParameters);
            $scope.refresh();
        };

    });

    $scope.refresh = function() {
        $scope.loading = true;
        vulnSearchParameterService.updateParameters($scope, $scope.parameters);

        $scope.$broadcast("updateBackParameters", $scope.parameters);
        $scope.$broadcast("refreshVulnSearchTree", $scope.parameters);
        $scope.lastLoadedFilterName = undefined;
    };

    $scope.add = function(collection) {
        collection.push({ name: '' })
    };

    $scope.$on('scanUploaded', function() {
        $scope.refresh();
        $scope.refreshHeading();
    });

    $scope.$on('scanDeleted', function() {
        $scope.refresh();
        $scope.refreshHeading();
    });

    $scope.refreshHeading = function() {
        $http.get(tfEncoder.encode("/reports/update/heading/"+ $scope.$parent.appId)).
            success(function(data, status, headers, config, response) {
                $rootScope.$broadcast('scans', data.object.scans);
                $rootScope.$broadcast('numVulns',  data.object.numVulns);
            }).
            error(function(data, status, headers, config) {
                $scope.errorMessage = "Failed to retrieve heading information. HTTP status was " + status;
                $scope.loadingTree = false;
            });
    };

    $scope.$on('updateDisplayData', function(event, parameters) {
        $scope.parameters = angular.copy(parameters);
        $scope.refresh();
    });

    $scope.$on('resetParameters', function(event, parameters) {
        $scope.parameters = angular.copy(parameters);
        $scope.refresh();
    });

});
