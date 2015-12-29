var module = angular.module('threadfix');

module.controller('VulnSearchController', function($scope, $rootScope, $window, $http, tfEncoder, $modal, $log, vulnSearchParameterService, vulnTreeTransformer, threadfixAPIService, filterService) {

    $scope.parameters = {};

    $scope.loadingTree = true;

    $scope.resetFilters = function() {
        $scope.parameters = {
            tags: [],
            vulnTags: [],
            commentTags: [],
            scanners: [],
            genericVulnerabilities: [],
            severities: {
                info: true,
                low: true,
                medium: true,
                high: true,
                critical: true
            },
            primaryPivot: "SEVERITY",
            secondaryPivot: "CWE",
            numberMerged: null,
            path: null,
            parameter: null,
            numberVulnerabilities: 10,
            showOpen: true,
            showClosed: false,
            showFalsePositive: false,
            showHidden: false,
            showDefectPresent: false,
            showDefectNotPresent: false,
            showDefectOpen: false,
            showDefectClosed: false,
            showInconsistentClosedDefectNeedsScan: false,
            showInconsistentClosedDefectOpenInScan: false,
            showInconsistentOpenDefect: false,
            showCommentPresent: false,
            daysOldModifier: null,
            daysOld: null,
            startDate: null,
            endDate: null
        };

        if ($scope.treeApplication) {
            // in application detail page, we don't need teams and applications filter attributes
        } else if ($scope.treeTeam) {
            $scope.parameters.applications = [];
        } else {
            $scope.parameters.teams = [];
            $scope.parameters.applications = [];
        }

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
                        $scope.commentTags = data.object.commentTags;
                        $scope.vulnTags = data.object.vulnTags;
                        $scope.vulnSearchPivots = data.object.vulnSearchPivots;
                        $scope.vulnSearchPivotDisplayNames = data.object.vulnSearchPivotDisplayNames;
                        $scope.tags.sort(nameCompare);
                        $scope.commentTags.sort(nameCompare);
                        $scope.vulnTags.sort(nameCompare);
                        $scope.scanners = data.object.scanners;
                        $scope.genericVulnerabilities = data.object.vulnTypes;
                        $scope.searchApplications = data.object.applications;
                        $scope.savedFilters = data.object.savedFilters;
                        $scope.savedDateRanges = data.object.savedDateRanges;
                        if (!$scope.savedDateRanges)
                            $scope.savedDateRanges = [];
                        $scope.savedDateRanges.unshift({name: ""});
                        $scope.selectedDateRange = $scope.savedDateRanges[0];
                        $scope.filterParameters = data.object.filterParameters;
                        $scope.genericSeverityList = data.object.genericSeverities;
                        $scope.versionsMap = data.object.versionsMap;
                    }
                    if ($scope.filterParameters) {

                        $scope.$parent.tab = { vulnerabilities: true};
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
            }

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
            }

            $scope.filterParameters = $scope.$parent.filterParameters;
            $scope.resetFilters();
            vulnSearchParameterService.convertFromSpringToAngular($scope, $scope.filterParameters);
            $scope.refresh();
        }

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

    $scope.$on('newMappings', function() {
        $scope.refresh();
        $scope.refreshHeading();
    });

    $scope.refreshHeading = function() {
        if ($scope.$parent.appId) {
            $http.get(tfEncoder.encode("/reports/update/heading/"+ $scope.$parent.appId)).
                success(function(data, status, headers, config, response) {
                    $rootScope.$broadcast('scans', data.object.scans);
                    $rootScope.$broadcast('numVulns',  data.object.numVulns);
                }).
                error(function(data, status, headers, config) {
                    $scope.errorMessage = "Failed to retrieve heading information. HTTP status was " + status;
                    $scope.loadingTree = false;
                });
        }
    };

    var refreshNoParamUpdate = function() {
        $scope.loading = true;
        vulnSearchParameterService.updateParameters($scope, $scope.parameters);

        $scope.$broadcast("refreshVulnSearchTree", $scope.parameters);
        $scope.lastLoadedFilterName = undefined;
    };

    $scope.$on('updateDisplayData', function(event, parameters) {
        $scope.parameters = angular.copy(parameters);
        refreshNoParamUpdate();
    });

    $scope.$on('resetParameters', function(event, parameters) {
        $scope.parameters = angular.copy(parameters);
        $scope.refresh();
    });

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    $scope.$watch('parameters.primaryPivot', function(){
        if ($scope.parameters.primaryPivot === $scope.parameters.secondaryPivot) {
            //$scope.parameters.primaryPivot = $scope.prevPrimaryPivot;
            $scope.primaryPivot_error = "Primary pivot cannot be equal to secondary pivot."
        } else {
            $scope.primaryPivot_error = "";
        }
    });

    $scope.$watch('parameters.secondaryPivot', function(){
        if ($scope.parameters.secondaryPivot === $scope.parameters.primaryPivot) {
            //$scope.parameters.secondaryPivot = $scope.prevSecondaryPivot;
            $scope.secondaryPivot_error = "Secondary pivot cannot be equal to primary pivot."
        } else {
            $scope.secondaryPivot_error = "";
        }
    });

    $scope.validatePrimaryPivot = function(primaryPivot){
        $scope.prevPrimaryPivot = $scope.parameters.primaryPivot;
    };

    $scope.validateSecondaryPivot = function(secondaryPivot){
        $scope.prevSecondaryPivot = $scope.parameters.secondaryPivot;
    };
});
