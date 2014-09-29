var module = angular.module('threadfix');

module.controller('SnapshotReportController', function($scope, $rootScope, $window, $http, tfEncoder, vulnSearchParameterService, vulnTreeTransformer) {

    $scope.parameters = {};
    $scope.noData = false;
    $scope.hideTitle = true;

    $scope.resetFilters = function() {
        $scope.parameters = {
            teams: [],
            applications: [],
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
            showDefectClosed: false,
            endDate: undefined,
            startDate: undefined
        };

    };


    $scope.$on('loadSnapshotReport', function() {

        $scope.noData = false;

        if (!$scope.allVulns) {
            $scope.loading = true;
            $http.post(tfEncoder.encode("/reports/snapshot"), $scope.getReportParameters()).
                success(function(data) {

                    $scope.loading = false;

                    $scope.resetFilters();
                    $scope.allVulns = data.object.vulnList;

                    if ($scope.allVulns) {
                       refresh();

                    } else {
                        $scope.noData = true;
                    };
                })
                .error(function() {
                    $scope.loading = false;
                });
        } else {

        }
    });

    $scope.$on('resetParameters', function(event, parameters) {
        if (!$scope.$parent.snapshotActive)
            return;
        $scope.parameters = angular.copy(parameters);
        refresh();

    });

    $scope.updateTree = function (severity) {
        $scope.hideTitle = false;
        $scope.parameters.severities = {
            info: severity === "Info",
            low: severity === "Low",
            medium: severity === "Medium",
            high: severity === "High",
            critical: severity === "Critical"
        };
        vulnSearchParameterService.updateParameters($scope, $scope.parameters);

        refreshVulnTree($scope.parameters);

    }

    var refreshVulnTree = function(parameters) {
        $scope.loadingTree = true;

        $http.post(tfEncoder.encode("/reports/tree"), parameters).
            success(function(data, status, headers, config) {
                if (data.success) {
                    $scope.vulnTree = vulnTreeTransformer.transform(data.object);

                    $scope.badgeWidth = 0;

                    if ($scope.vulnTree) {
                        $scope.vulnTree.forEach(function(treeElement) {
                            var size = 7;
                            var test = treeElement.total;
                            while (test >= 10) {
                                size = size + 7;
                                test = test / 10;
                            }

                            //expand each severity level of vulns on page load
                            treeElement.expanded = true;

                            if (size > $scope.badgeWidth) {
                                $scope.badgeWidth = size;
                            }
                        });
                    }

                    $scope.checkIfVulnTreeExpanded();

                    $scope.badgeWidth = { "text-align": "right", width: $scope.badgeWidth + 'px' };
                } else if (data.message) {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.loadingTree = false;
            }).
            error(function(data, status, headers, config) {
                console.log("Got " + status + " back.");
                $scope.errorMessage = "Failed to retrieve vulnerability tree. HTTP status was " + status;
                $scope.loadingTree = false;
            });
    };

    $scope.toggleVulnCategory = function(treeElement, expanded) {
        treeElement.expanded = expanded;
        $scope.checkIfVulnTreeExpanded();
    };

    $scope.checkIfVulnTreeExpanded = function() {
        var expanded = false;

        $scope.vulnTree.forEach(function(treeElement) {
            if(treeElement.expanded){
                expanded = true;
            }
        });

        $scope.vulnTree.expanded = expanded;

        return expanded;
    };

    $scope.toggleVulnTree = function() {
        var expanded = false;

        if ($scope.vulnTree) {
            expanded = $scope.checkIfVulnTreeExpanded();

            $scope.vulnTree.map(function(treeElement){
                treeElement.expanded = !expanded;

                if(treeElement.entries){
                    treeElement.entries.map(function(entry){

                        if(entry.expanded && expanded){
                            entry.expanded = !expanded;
                        }
                    });
                }
            });
        }

        $scope.vulnTree.expanded = !expanded;
    };

    $scope.expandAndRetrieveTable = function(element) {
        $scope.updateElementTable(element, 10, 1);
    };

    $scope.updateElementTable = function(element, numToShow, page) {
        console.log('Updating element table');

        var parameters = angular.copy($scope.parameters);

        vulnSearchParameterService.updateParameters($scope, parameters);
        parameters.genericSeverities.push({ intValue: element.intValue });
        parameters.genericVulnerabilities = [ element.genericVulnerability ];
        parameters.page = page;
        parameters.numberVulnerabilities = numToShow;

        $scope.loadingTree = true;

        $http.post(tfEncoder.encode("/reports/search"), parameters).
            success(function(data, status, headers, config) {
                element.expanded = true;

                if (data.success) {
                    element.vulns = data.object.vulns;
                    element.vulns.forEach(updateChannelNames)
                    element.totalVulns = data.object.vulnCount;
                    element.max = Math.ceil(data.object.vulnCount/100);
                    element.numberToShow = numToShow;
                    element.page = page;
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.loadingTree = false;
            }).
            error(function(data, status, headers, config) {
                $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
                $scope.loadingTree = false;
            });
    };

    // collapse duplicates: [arachni, arachni, appscan] => [arachni (2), appscan]
    var updateChannelNames = function(vulnerability) {
        if (vulnerability.channelNames.length > 1 ) {
            var holder = {};
            vulnerability.channelNames.forEach(function(name) {
                if (holder[name]) {
                    holder[name] = holder[name] + 1;
                } else {
                    holder[name] = 1;
                }
            });

            vulnerability.channelNames = [];
            for (var key in holder) {
                if (holder.hasOwnProperty(key)){
                    if (holder[key] === 1) {
                        vulnerability.channelNames.push(key)
                    } else {
                        vulnerability.channelNames.push(key + " (" + holder[key] + ")")
                    }
                }
            }
        }
    };


    var refresh = function(){
        $scope.loading = true;
        filterByTeamAndApp();
        if ($scope.filterVulns.length === 0) {
            $scope.noData = true;
        } else {
            $scope.noData = false;
        }
        updateDisplayData();
        $scope.loading = false;
    };

    var updateDisplayData = function(){
        var teams;
        var apps;
        if ($scope.parameters.teams.length === 0 && $scope.parameters.applications.length === 0) {
            teams = "All";
            apps = "All";
        }
        else {
            if ($scope.parameters.teams.length > 0) {
                teams = $scope.parameters.teams[0].name;
            }
            var i;
            for (i=1; i<$scope.parameters.teams.length; i++) {
                teams += ", " + $scope.parameters.teams[i].name;
            }

            if ($scope.parameters.applications.length > 0) {
                apps = $scope.parameters.applications[0].name;
            }
            for (i=1; i<$scope.parameters.applications.length; i++) {
                apps += ", " + $scope.parameters.applications[i].name;
            }
        }

        $scope.title = {
            teams: teams,
            apps: apps

        };
        $scope.pointInTimeData = processData();

    };

    var processData = function() {

        var data = {
            Critical: {
                Severity: 'Critical',
                Count: 0,
                Avg_Age: 0,
                Percentage: '0%'
            },
            High: {
                Severity: 'High',
                Count: 0,
                Avg_Age: 0,
                Percentage: '0%'
            },
            Medium: {
                Severity: 'Medium',
                Count: 0,
                Avg_Age: 0,
                Percentage: '0%'
            },
            Low: {
                Severity: 'Low',
                Count: 0,
                Avg_Age: 0,
                Percentage: '0%'
            },
            Info: {
                Severity: 'Info',
                Count: 0,
                Avg_Age: 0,
                Percentage: '0%'
            }
        };

        var highAgeSum = 0,
            mediumAgeSum = 0,
            criticalAgeSum = 0,
            lowAgeSum = 0,
            infoAgeSum = 0,
            totalCount;

        $scope.filterVulns.forEach(function(vuln){
            if ("High" === vuln.severity) {
                data.High.Count += 1;
                highAgeSum += getDates(vuln.importTime);
            } else if ("Medium" === vuln.severity) {
                data.Medium.Count += 1;
                mediumAgeSum += getDates(vuln.importTime);
            } else if ("Critical" === vuln.severity) {
                data.Critical.Count += 1;
                criticalAgeSum += getDates(vuln.importTime);
            } else if ("Low" === vuln.severity) {
                data.Low.Count += 1;
                lowAgeSum += getDates(vuln.importTime);
            } else if ("Info" === vuln.severity) {
                data.Info.Count += 1;
                infoAgeSum += getDates(vuln.importTime);
            }
        });
        totalCount = data.High.Count + data.Medium.Count + data.Critical.Count + data.Low.Count + data.Info.Count;

        if (totalCount !== 0) {
            data.Critical.Percentage = getPercent(data.Critical.Count/totalCount);
            data.High.Percentage = getPercent(data.High.Count/totalCount);
            data.Medium.Percentage = getPercent(data.Medium.Count/totalCount);
            data.Low.Percentage = getPercent(data.Low.Count/totalCount);
            data.Info.Percentage = getPercent(data.Info.Count/totalCount);
        }

        data.High.Avg_Age = (data.High.Count !== 0) ? Math.round(highAgeSum/data.High.Count) : 0;
        data.Critical.Avg_Age = (data.Critical.Count !== 0) ? Math.round(criticalAgeSum/data.Critical.Count) : 0;
        data.Medium.Avg_Age = (data.Medium.Count !== 0) ? Math.round(mediumAgeSum/data.Medium.Count) : 0;
        data.Low.Avg_Age = (data.Low.Count !== 0) ? Math.round(lowAgeSum/data.Low.Count) : 0;
        data.Info.Avg_Age = (data.Info.Count !== 0) ? Math.round(infoAgeSum/data.Info.Count) : 0;

        return data;
    };

    var getDates = function(importTime) {
        return Math.round(((new Date()).getTime() - importTime) / (1000 * 3600 * 24));
    };

    var getPercent = function(rate) {
        return Math.round(1000 * rate)/10 + "%";
    }

    var filterByTeamAndApp = function() {

        $scope.filterVulns = $scope.allVulns.filter(function(vuln){

            if ($scope.parameters.teams.length === 0
                && $scope.parameters.applications.length === 0)
                return true;

            var i;
            for (i=0; i<$scope.parameters.teams.length; i++) {
                if (vuln.teamName === $scope.parameters.teams[i].name) {
                    return true;
                }
            }

            for (i=0; i<$scope.parameters.applications.length; i++) {

                if (beginsWith($scope.parameters.applications[i].name, vuln.teamName + " / ") &&
                    endsWith($scope.parameters.applications[i].name, " / " + vuln.appName)) {
                    return true;
                }
            }

            return false;
        });

    };

    var endsWith = function(str, suffix) {
        return str.indexOf(suffix, str.length - suffix.length) !== -1;
    };

    var beginsWith = function(str, prefix) {
        return str.indexOf(prefix) == 0;
    };

});
