var module = angular.module('threadfix');

module.controller('SnapshotReportController', function($scope, $rootScope, $window, $http, tfEncoder, vulnSearchParameterService, vulnTreeTransformer, reportUtilities) {

    $scope.parameters = {};
    $scope.noData = false;
    $scope.hideTitle = true;
    $scope.margin = {top: 70, right: 100, bottom: 70, left: 70};

    $scope.snapshotOptions = [
        { name: "Point in Time", id: 2 },
        { name: "Progress By Vulnerability", id: 3 },
//        { name: "Portfolio Report", id: 8 },
        { name: "Most Vulnerable Applications", id: 10 }
    ];

    $scope.resetFilters = function() {
        $scope.parameters = {
            teams: [],
            applications: [],
            scanners: [],
            genericVulnerabilities: [],
            severities: {
                info: true,
                low: true,
                medium: true,
                high: true,
                critical: true
            },
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

        $scope.savedFilters = $scope.$parent.savedFilters.filter(function(filter){
            var parameters = JSON.parse(filter.json);
            return (parameters.filterType && parameters.filterType.isSnapshotFilter);
        });

        if (!$scope.allVulns) {
            $scope.loading = true;
            $scope.reportId = ($scope.$parent.reportId) ? $scope.$parent.reportId : 2;
            $http.post(tfEncoder.encode("/reports/snapshot"), $scope.getReportParameters()).
                success(function(data) {
                    $scope.loading = false;
                    $scope.resetFilters();
                    $scope.allVulns = data.object.vulnList;
                    $scope.allApps = data.object.appList;

                    $scope.tags = data.object.tags;

                    if ($scope.$parent.teamId !== -1 && $scope.$parent.applicationId === -1) {
                        $scope.parameters.teams = [$scope.$parent.team];
                        $scope.parameters.applications = [];
                        $scope.$broadcast("updateBackParameters", $scope.parameters);
                    }
                    if ($scope.$parent.applicationId !== -1) {
                        var app = angular.copy($scope.$parent.application);
                        app.name = $scope.$parent.team.name + " / " + app.name;
                        $scope.parameters.applications = [app];
                        $scope.parameters.teams = [];
                        $scope.$broadcast("updateBackParameters", $scope.parameters);
                    }

                    if ($scope.allVulns) {
                        // Point In Time is default report for Snapshot
                        $scope.allPointInTimeVulns = $scope.allVulns.filter(function(vuln){
                            return vuln.active;
                        });
                        refresh();
                    } else {
                        $scope.noData = true;
                    };
                })
                .error(function() {
                    $scope.loading = false;
                });
        }

        $scope.$parent.snapshotActive = true;

    });

    $scope.$on('resetParameters', function(event, parameters) {
        if (!$scope.$parent.snapshotActive)
            return;
        $scope.parameters = angular.copy(parameters);
        refresh();
    });

    $scope.$on('updateDisplayData', function(event, parameters) {
        if (!$scope.$parent.snapshotActive)
            return;
        $scope.parameters = angular.copy(parameters);
        if ($scope.reportId === 2) {
            filterPointInTimeDisplayBySeverity();
            updateTree();
        } else if ($scope.reportId === 3) {
            filterByTeamAndApp($scope.allCWEvulns);
            filterByTypeDataBySeverity($scope.filterVulns);
            processByTypeData($scope.filterVulns);
        }
    });
    $scope.updateTree = function (severity) {
        var _parameters = angular.copy($scope.parameters);
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

        $scope.parameters = _parameters;

    }

    var updateTree = function () {
        var _parameters = angular.copy($scope.parameters);
        $scope.hideTitle = false;
        vulnSearchParameterService.updateParameters($scope, $scope.parameters);

        if (!$scope.title)
            $scope.title = {};
        $scope.title.teamsList = $scope.parameters.teams;
        $scope.title.appsList = $scope.parameters.applications;

        refreshVulnTree($scope.parameters);
        $scope.parameters = _parameters;
    }

    $scope.loadReport = function() {
        $scope.reportId = parseInt($scope.reportId);
        if ($scope.reportId === 3) {
            if (!$scope.allCWEvulns) {
                $scope.allCWEvulns = $scope.allVulns.filter(function (vuln) {
                    if (!vuln.genericVulnName || vuln.isFalsePositive || vuln.hidden)
                        return false;
                    else
                        return true;
                });

                if (!$scope.allCWEvulns) {
                    $scope.noData = true;
                } else {
                    filterByTeamAndApp($scope.allCWEvulns);
                    filterByTypeDataBySeverity($scope.filterVulns);
                    processByTypeData($scope.filterVulns);
                }
            } else {
                filterByTeamAndApp($scope.allCWEvulns);
                filterByTypeDataBySeverity($scope.filterVulns);
                processByTypeData($scope.filterVulns);
            }
        } else if ($scope.reportId === 2) {

            if (!$scope.allPointInTimeVulns) {
                $scope.noData = true;
            } else {
                filterByTeamAndApp($scope.allPointInTimeVulns);
                updateTree();
                processPointInTimeData();
                filterPointInTimeDisplayBySeverity();
            }
        } else if ($scope.reportId === 10) {
            filterApps();
        }
    }

    var processByTypeData = function(allCWEvulns) {
        $scope.progressByTypeData = [];
        var statsMap = {};
        var now = (new Date()).getTime();

        allCWEvulns.forEach(function(vuln){
            var key = vuln.genericVulnName;
            if (!statsMap[key]) {
                statsMap[key] = {
                    numOpen : 0,
                    numClosed : 0,
                    totalAgeOpen : 0,
                    totalTimeToClose : 0
                }
            }

            if (vuln.active) {
                statsMap[key]["numOpen"] = statsMap[key]["numOpen"] + 1;
                statsMap[key]["totalAgeOpen"] = statsMap[key]["totalAgeOpen"] + getDates(now, vuln.importTime);
            } else {
                statsMap[key]["numClosed"] = statsMap[key]["numClosed"] + 1;
                statsMap[key]["totalTimeToClose"] = statsMap[key]["totalTimeToClose"] + getDates(vuln.closeTime, vuln.importTime);
            }
        });

//        var keys = getKeys(statsMap);
        var keys = Object.keys(statsMap);
        keys.forEach(function(key){
            var mapEntry = statsMap[key];
            var genericVulnEntry = {
                total : mapEntry["numOpen"] + mapEntry["numClosed"],
                description : key
            };

            genericVulnEntry.percentClosed = (genericVulnEntry.total === 0) ? 100 : getPercentNumber(mapEntry["numClosed"]/genericVulnEntry.total);
            genericVulnEntry.averageAgeOpen = (mapEntry["numOpen"] === 0) ? 0 : Math.round(mapEntry["totalAgeOpen"]/mapEntry["numOpen"]);
            genericVulnEntry.averageTimeToClose = (mapEntry["numClosed"] === 0) ? 0 : Math.round(mapEntry["totalTimeToClose"]/mapEntry["numClosed"]);

            $scope.progressByTypeData.push(genericVulnEntry);
        })

        // Sorting by Total is default
        $scope.$parent.setSortNumber($scope.progressByTypeData, "total");
    };

    var filterByTypeDataBySeverity = function(allVulns) {
        $scope.filterVulns = allVulns.filter(function(vuln){
            if ("Critical" === vuln.severity) {
                return $scope.parameters.severities.critical;
            } else if ("High" === vuln.severity) {
                return $scope.parameters.severities.high;
            } else if ("Medium" === vuln.severity) {
                return $scope.parameters.severities.medium;
            } else if ("Low" === vuln.severity) {
                return $scope.parameters.severities.low;
            } else if ("Info" === vuln.severity) {
                return $scope.parameters.severities.info;
            }
            return false;
        });
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
                    element.vulns.forEach(updateChannelNames);
                    element.vulns.forEach(function(vuln){
                        vulnSearchParameterService.updateVulnCommentTags($scope.tags, vuln);
                    });
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
//        $scope.loading = true;
        if ($scope.reportId === 2) {
            filterByTeamAndApp($scope.allPointInTimeVulns);
            updateTree();
        } else if ($scope.reportId === 3) {
            filterByTeamAndApp($scope.allCWEvulns);
        } else if ($scope.reportId === 10) {
            filterApps();
            reportUtilities.createTeamAppNames($scope);
        }

        if ($scope.filterVulns.length === 0) {
            $scope.noData = true;
        } else {
            $scope.noData = false;
        }
        updateDisplayData();
//        $scope.loading = false;
    };

    var updateDisplayData = function(){
        reportUtilities.createTeamAppNames($scope);
        if ($scope.reportId === 2) {
            processPointInTimeData();
            filterPointInTimeDisplayBySeverity();
        } else if ($scope.reportId === 3) {
            filterByTypeDataBySeverity($scope.filterVulns);
            processByTypeData($scope.filterVulns);
        }
    };

    var processPointInTimeData = function() {
        $scope.data = {
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

        var now = (new Date()).getTime();

        $scope.filterVulns.forEach(function(vuln){
            if ("High" === vuln.severity) {
                $scope.data.High.Count += 1;
                highAgeSum += getDates(now, vuln.importTime);
            } else if ("Medium" === vuln.severity) {
                $scope.data.Medium.Count += 1;
                mediumAgeSum += getDates(now, vuln.importTime);
            } else if ("Critical" === vuln.severity) {
                $scope.data.Critical.Count += 1;
                criticalAgeSum += getDates(now, vuln.importTime);
            } else if ("Low" === vuln.severity) {
                $scope.data.Low.Count += 1;
                lowAgeSum += getDates(now, vuln.importTime);
            } else if ("Info" === vuln.severity) {
                $scope.data.Info.Count += 1;
                infoAgeSum += getDates(now, vuln.importTime);
            }
        });

        totalCount = $scope.data.High.Count + $scope.data.Medium.Count + $scope.data.Critical.Count + $scope.data.Low.Count + $scope.data.Info.Count;

        if (totalCount !== 0) {
            $scope.data.Critical.Percentage = getPercent($scope.data.Critical.Count/totalCount);
            $scope.data.High.Percentage = getPercent($scope.data.High.Count/totalCount);
            $scope.data.Medium.Percentage = getPercent($scope.data.Medium.Count/totalCount);
            $scope.data.Low.Percentage = getPercent($scope.data.Low.Count/totalCount);
            $scope.data.Info.Percentage = getPercent($scope.data.Info.Count/totalCount);
        }

        $scope.data.High.Avg_Age = ($scope.data.High.Count !== 0) ? Math.round(highAgeSum/$scope.data.High.Count) : 0;
        $scope.data.Critical.Avg_Age = ($scope.data.Critical.Count !== 0) ? Math.round(criticalAgeSum/$scope.data.Critical.Count) : 0;
        $scope.data.Medium.Avg_Age = ($scope.data.Medium.Count !== 0) ? Math.round(mediumAgeSum/$scope.data.Medium.Count) : 0;
        $scope.data.Low.Avg_Age = ($scope.data.Low.Count !== 0) ? Math.round(lowAgeSum/$scope.data.Low.Count) : 0;
        $scope.data.Info.Avg_Age = ($scope.data.Info.Count !== 0) ? Math.round(infoAgeSum/$scope.data.Info.Count) : 0;

    };

    var filterPointInTimeDisplayBySeverity = function() {
        var criticalCount = $scope.parameters.severities.critical ? $scope.data.Critical.Count : 0;
        var highCount = $scope.parameters.severities.high ? $scope.data.High.Count : 0;
        var mediumCount = $scope.parameters.severities.medium ? $scope.data.Medium.Count : 0;
        var lowCount = $scope.parameters.severities.low ? $scope.data.Low.Count : 0;
        var infoCount = $scope.parameters.severities.info ? $scope.data.Info.Count : 0;

        var totalCount = criticalCount + highCount + mediumCount + lowCount + infoCount;

        if (totalCount !== 0) {
            $scope.data.Critical.Percentage = getPercent($scope.data.Critical.Count/totalCount);
            $scope.data.High.Percentage = getPercent($scope.data.High.Count/totalCount);
            $scope.data.Medium.Percentage = getPercent($scope.data.Medium.Count/totalCount);
            $scope.data.Low.Percentage = getPercent($scope.data.Low.Count/totalCount);
            $scope.data.Info.Percentage = getPercent($scope.data.Info.Count/totalCount);
        }

        $scope.pointInTimeData = {};
        if ($scope.parameters.severities.critical)
            $scope.pointInTimeData.Critical = $scope.data.Critical;
        if ($scope.parameters.severities.high)
            $scope.pointInTimeData.High = $scope.data.High;
        if ($scope.parameters.severities.medium)
            $scope.pointInTimeData.Medium = $scope.data.Medium;
        if ($scope.parameters.severities.low)
            $scope.pointInTimeData.Low = $scope.data.Low;
        if ($scope.parameters.severities.info)
            $scope.pointInTimeData.Info = $scope.data.Info;

    }

    var getDates = function(firstTime, secondTime) {
        return Math.round((firstTime - secondTime) / (1000 * 3600 * 24));
    };

    var getPercent = function(rate) {
        return getPercentNumber(rate) + "%";
    }

    var getPercentNumber = function(rate) {
        return Math.round(1000 * rate)/10;
    }

    var filterByTeamAndApp = function(vulnList) {
        $scope.filterVulns = vulnList.filter(function(vuln){

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

    var filterApps = function() {

        $scope.topAppsData = $scope.allApps.filter(function(app){
            if ($scope.parameters.teams.length === 0
                && $scope.parameters.applications.length === 0)
                return true;

            var i;
            for (i=0; i<$scope.parameters.teams.length; i++) {
                if (app.teamName === $scope.parameters.teams[i].name) {
                    return true;
                }
            }

            for (i=0; i<$scope.parameters.applications.length; i++) {
                if (beginsWith($scope.parameters.applications[i].name, app.teamName + " / ") &&
                    endsWith($scope.parameters.applications[i].name, " / " + app.appName)) {
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

    var getKeys = function(object) {
        var prototypeOfObject = Object.prototype;
        var owns = Function.prototype.call.bind(prototypeOfObject.hasOwnProperty);
        var hasDontEnumBug = !({ toString: null }).propertyIsEnumerable('toString'),
            dontEnums = [
                "toString",
                "toLocaleString",
                "valueOf",
                "hasOwnProperty",
                "isPrototypeOf",
                "propertyIsEnumerable",
                "constructor"
            ],
            dontEnumsLength = dontEnums.length;

        if (
            (typeof object != "object" && typeof object != "function") ||
            object === null
            ) {
            throw new TypeError("Object.keys called on a non-object");
        }

        var keys = [];
        for (var name in object) {
            if (owns(object, name)) {
                keys.push(name);
            }
        }

        if (hasDontEnumBug) {
            for (var i = 0, ii = dontEnumsLength; i < ii; i++) {
                var dontEnum = dontEnums[i];
                if (owns(object, dontEnum)) {
                    keys.push(dontEnum);
                }
            }
        }
        return keys;
    }

});
