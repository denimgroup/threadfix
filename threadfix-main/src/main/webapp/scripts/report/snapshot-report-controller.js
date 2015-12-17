var module = angular.module('threadfix');

module.controller('SnapshotReportController', function($scope, $rootScope, $window, $http, tfEncoder, vulnSearchParameterService,
                                                       reportUtilities, reportExporter, customSeverityService, $log) {

    $scope.parameters = {};
    $scope.noData = false;
    $scope.hideTitle = true;
    $scope.margin = {top: 85, right: 100, bottom: 70, left: 70};
    $scope.PIT_Report_Id = 2;
    $scope.PBV_Report_Id = 3;
    $scope.MVA_Report_Id = 10;
    $scope.OWASP_Report_Id = 11;
    $scope.Portfolio_Report_Id = 12;
    $scope.DISA_STIG_Report_Id = 13;
    $scope.Scan_Comparison_Summary_Id = 14;

    $scope.snapshotOptions = [
        { name: "Point in Time", id: $scope.PIT_Report_Id },
        { name: "Progress By Vulnerability", id: $scope.PBV_Report_Id },
        { name: "Most Vulnerable Applications", id: $scope.MVA_Report_Id },
        { name: "OWASP Top 10", id: $scope.OWASP_Report_Id },
        { name: "Portfolio", id: $scope.Portfolio_Report_Id },
        { name: "DISA STIG", id: $scope.DISA_STIG_Report_Id },
        { name: "Scan Comparison Summary", id: $scope.Scan_Comparison_Summary_Id }
    ];

    $scope.graphIdMap = {
    };
    $scope.graphIdMap[$scope.PIT_Report_Id] = "pointInTimeGraph";
    $scope.graphIdMap[$scope.MVA_Report_Id] = "mostVulnAppsGraph";

    $scope.htmlElementIdMap = {
    };
    $scope.htmlElementIdMap[$scope.PIT_Report_Id] = "pointInTimeTablePdf";
    $scope.htmlElementIdMap[$scope.OWASP_Report_Id] = "pointInTimeTablePdf";
    $scope.htmlElementIdMap[$scope.PBV_Report_Id] = "progressVulnsDiv";
    $scope.htmlElementIdMap[$scope.Portfolio_Report_Id] = ["portfolioDiv", "portfolioScanStat"];
    $scope.htmlElementIdMap[$scope.DISA_STIG_Report_Id] = "pointInTimeTablePdf";
    $scope.htmlElementIdMap[$scope.Scan_Comparison_Summary_Id] = "scanComparisonDiv";

    $scope.titleMap = {};
    $scope.titleMap[$scope.PIT_Report_Id] = "Point_In_Time";
    $scope.titleMap[$scope.OWASP_Report_Id] = "OWASP_Top_10";
    $scope.titleMap[$scope.PBV_Report_Id] = "Progress_By_Vulnerability";
    $scope.titleMap[$scope.MVA_Report_Id] = "Most_Vulnerable_Applications";
    $scope.titleMap[$scope.Portfolio_Report_Id] = "Portfolio";
    $scope.titleMap[$scope.DISA_STIG_Report_Id] = "DISA STIG";
    $scope.titleMap[$scope.Scan_Comparison_Summary_Id] = "Scan_Comparison_Summary";


    $scope.OWASP_TOP10 = [
        {
            year: 2013,
            top10: [
                {
                    id: 'A1',
                    name: 'A1 - Injection',
                    members: [77, 78, 88, 89, 90, 91, 929]
                },
                {
                    id: 'A2',
                    name: "A2 - Broken Authentication and Session Management",
                    members: [256, 287, 311, 319, 384, 522, 523, 613, 620, 640, 930]
                },
                {
                    id: 'A3',
                    name: "A3 - Cross-Site Scripting (XSS)",
                    members: [79, 931]
                },
                {
                    id: 'A4',
                    name: "A4 - Insecure Direct Object References",
                    members: [22, 99, 639, 932]
                },
                {
                    id: 'A5',
                    name: "A5 - Security Misconfiguration",
                    members: [2, 16, 209, 215, 548, 933]
                },
                {
                    id: 'A6',
                    name: "A6 - Sensitive Data Exposure",
                    members: [310, 311, 312, 319, 320, 325, 326, 327, 328, 934]
                },
                {
                    id: 'A7',
                    name: "A7 - Missing Function Level Access Control",
                    members: [285, 287, 935]
                },
                {
                    id: 'A8',
                    name: "A8 - Cross-Site Request Forgery (CSRF)",
                    members: [352, 936]
                },
                {
                    id: 'A9',
                    name: "A9 - Using Components with Known Vulnerabilities",
                    members: [937]
                },
                {
                    id: 'A10',
                    name: "A10 - Unvalidated Redirects and Forwards",
                    members: [601, 938]
                }
            ]
        },
        {
            year: 2010,
            top10: [
                {
                    id: 'A1',
                    name: 'A1 - Injection',
                    members: [78, 88, 89, 90, 91, 810]
                },
                {
                    id: 'A2',
                    name: "A2 - Cross-Site Scripting (XSS)",
                    members: [79, 811]

                },
                {
                    id: 'A3',
                    name: "A3 - Broken Authentication and Session Management",
                    members: [287, 306, 307, 798, 812]
                },
                {
                    id: 'A4',
                    name: "A4 - Insecure Direct Object References",
                    members: [22, 99, 434, 639, 829, 862, 863, 813]
                },
                {
                    id: 'A5',
                    name: "A5 - Cross-Site Request Forgery(CSRF)",
                    members: [352, 814]
                },
                {
                    id: 'A6',
                    name: "A6 - Security Misconfiguration",
                    members: [209, 219, 250, 538, 552, 732, 815]
                },
                {
                    id: 'A7',
                    name: "A7 - Insecure Cryptographic Storage",
                    members: [311, 312, 326, 327, 759, 816]
                },
                {
                    id: 'A8',
                    name: "A8 - Failure to Restrict URL Access",
                    members: [285, 862, 863, 817]
                },
                {
                    id: 'A9',
                    name: "A9 - Insufficient Transport Layer Protection",
                    members: [311, 319, 818]
                },
                {
                    id: 'A10',
                    name: "A10 - Unvalidated Redirects and Forwards",
                    members: [601, 819]
                }
            ]
        },
        {
            year: 2007,
            top10: [
                {
                    id: 'A1',
                    name: 'A1 - Cross Site Scripting (XSS)',
                    members: [79, 712]
                },
                {
                    id: 'A2',
                    name: "A2 - Injection Flaws",
                    members: [77, 89, 90, 91, 93, 713]
                },
                {
                    id: 'A3',
                    name: "A3 - Malicious File Execution",
                    members: [78, 95, 98, 434, 714]
                },
                {
                    id: 'A4',
                    name: "A4 - Insecure Direct Object Reference",
                    members: [22, 472, 639, 715]
                },
                {
                    id: 'A5',
                    name: "A5 - Cross Site Request Forgery (CSRF)",
                    members: [352, 716]
                },
                {
                    id: 'A6',
                    name: "A6 - Information Leakage and Improper Error Handling",
                    members: [200, 203, 209, 215, 717]
                },
                {
                    id: 'A7',
                    name: "A7 - Broken Authentication and Session Management",
                    members: [287, 301, 522, 718]
                },
                {
                    id: 'A8',
                    name: "A8 - Insecure Cryptographic Storage",
                    members: [311, 321, 325, 326, 719]
                },
                {
                    id: 'A9',
                    name: "A9 - Insecure Communications",
                    members: [311, 321, 325, 326, 720]
                },
                {
                    id: 'A10',
                    name: "A10 - Failure to Restrict URL Access",
                    members: [285, 288, 425, 721]
                }
            ]
        }];

    $scope.DISA_STIG = [
        {
            id: "CATI",
            name: "CAT I",
            members: [
                {
                    stigId: "APP3130",
                    cweIds:[636]
                },
                {
                    stigId: "APP3310",
                    cweIds:[256,257]
                },
                {
                    stigId: "APP3350",
                    cweIds: [13,259]
                },
                {
                    stigId: "APP3510",
                    cweIds: [20]
                },
                {
                    stigId: "APP3540",
                    cweIds: [89,564]
                },
                {
                    stigId: "APP3550",
                    cweIds: [190,191,192,738,872]
                },
                {
                    stigId: "APP3560",
                    cweIds: [134]
                },
                {
                    stigId: "APP3570",
                    cweIds: [77,78,990]
                },
                {
                    stigId: "APP3580",
                    cweIds: [80,85,87,712,725,811,931]
                },
                {
                    stigId: "APP3590",
                    cweIds: [120,121,122,680]
                },
                {
                    stigId: "APP3810",
                    cweIds: [91]
                }
            ]
        },
        {
            id: "CATII",
            name: "CAT II",
            members: [
                {
                    stigId: "APP3050",
                    cweIds: [561]
                },
                {
                    stigId: "APP3060",
                    cweIds: [493]
                },
                {
                    stigId: "APP3100",
                    cweIds: [376]
                },
                {
                    stigId: "APP3110",
                    cweIds: [489]
                },
                {
                    stigId: "APP3140",
                    cweIds: [455]
                },
                {
                    stigId: "APP3230",
                    cweIds: [244]
                },
                {
                    stigId: "APP3585",
                    cweIds: [352,716,814,936]
                },
                {
                    stigId: "APP3600",
                    cweIds: [171,647]
                },
                {
                    stigId: "APP3620",
                    cweIds: [200]
                },
                {
                    stigId: "APP3630",
                    cweIds: [362,363,364,366,367,368,421,689,988]
                },
                {
                    stigId: "APP3800",
                    cweIds: [674]
                }
            ]
        },
        {
            id: "CATIII",
            name: "CAT III",
            members: []
        }
    ];


    $scope.resetFilters = function() {
        $scope.parameters = {
            tags: [],
            vulnTags: [],
            teams: [],
            applications: [],
            severities: {
                info: true,
                low: true,
                medium: true,
                high: true,
                critical: true
            },
            numberVulnerabilities: 10,
            showOpen: true,
            selectedOwasp: $scope.OWASP_TOP10[0]
        };
    };

    $scope.$on('loadSnapshotReport', function() {

        $scope.noData = false;

        $scope.loading = true;
        $scope.reportId = ($scope.$parent.reportId && $scope.$parent.reportId !== 9) ? $scope.$parent.reportId : $scope.PIT_Report_Id;
        $http.post(tfEncoder.encode("/reports/snapshot"), $scope.getReportParameters()).
            success(function(data) {
                $scope.loading = false;
                $scope.resetFilters();
                $scope.allPortfolioApps = data.object.appList;

                $scope.tags = data.object.tags;
                $scope.vulnTags = data.object.vulnTags;

                $scope.appTagMatrix = [];
                $scope.allPortfolioApps.forEach(function(app) {
                    var tagMatrix = $scope.appTagMatrix[app.appId];
                    if (typeof tagMatrix == "undefined") {
                        tagMatrix = [];
                        $scope.appTagMatrix[app.appId] = tagMatrix;
                    }
                    app.tags.forEach(function(tag) {
                        tagMatrix[tag.name] = true;
                    });
                });

                $scope.genericSeverities = customSeverityService.getGenericSeverities();

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
                refresh();
            })
            .error(function() {
                $scope.loading = false;
            });

        $scope.$parent.snapshotActive = true;
        $scope.$parent.complianceActive = false;

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
        if ($scope.reportId === $scope.PIT_Report_Id) {
            updateTree();
        } else if ($scope.reportId === $scope.PBV_Report_Id) {
            processPBVData();
        } else if ($scope.reportId === $scope.MVA_Report_Id) {
            filterMVABySeverity();
        } else if ($scope.reportId === $scope.OWASP_Report_Id) {
            processOWASPData();
        } else if ($scope.reportId === $scope.DISA_STIG_Report_Id) {
            processDisaStigData();
        } else if ($scope.reportId === $scope.Scan_Comparison_Summary_Id) {
            processScanComparisonData();
        }
    });

    var updateTree = function () {
        var _parameters = angular.copy($scope.parameters);
        $scope.hideTitle = false;
        vulnSearchParameterService.updateParameters($scope, $scope.parameters);

        if (!$scope.title)
            $scope.title = {};
        $scope.title.tagsList = $scope.parameters.tags;
        $scope.title.vulnTagsList = $scope.parameters.vulnTags;
        $scope.title.teamsList = $scope.parameters.teams;
        $scope.title.appsList = $scope.parameters.applications;

        $scope.$broadcast("refreshVulnSearchTree", $scope.parameters);
        updateAverageAge($scope.parameters);
        $scope.parameters = _parameters;
    };

    var updateAverageAge = function(parameters) {
        $scope.loading = true;
        $scope.averageAges = undefined;
        $http.post(tfEncoder.encode("/reports/snapshot/averageAge"), parameters).
        success(function(data, status, headers, config) {
            if (data.success) {
                $scope.averageAges = data.object.averageAges;
            } else if (data.message) {
                $scope.errorMessage = "Failure. Message was : " + data.message;
            }

            $scope.loading = false;
        }).
        error(function(data, status, headers, config) {
            $log.info("Got " + status + " back.");
            $scope.errorMessage = "Failed to retrieve vulnerability tree. HTTP status was " + status;
            $scope.loading = false;
        });
    };

    $scope.loadReport = function() {
        $scope.reportId = parseInt($scope.reportId);

        if ($scope.reportId !== $scope.OWASP_Report_Id) {
            $scope.parameters.startDate = undefined;
            $scope.parameters.endDate = undefined;
        }

        // Progress By Vulnerability report
        if ($scope.reportId === $scope.PBV_Report_Id) {
            processPBVData();
        }
        // Point In Time report
        else if ($scope.reportId === $scope.PIT_Report_Id) {
            updateTree();
        }
        // Most Vulnerable Applications report
        else if ($scope.reportId === $scope.MVA_Report_Id) {
            processMVAData();
        }
        // OWASP Top 10 report
        else if ($scope.reportId === $scope.OWASP_Report_Id) {
            processOWASPData();
        }
        // Disa Stig report
        else if ($scope.reportId === $scope.DISA_STIG_Report_Id) {
            processDisaStigData();
        }
        // Portfolio report
        else if ($scope.reportId === $scope.Portfolio_Report_Id) {
            $scope.filterPortfolioApps = filterByTag(filterByTeamAndApp($scope.allPortfolioApps));
            processPortfolioData();
        }
        // Scan Comparison (including HAM Effectiveness) report
        else if ($scope.reportId === $scope.Scan_Comparison_Summary_Id) {
            processScanComparisonData();
        }
    };

    var processPBVData = function() {
        $scope.progressByTypeData = [];
        var parameters = angular.copy($scope.parameters);
        $scope.hideTitle = false;
        vulnSearchParameterService.updateParameters($scope, parameters);

        if (!$scope.title)
            $scope.title = {};
        $scope.title.tagsList = parameters.tags;
        $scope.title.vulnTagsList = parameters.vulnTags;
        $scope.title.teamsList = parameters.teams;
        $scope.title.appsList = parameters.applications;

        $scope.loadingPBV = true;
        $http.post(tfEncoder.encode("/reports/snapshot/progressByType"), parameters).
        success(function(data, status, headers, config) {
            if (data.success) {
                $scope.progressByTypeData = data.object;

                // Sorting by Total is default
                $scope.$parent.setSortNumber($scope.progressByTypeData, "total");
            } else if (data.message) {
                $scope.errorMessage = "Failure. Message was : " + data.message;
            }

            $scope.loadingPBV = false;
        }).
        error(function(data, status, headers, config) {
            $log.info("Got " + status + " back.");
            $scope.errorMessage = "Failed to retrieve vulnerability tree. HTTP status was " + status;
            $scope.loadingPBV = false;
        });

    };

    var refresh = function(){
        reportUtilities.createTeamAppNames($scope);

        if ($scope.reportId === $scope.PIT_Report_Id) {
            updateTree();
        } else if ($scope.reportId === $scope.PBV_Report_Id) {
            processPBVData();
        } else if ($scope.reportId === $scope.MVA_Report_Id) {
            processMVAData();
        } else if ($scope.reportId === $scope.OWASP_Report_Id) {
            processOWASPData();
        } else if ($scope.reportId === $scope.Portfolio_Report_Id) {
            $scope.filterPortfolioApps = filterByTag(filterByTeamAndApp($scope.allPortfolioApps));
            processPortfolioData();
        } else if ($scope.reportId === $scope.DISA_STIG_Report_Id) {
            processDisaStigData();
        } else if ($scope.reportId === $scope.Scan_Comparison_Summary_Id) {
            processScanComparisonData();
        }

    };

    var getPercent = function(rate) {
        return getPercentNumber(rate) + "%";
    };

    var getPercentNumber = function(rate) {
        return Math.round(1000 * rate)/10;
    };

    var filterByTeamAndApp = function(rawList) {

        var filteredList;

        if ($scope.parameters.teams.length === 0
            && $scope.parameters.applications.length === 0)
            filteredList = rawList;
        else {
            filteredList = rawList.filter(function(vuln){
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
        }
        return filteredList;
    };

    var filterByTag = function(rawList) {

        var filteredList;

        // Filter by application tags
        if ($scope.parameters.tags.length === 0)
            filteredList = rawList;
        else {
            filteredList = rawList.filter(function(vuln){
                var i;
                for (i=0; i<$scope.parameters.tags.length; i++) {
                    if ($scope.appTagMatrix[vuln.appId][$scope.parameters.tags[i].name]) {
                        return true;
                    }
                }
                return false;
            });
        }

        // Filter by vulnerability tags
        if ($scope.parameters.vulnTags.length !== 0) {
            filteredList = filteredList.filter(function(vuln){

                var isSelected = false;
                vuln.tags.some(function(vulnTag){
                    $scope.parameters.vulnTags.some(function(selectedTag){
                        if (selectedTag.name === vulnTag.name) {
                            isSelected = true;
                            return true;
                        }
                    })
                    if (isSelected) return true;
                });

                return isSelected;
            });
        }

        return filteredList;
    };

    var processWithCustomSeverities = function(appList) {
        var returnList = [];

        appList.forEach(function(application) {

            if (application.cweId) { // top 10 vulns
                $scope.topAppsData.push(application);
            } else { // top 10 apps
                var innerData = {};
                innerData[customSeverityService.getCustomSeverity("Info")] = application["Info"];
                innerData[customSeverityService.getCustomSeverity("Low")] = application["Low"];
                innerData[customSeverityService.getCustomSeverity("Medium")] = application["Medium"];
                innerData[customSeverityService.getCustomSeverity("High")] = application["High"];
                innerData[customSeverityService.getCustomSeverity("Critical")] = application["Critical"];
                innerData.appId = application.appId;
                innerData.appName = application.appName;
                innerData.teamId = application.teamId;
                innerData.teamName = application.teamName;
                innerData.title = application.title;
                returnList.push(innerData);
            }
        });


        return returnList;
    };

    var processMVAData = function() {

        $scope.loading = true;

        var parameters = angular.copy($scope.parameters);

        vulnSearchParameterService.updateParameters($scope.$parent, parameters);

        if (!$scope.title)
            $scope.title = {};
        $scope.title.tagsList = parameters.tags;
        $scope.title.vulnTagsList = parameters.vulnTags;
        $scope.title.teamsList = parameters.teams;
        $scope.title.appsList = parameters.applications;

        $http.post(tfEncoder.encode("/reports/getTopApps"), parameters).
            success(function(data) {
                if (data.object.appList) {
                    $scope.topAppsData = processWithCustomSeverities(data.object.appList);
                } else {
                    $scope.topAppsData = convertRawInfo(data.object.rawAppList);
                }
                if ($scope.topAppsData) {
                    $scope._topAppsData = angular.copy($scope.topAppsData);
                    filterMVABySeverity();

                } else {
                    $scope.noData = true;
                };
                $scope.loading = false;
            })
            .error(function() {
                $scope.loading = false;
            });

    };

    var convertRawInfo = function(rawAppList) {
        var map = {};
        rawAppList.forEach(function(rawApp){
            if (map[rawApp.appId]) {
                map[rawApp.appId][rawApp.severityNameValue] = rawApp.vulnCount;
            } else {
                map[rawApp.appId] = {
                    Critical: 0,
                    High: 0,
                    Medium: 0,
                    Low: 0,
                    Info: 0,
                    appId: rawApp.appId,
                    appName: rawApp.appName,
                    teamId: rawApp.teamId,
                    teamName: rawApp.teamName,
                    title: rawApp.teamName + "/" + rawApp.appName
                };
                map[rawApp.appId][rawApp.severityNameValue] = rawApp.vulnCount;
            }
        });

        var result = [];
        for (var key in map) {
            result.push(map[key]);
        }
        return result;
    }

    var processOWASPData = function() {

        $scope.loading = true;

        var parameters = angular.copy($scope.parameters);
        parameters.owasp = parameters.selectedOwasp;
        vulnSearchParameterService.updateParameters($scope, parameters);

        $scope.$broadcast("refreshVulnSearchTree", parameters);
        $scope.loading = false;
        $scope.hideTitle = false;
    };

    var processDisaStigData = function() {

        $scope.loading = true;

        var parameters = angular.copy($scope.parameters);
        parameters.disaStig = $scope.DISA_STIG;
        vulnSearchParameterService.updateParameters($scope, parameters);

        $scope.$broadcast("refreshVulnSearchTree", parameters);
        $scope.loading = false;
        $scope.hideTitle = false;
    };

    var processPortfolioData = function() {
        var now = new Date(), latestScanTime, temp, monthsOld, index;
        if (!$scope.filterPortfolioApps) return;
        var critical = {'criticality' : 'Critical'}, high = {'criticality' : 'High'}, medium = {'criticality' : 'Medium'}, low = {'criticality' : 'Low'};
        $scope.appsByCriticality = [critical, high, medium, low];
        $scope.filterPortfolioApps.forEach(function(app){
            temp = $scope.appsByCriticality[appCriticalityMap[app.criticality]];
            temp['Total'] = (temp['Total'] ? temp['Total'] + 1 : 1);
            if (!app.noOfScans || !app.latestScanTime) {
                temp['Never'] = (temp['Never'] ? temp['Never'] + 1 : 1);
            } else {
                latestScanTime = new Date(app.latestScanTime);
                monthsOld = (now.getFullYear() - latestScanTime.getFullYear()) * 12 + now.getMonth() - latestScanTime.getMonth();
                if (monthsOld < 2)
                    index = "1Month";
                else if (monthsOld < 4)
                    index = "3Months";
                else if (monthsOld < 7)
                    index = "6Months";
                else if (monthsOld < 13)
                    index = "12Months";
                else index = 'Years';

                temp[index] = (temp[index] ? temp[index] + 1 : 1);
            }
        });

        $scope.appsByCriticality.forEach(function(appRow){
            Object.keys(appRow).forEach(function(key){
                if (key !== 'criticality' && key !== 'Total') {
                    if (!appRow[key])
                        appRow[key] = 0;
                    else {
                        appRow[key] = appRow[key] + "(" + getPercent(appRow[key]/appRow['Total']) + ")";
                    }
                }

            });
        });

        var teamMap = {}, daysOld;
        $scope.filterPortfolioApps.forEach(function(app) {
            if (!teamMap[app.teamId]) {
                teamMap[app.teamId] = {
                    name: "Team: " + app.teamName,
                    noOfScans: 0,
                    criticality: "",
                    daysScanedOld : 'Never',
                    apps : []
                };
            }
            if (app.noOfScans && app.latestScanTime) {
                teamMap[app.teamId].noOfScans += app.noOfScans;
                daysOld = Math.round((now.getTime() - app.latestScanTime)/(24*60*60*1000));

                if (teamMap[app.teamId].lowBound === undefined)
                    teamMap[app.teamId].lowBound = daysOld;
                if (teamMap[app.teamId].upBound === undefined)
                    teamMap[app.teamId].upBound = daysOld;

                if (teamMap[app.teamId].lowBound > daysOld) teamMap[app.teamId].lowBound = daysOld;
                if (teamMap[app.teamId].upBound < daysOld) teamMap[app.teamId].upBound = daysOld;

                app.daysScanedOld = daysOld;
            }

            teamMap[app.teamId].apps.push(app);
        });

        $scope.teamStatistics = [];
        Object.keys(teamMap).forEach(function(key){
            if (teamMap[key].noOfScans !== 0) {
                teamMap[key].daysScanedOld = (teamMap[key].lowBound === teamMap[key].upBound) ?
                    teamMap[key].lowBound : teamMap[key].lowBound + '-' + teamMap[key].upBound;
            }
            $scope.teamStatistics.push(teamMap[key]);
        });

        $scope.teamStatistics.sort(function(a, b) {
            return a.name.localeCompare(b.name);
        });

        $scope.scanStatistics = [];
        $scope.noOfScans = 0;
        $scope.teamStatistics.forEach(function(team){
            $scope.noOfScans += team.noOfScans;
            $scope.scanStatistics.push(team);
            team.apps.forEach(function(app) {
                app.name = app.appName;
                $scope.scanStatistics.push(app);
            });
            $scope.scanStatistics.push({});
        })
    };

    var filterMVABySeverity = function() {

        $scope.topAppsData = angular.copy($scope._topAppsData);

        $scope.topAppsData.forEach(function(app) {
            if ($scope.parameters.severities.critical
                || $scope.parameters.severities.high
                || $scope.parameters.severities.medium
                || $scope.parameters.severities.low
                || $scope.parameters.severities.info) {
                if (!$scope.parameters.severities.critical)
                    app[customSeverityService.getCustomSeverity("Critical")] = 0;
                if (!$scope.parameters.severities.high)
                    app[customSeverityService.getCustomSeverity("High")] = 0;
                if (!$scope.parameters.severities.medium)
                    app[customSeverityService.getCustomSeverity("Medium")] = 0;
                if (!$scope.parameters.severities.low)
                    app[customSeverityService.getCustomSeverity("Low")] = 0;
                if (!$scope.parameters.severities.info)
                    app[customSeverityService.getCustomSeverity("Info")] = 0;
                app.genericSeverities = customSeverityService.getGenericSeverities();
            }
        });

        $scope.topAppsData.sort(function(app1, app2) {
            return getTotalVulns(app2) - getTotalVulns(app1);
        })
    };

    var processScanComparisonData = function() {

        $scope.scannerComparisonData = [];
        var parameters = angular.copy($scope.parameters);
        $scope.hideTitle = false;
        vulnSearchParameterService.updateParameters($scope, parameters);

        if (!$scope.title)
            $scope.title = {};
        $scope.title.tagsList = parameters.tags;
        $scope.title.vulnTagsList = parameters.vulnTags;
        $scope.title.teamsList = parameters.teams;
        $scope.title.appsList = parameters.applications;

        $scope.loadingScanComparison = true;
        $http.post(tfEncoder.encode("/reports/snapshot/scanComparison"), parameters).
        success(function(data, status, headers, config) {
            if (data.success) {
                $scope.scannerComparisonData = data.object.channelsInfo;
                $scope.totalVuln = data.object.totalVuln;
                $scope.scannerComparisonData.sort(function(c1, c2){
                    return c2.foundCount - c1.foundCount;
                });
            } else if (data.message) {
                $scope.errorMessage = "Failure. Message was : " + data.message;
            }

            $scope.loadingScanComparison = false;
        }).
        error(function(data, status, headers, config) {
            $log.info("Got " + status + " back.");
            $scope.errorMessage = "Failed to retrieve vulnerability tree. HTTP status was " + status;
            $scope.loadingScanComparison = false;
        });

    };


    var getTotalVulns = function (app){
        return app.Critical + app.High + app.Medium + app.Low + app.Info;
    };

    var endsWith = function(str, suffix) {
        return str.indexOf(suffix, str.length - suffix.length) !== -1;
    };

    var beginsWith = function(str, prefix) {
        return str.indexOf(prefix) == 0;
    };

    Array.prototype.unique = function() {
        var arr = [];
        for(var i = 0; i < this.length; i++) {
            if(arr.indexOf(this[i]) === -1) {
                arr.push(this[i]);
            }
        }
        return arr;
    };

    $scope.exportPDF = function() {

        var parameters = angular.copy($scope.parameters);

        if ($scope.reportId == $scope.OWASP_Report_Id)
            parameters.owasp = parameters.selectedOwasp;

        if ($scope.reportId == $scope.DISA_STIG_Report_Id) {
            parameters.isDISASTIG = true;
        }

        $scope.exportInfo = {};
        $scope.exportInfo.tableId = $scope.htmlElementIdMap[$scope.reportId];
        $scope.exportInfo.svgId = $scope.graphIdMap[$scope.reportId];
        $scope.exportInfo.title = $scope.titleMap[$scope.reportId];
        $scope.exportInfo.tags = $scope.title.tags;
        $scope.exportInfo.teams = $scope.title.teams;
        $scope.exportInfo.apps = $scope.title.apps;

        if ($scope.reportId === $scope.PIT_Report_Id || $scope.reportId === $scope.OWASP_Report_Id || $scope.DISA_STIG_Report_Id)
            reportExporter.exportPDFTable($scope, parameters, $scope.exportInfo);
        else
            reportExporter.exportPDFTableFromId($scope, $scope.exportInfo);

        parameters.isDISASTIG = false;

    };

    $scope.exportCSV = function() {

        var vulnTagsName = ($scope.title.vulnTags) ? "_" + $scope.title.vulnTags : "";
        var tagsName = ($scope.title.tags) ? "_" + $scope.title.tags : "";
        var teamsName = ($scope.title.teams) ? "_" + $scope.title.teams : "";
        var appsName = ($scope.title.apps) ? "_" + $scope.title.apps : "";

        reportExporter.exportCSV(convertToCsv($scope.title, $scope.progressByTypeData),
            "application/octet-stream", "VulnerabilityProgressByType" + teamsName + appsName + ".csv");
    };

    var convertToCsv = function(title, data){
        var csvArray = ['Vulnerability Progress By Type \n'];
        if (title.vulnTags)
            csvArray.push(["Vulnerability Tags: " + title.vulnTags]);
        if (title.tags)
            csvArray.push(["Application Tags: " + title.tags]);
        if (title.teams)
            csvArray.push(["Teams: " + title.teams]);
        if (title.apps)
            csvArray.push(["Applications: " + title.apps]);
        csvArray.push("\n");
        csvArray.push(['Type,Count,% Fixed,Average Age,Average Time to Close']);
        data.forEach(function(d) {
            csvArray.push(d.description + ',' + d.total + ',' + d.percentClosed + ',' + d.averageAgeOpen + ',' + d.averageTimeToClose);
        });
        return csvArray.join("\n");
    };
    var appCriticalityMap = {"Critical" : 0, "High" : 1, "Medium" : 2, "Low" : 3};
});
