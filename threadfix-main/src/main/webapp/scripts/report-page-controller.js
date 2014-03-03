var myAppModule = angular.module('threadfix')

myAppModule.controller('ReportPageController', function ($scope, $window, $http, threadfixAPIService) {

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    $scope.tabs = [
        {
            title: "Trending",
            active: true,
            options: [
                { name: "Trending Scans", id: 1 },
                { name: "Monthly Progress", id: 7 },
                { name: "12 Month Vulnerability Burndown", id: 9 },
                { name: "Top 20 Vulnerable Applications", id: 10 }
            ]
        },
        {
            title: "Snapshot",
            options: [
                { name: "Point in Time", id: 2 },
                { name: "Progress By Vulnerability", id: 3 },
                { name: "Portfolio Report", id: 8 },
                { name: "Vulnerability List", id: 11 }
            ]
        },
        {
            title: "Comparison",
            options: [
                { name: "Comparison By Vulnerability", id: 4 },
                { name: "Comparison Summary", id: 5 },
                { name: "Comparison Detail", id: 6 }
            ]
        }
    ];

    $scope.updateOptions = function(tab) {
        $scope.options = tab.options;
        $scope.reportId = tab.options[0].id;
    }

    $scope.updateApplications = function() {
        if ($scope.team.id === -1) {
            $scope.application = {id: -1, name: "All"};
            $scope.applications = [];
        } else {
            $scope.applications = $scope.team.applications;
            if ($scope.applications[0].id !== -1) {
                $scope.applications.unshift({id: -1, name: "All"});
            }
            $scope.application = $scope.applications[0];
        }
    }

    $scope.clearApplications = function() {
        $scope.applications = [];
    }

    $scope.applications = [];
    $scope.options = $scope.tabs[0].options;

    $scope.team = {
        id: -1
    };
    $scope.application = {
        id: -1
    };

    $scope.reportId = 1;
    $scope.formatId = 1;

    $scope.getReportParameters = function() {
        return {
            organizationId: $scope.team.id,
            applicationId: $scope.application.id,
            reportId: $scope.reportId,
            formatId: $scope.formatId
        };
    };

    $scope.loading = true;

    var loadReport = function() {
        if ($scope.initialized) {
            $scope.loading = true;
            $http.post("/reports/ajax" + $scope.csrfToken, $scope.getReportParameters()).
                success(function(data, status, headers, config) {
                    $scope.reportHTML = data;
                    $scope.loading = false;
                }).
                error(function(data, status, headers, config) {

                    // TODO improve error handling and pass something back to the users
                    $scope.leftReportFailed = true;
                    $scope.loadingLeft = false;
                    $scope.loading = false;
                });
        }
    };

    $scope.$watch('application', loadReport);
    $scope.$watch('formatId', loadReport);
    $scope.$watch('reportId', loadReport);

    $scope.$watch('csrfToken', function() {
        threadfixAPIService.getTeams($scope.csrfToken).
            success(function(data, status, headers, config) {
                if (data.success) {
                    $scope.teams = data.object;

                    $scope.teams.sort(nameCompare)

                    $scope.teams.unshift({id: -1, name: "All"});
                    $scope.team = $scope.teams[0];

                } else {
                    $scope.output = "Failure. Message was : " + data.message;
                }
            }).
            error(function(data, status, headers, config) {
                $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
            });

        $scope.initialized = true;

        loadReport();
    });


    
});