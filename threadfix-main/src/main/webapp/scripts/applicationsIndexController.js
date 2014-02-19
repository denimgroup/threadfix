var myAppModule = angular.module('threadfix')

myAppModule.controller('ApplicationsIndexController', function($scope, $log, $modal, $upload, threadfixAPIService) {

    // Initialize
    $scope.initialized = false;

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    // since we need the csrfToken to make the request, we need to wait until it's initialized
    $scope.$watch('csrfToken', function() {
        threadfixAPIService.getTeams($scope.csrfToken).
            success(function(data, status, headers, config) {
                $scope.initialized = true;

                if (data.success) {
                    $scope.teams = data.object;
                    $scope.teams.sort(nameCompare)

                    if ($scope.teams.length == 0) {
                        $scope.openTeamModal();
                    }
                } else {
                    $scope.output = "Failure. Message was : " + data.message;
                }
            }).
            error(function(data, status, headers, config) {
                $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
            });
    });
    // Table animations

    $scope.toggle = function(team) {

        if (typeof team.expanded === "undefined") {
            team.expanded = false;
        }

        if (team.expanded) {
            team.expanded = false;
        } else {
            team.expanded = true;
        }

        loadGraph(team);
    }

    $scope.expand = function() {
        $scope.teams.forEach(function(team) {
            team.expanded = true;
            loadGraph(team);
        });
    }

    $scope.contract = function() {
        $scope.teams.forEach(function(team) {
            team.expanded = false;
        });
    }

    var loadGraph = function(team) {

        if (team.report == null) {

            var url = '/organizations/' + team.id + '/getReport' + $scope.csrfToken;

            var failureDiv = '<div class="" style="margin-top:10px;margin-right:20px;width:300px;height:200px;text-align:center;line-height:150px;">Failed to load report.</div>';

            threadfixAPIService.loadReport(url).
                success(function(data, status, headers, config) {

                    // TODO figure out Jasper better, it's a terrible way to access the report images.
                    var matches = data.match(/(<img src="\/jasperimage\/.*\/img_0_0_0" style="height: 250px" alt=""\/>)/);
                    if (matches !== null && matches[1] !== null) {
                        team.report = matches[1];
                    } else {
                        team.report = failureDiv;
                    }
                }).
                error(function(data, status, headers, config) {

                    // TODO improve error handling and pass something back to the users
                    team.report = failureDiv;
                });
        }
    }

    // Modal functions

    $scope.openTeamModal = function() {
        var modalInstance = $modal.open({
            templateUrl: 'newTeamModal.html',
            controller: 'GenericModalController',
            resolve: {
                url: function() {
                    return "/organizations/modalAdd" + $scope.csrfToken;
                },
                object: function() {
                    return {};
                }
            }
        });

        modalInstance.result.then(function (newTeam) {

            $scope.teams.push(newTeam);

            $scope.teams.sort(nameCompare);

            $scope.successMessage = "Successfully added team " + newTeam.name;

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }

    $scope.openAppModal = function (team) {

        var application = {
            team: {
                id: team.id,
                name: team.name
            },
            applicationCriticality: {
                id: 2
            },
            frameworkType: 'Detect'
        };

        var modalInstance = $modal.open({
            templateUrl: 'newApplicationModal.html',
            controller: 'GenericModalController',
            resolve: {
                url: function() {
                    return "/organizations/" + team.id + "/modalAddApp" + $scope.csrfToken;
                },
                object: function () {
                    return application;
                }
            }
        });

        modalInstance.result.then(function (newApplication) {

            if (team.applications == null) {
                team.applications = [];
            }

            team.applications.push(newApplication);

            team.applications.sort(nameCompare);

            team.expanded = true;
            loadGraph(team);

            $scope.successMessage = "Successfully added application " + newApplication.name;

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.showUploadForm = function(team, app) {
        var modalInstance = $modal.open({
            templateUrl: 'uploadScanForm.html',
            controller: 'UploadScanController',
            resolve: {
                url: function() {
                    return "/organizations/" + team.id + "/applications/" + app.id + "/upload/remote" + $scope.csrfToken;
                },
                files: function() {
                    return false;
                }
            }
        });

        modalInstance.result.then(function (updatedTeam) {
            $log.info("Successfully uploaded scan.");
            $log.successMessage = "Successfully uploaded scan.";
            updateTeam(team, updatedTeam);
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });

    }

    $scope.onFileSelect = function(team, app, $files) {
        var modalInstance = $modal.open({
            templateUrl: 'uploadScanForm.html',
            controller: 'UploadScanController',
            resolve: {
                url: function() {
                    return "/organizations/" + team.id + "/applications/" + app.id + "/upload/remote" + $scope.csrfToken;
                },
                files: function() {
                    return $files;
                }
            }
        });

        modalInstance.result.then(function (updatedTeam) {
            $log.info("Successfully uploaded scan.");
            $log.successMessage = "Successfully uploaded scan.";
            updateTeam(team, updatedTeam);
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    var updateTeam = function(oldTeam, newTeam) {

        var index = $scope.teams.indexOf(oldTeam);
        if (index > -1) { // let's hope it is
            $scope.teams.splice(index, 1);
        }

        $scope.teams.push(newTeam);
        $scope.teams.sort(nameCompare);

        newTeam.expanded = true;
        newTeam.report = null;
        loadGraph(newTeam);
    }

});
