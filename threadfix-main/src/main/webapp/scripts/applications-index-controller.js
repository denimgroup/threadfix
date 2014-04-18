var myAppModule = angular.module('threadfix')

myAppModule.controller('ApplicationsIndexController', function($scope, $log, $modal, $upload, $window, tfEncoder, threadfixAPIService) {

    // Initialize
    $scope.initialized = false;

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    $scope.active = function(app) {
        return app.active;
    }

    // since we need the csrfToken to make the request, we need to wait until it's initialized
    $scope.$on('rootScopeInitialized', function() {
        threadfixAPIService.getTeams().
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
            threadfixAPIService.loadAppTableReport(team.id).
                success(function(data, status, headers, config) {

                    // TODO figure out Jasper better, it's a terrible way to access the report images.
                    var matches = data.match(/(<img src=".*\/jasperimage\/.*\/img_0_0_0" style="height: 250px" alt=""\/>)/);
                    if (matches !== null && matches[1] !== null) {
                        team.report = matches[1];
                    }
//                    else {
//                        team.reportFailed = true;
//                    }
                }).
                error(function(data, status, headers, config) {

                    // TODO improve error handling and pass something back to the users
                    team.report = true;
                    team.reportFailed = true;
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
                    return tfEncoder.encode("/organizations/modalAdd");
                },
                object: function() {
                    return {};
                },
                config: function() {
                    return {};
                },
                buttonText: function() {
                    return "Add Team";
                }
            }

        });

        modalInstance.result.then(function (newTeam) {

            if (!$scope.teams || $scope.teams.length === 0) {
                $scope.teams = [];
            }

            $scope.teams.push(newTeam);

            $scope.teams.sort(nameCompare);

            $scope.successMessage = "Successfully added team " + newTeam.name;

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }

    $scope.showAppLimitMessage = function(number) {
        alert('You have reached the application limit of ' + number + ' for your current license. To upgrade your license, please contact Denim Group.');
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
                    return tfEncoder.encode("/organizations/" + team.id + "/modalAddApp");
                },
                object: function () {
                    return application;
                },
                buttonText: function() {
                    return "Add Application";
                }
            }
        });

        modalInstance.result.then(function (newApplication) {

            if (!team.applications || team.applications.length === 0) {
                team.applications = [];
            }

            team.applications.push(newApplication);

            team.applications.sort(nameCompare);

            team.expanded = true;
//            loadGraph(team);

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
                    return tfEncoder.encode("/organizations/" + team.id + "/applications/" + app.id + "/upload/remote");
                },
                files: function() {
                    return false;
                }
            }
        });

        modalInstance.result.then(function (updatedTeam) {
            $log.info("Successfully uploaded scan.");
            $scope.successMessage = "Successfully uploaded scan.";
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
                    return tfEncoder.encode("/organizations/" + team.id + "/applications/" + app.id + "/upload/remote");
                },
                files: function() {
                    return $files;
                }
            }
        });

        modalInstance.result.then(function (updatedTeam) {
            $log.info("Successfully uploaded scan.");
            $scope.successMessage = "Successfully uploaded scan.";
            updateTeam(team, updatedTeam);
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.goTo = function(team) {
        $window.location.href = tfEncoder.encode("/organizations/" + team.id);
    };

    $scope.goToPage = function(team, app) {
        $window.location.href = tfEncoder.encode("/organizations/" + team.id + "/applications/" + app.id);
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
