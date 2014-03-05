var module = angular.module('threadfix')

module.controller('RemoteProvidersController', function($scope, $http, $modal, $log){

    $scope.providers = [];

    $scope.initialized = false;

    $scope.empty = true;

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    $scope.$watch('csrfToken', function() {
        $http.get('/configuration/remoteproviders/getMap' + $scope.csrfToken).
            success(function(data, status, headers, config) {

                if (data.success) {
                    $scope.providers = data.object.remoteProviders;
                    $scope.teams = data.object.teams;

                    $scope.empty = $scope.providers.length === 0;

                    $scope.defectTrackerTypes = data.object.defectTrackerTypes;

                    $scope.providers.sort(nameCompare);
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.initialized = true;
            }).
            error(function(data, status, headers, config) {
                $scope.initialized = true;
                $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
            });
    });

    $scope.clearConfiguration = function(provider) {

        var url = "/configuration/remoteproviders/" + provider.id + "/clearConfiguration" + $scope.csrfToken;

        if (confirm("Are you sure you want to clear your " + provider.name + " configuration?")) {
            $http.post(url).
                success(function(data, status, headers, config) {
                    if (data.success) {
                        provider.username = data.object.username;
                        provider.apiKey = data.object.apiKey;
                        provider.password = data.object.password;
                        provider.remoteProviderApplications = undefined;
                    } else {
                        $scope.errorMessage = "Error encountered: " + data.message;
                    }
                }).
                error(function(data, status, headers, config) {
                    $scope.errorMessage = "Failed to delete team. HTTP status was " + status;
                });
        }
    };

    $scope.importAllScans = function(provider) {

        var url = "/configuration/remoteproviders/" + provider.id + "/importAll" + $scope.csrfToken;

        $http.post(url).
            success(function(data, status, headers, config) {
                if (data.success) {
                    $scope.successMessage = "ThreadFix is importing scans from " + provider.name +
                        " in the background. It may take a few minutes to finish the process.";
                } else {
                    $scope.errorMessage = "Error encountered: " + data.message;
                }
            }).
            error(function(data, status, headers, config) {
                $scope.errorMessage = "Failed to delete team. HTTP status was " + status;
            });
    }

    $scope.configure = function(provider) {
        var modalInstance = $modal.open({
            templateUrl: 'configureRemoteProviderModal.html',
            controller: 'RemoteProviderModalController',
            resolve: {
                url: function() {
                    return "/configuration/remoteproviders/" + provider.id + "/configure" + $scope.csrfToken;
                },
                type: function() {
                    return provider;
                },
                config: function() {
                    return {
                        trackerTypes: $scope.defectTrackerTypes
                    };
                },
                buttonText: function() {
                    return "Create Defect Tracker";
                }
            }
        });

        modalInstance.result.then(function (newTracker) {

            $scope.successMessage = "Successfully edited tracker " + newTracker.name;

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }

    $scope.openAppModal = function(provider, app) {
        var modalInstance = $modal.open({
            templateUrl: 'editRemoteProviderApplicationMapping.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return "/configuration/remoteproviders/" + provider.id + "/apps/" + app.id + "/edit" + $scope.csrfToken;
                },
                object: function() {
                    if (!app.application) {
                        return {
                            organization: $scope.teams[0],
                            application: $scope.teams[0].applications[0]
                        }
                    } else {
                        var teamId = app.application.team.id;
                        var appId = app.application.id;

                        var filterTeam = function(team) {
                            return team.id === teamId;
                        }

                        var filterApp = function(app) {
                            return app.id === appId;
                        }

                        var team = $scope.teams.filter(filterTeam)[0]
                        var application = team.applications.filter(filterApp)[0];

                        return {
                            organization: team,
                            application: application
                        }
                    }
                    return app;
                },
                buttonText: function() {
                    return "Save";
                },
                config: function() {
                    return {
                        teams: $scope.teams,
                        showDelete: app.application
                    };
                },
                deleteUrl: function() {
                    if (app.application) {
                        return "/configuration/remoteproviders/" + provider.id + "/apps/" + app.id + "/delete/" + app.application.id + $scope.csrfToken;
                    } else {
                        return null;
                    }
                }
            }
        });

        modalInstance.result.then(function (editedApp) {

            app.application = editedApp.application;

            $scope.successMessage = "Successfully edited tracker " + editedApp.name;

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }

});