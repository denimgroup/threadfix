var module = angular.module('threadfix');

module.controller('RemoteProvidersTabController', function($scope, $http, $modal, $rootScope, $log, tfEncoder){

    $scope.providers = [];

    $scope.heading = 'Remote Providers';

    $scope.initialized = false;

    $scope.empty = true;

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    var calculateShowImportAll = function(provider) {
        provider.showImportAll = provider.remoteProviderApplications.filter(function(app) {
            return app.application
        }).length > 0;
    };

    var setCredentialsMatrix = function(provider) {

        var hasCredentials = false;

        if (provider.authenticationFields.length) {
            var authString = "";

            provider.authenticationFields.forEach(function(field) {
                authString = authString + field.name + ", ";

                if (field.value) {
                    hasCredentials = true;
                }
            });

            if (authString.length > 0) {
                authString = authString.substring(0, authString.length - 2);
            }

            provider.authInformation = authString;
        } else if (provider.hasApiKey) {
            provider.authInformation = "API Key";
            if (provider.apiKey) {
                hasCredentials = true;
            }
        } else if (provider.hasUserNamePassword) {
            provider.authInformation = "Username and Password";
            if (provider.username) {
                hasCredentials = true;
            }
        }

        provider.hasCredentials = hasCredentials ? 'Yes' : 'No';
    };

    $scope.$on('rootScopeInitialized', function() {
        $http.get(tfEncoder.encode('/configuration/remoteproviders/getMap')).
            success(function(data, status, headers, config) {

                if (data.success) {
                    $scope.providers = data.object.remoteProviders;
                    $scope.teams = data.object.teams;
                    $scope.scheduledImports = data.object.scheduledImports;
                    $scope.qualysPlatforms = data.object.qualysPlatforms;

                    $scope.defectTrackerTypes = data.object.defectTrackerTypes;

                    $scope.providers.sort(nameCompare);

                    $scope.providers.forEach($scope.paginate);

                    $scope.providers.forEach(calculateShowImportAll);

                    $scope.providers.forEach(setCredentialsMatrix);

                    $rootScope.$broadcast('scheduledImports', $scope.scheduledImports);

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

    $scope.paginate = function(provider) {
        if (provider.remoteProviderApplications) {
            if (!provider.page) {
                provider.page = 1;
            }

            var targetPage = provider.page - 1;

            if (provider.remoteProviderApplications.length > (provider.page * 100)) {
                provider.displayApps = provider.remoteProviderApplications.slice(targetPage * 100, 100 * provider.page)
            } else {
                provider.displayApps = provider.remoteProviderApplications.slice(targetPage * 100)
            }
        }
    };

    $scope.clearConfiguration = function(provider) {

        var url = tfEncoder.encode("/configuration/remoteproviders/" + provider.id + "/clearConfiguration");

        if (confirm("Are you sure you want to clear your " + provider.name + " configuration?")) {
            provider.clearingConfiguration = true;
            $http.post(url).
                success(function(data, status, headers, config) {
                    if (data.success) {
                        provider.username = undefined;
                        provider.apiKey = undefined;
                        provider.password = undefined;
                        provider.remoteProviderApplications = undefined;
                        provider.successMessage = undefined;
                        provider.errorMessage = undefined;
                        provider.hasCredentials = "No";
                        $scope.successMessage = provider.name + " configuration was cleared successfully.";
                    } else {
                        provider.errorMessage = "Error encountered: " + data.message;
                    }
                    provider.clearingConfiguration = false;
                }).
                error(function(data, status, headers, config) {
                    provider.clearingConfiguration = false;
                    provider.errorMessage = "Failed to clear configuration. HTTP status was " + status;
                });
        }
    };

    $scope.goToApp = function(app) {
        window.location.href = tfEncoder.encode("/organizations/" + app.team.id + "/applications/" + app.id);
    };

    $scope.goToTeam = function(team) {
        window.location.href = tfEncoder.encode("/organizations/" + team.id);
    };

    $scope.importAllScans = function(provider) {

        var url = tfEncoder.encode("/configuration/remoteproviders/" + provider.id + "/importAll");

        provider.importingScans = true;

        $http.get(url).
            success(function(data, status, headers, config) {
                if (data.success) {
                    // TODO better progress indicators
                    provider.successMessage = "ThreadFix is importing scans from " + provider.name +
                        " in the background. It may take a few minutes to finish the process.";
                } else {
                    provider.errorMessage = "Error encountered: " + data.message;
                }
                provider.importingScans = false;
            }).
            error(function(data, status, headers, config) {
                provider.errorMessage = "Failed to import scans. HTTP status was " + status;
                provider.importingScans = false;
            });
    };

    $scope.importScansApp = function(provider, app) {
        var url = tfEncoder.encode("/configuration/remoteproviders/" + provider.id + "/apps/" + app.id + "/import");

        app.importingScans = true;

        $http.get(url).
            success(function(data, status, headers, config) {
                if (data.success) {
                    if (confirm("ThreadFix imported scans successfully. Would you like to go to the application's page?")) {
                        window.location.href = tfEncoder.encode("/organizations/" + app.application.team.id + "/applications/" + app.application.id);
                    }
                } else {
                    provider.errorMessage = "Error encountered: " + data.message;
                }
                app.importingScans = false;
            }).
            error(function(data, status, headers, config) {
                provider.errorMessage = "Failed to delete team. HTTP status was " + status;
                app.importingScans = false;
            });
    };

    $scope.configure = function(provider) {
        var modalInstance = $modal.open({
            templateUrl: 'configureRemoteProviderModal.html',
            controller: 'RemoteProviderModalController',
            windowClass: 'remote-provider-config-modal',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/remoteproviders/" + provider.id + "/configure");
                },
                type: function() {
                    if (!provider.matchSourceNumbers) {
                        provider.matchSourceNumbers = false;
                    }
                    return provider;
                },
                config: function() {
                    return {
                        qualysPlatforms: $scope.qualysPlatforms
                    };
                },
                buttonText: function() {
                    return "Create Defect Tracker";
                }
            }
        });

        modalInstance.result.then(function (newProvider) {

            provider.remoteProviderApplications = newProvider.remoteProviderApplications;
            $scope.paginate(provider);

            $scope.empty = $scope.providers.length === 0;

            provider.hasCredentials = "Yes";

            $scope.providers.sort(nameCompare);

            $scope.successMessage = "Successfully edited remote provider " + newProvider.name;

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.openAppModal = function(provider, app) {

        var filterActiveApp = function(app) {
            return app.active;
        };
        $scope.teams.forEach(function(team) {
            team.applications = team.applications.filter(filterActiveApp);
        });

        var modalInstance = $modal.open({
            templateUrl: 'editRemoteProviderApplicationMapping.html',
            controller: 'RemoteProviderModalMappingController',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/remoteproviders/" + provider.id + "/apps/" + app.id + "/edit");
                },
                object: function() {
                    if (!app.application) {
                        if ( $scope.teams &&  $scope.teams[0] &&  $scope.teams[0].applications)
                            return {
                                organization: $scope.teams[0],
                                application: $scope.teams[0].applications[0],
                                nativeId: app.nativeId,
                                nativeName: app.nativeName,
                                customName: app.customName
                            }
                    } else {
                        var teamId = app.application.team.id;
                        var appId = app.application.id;

                        var filterTeam = function(team) {
                            return team.id === teamId;
                        };

                        var filterApp = function(app) {
                            return app.id === appId;
                        };

                        var team = $scope.teams.filter(filterTeam)[0]
                        team.applications = team.applications.filter(filterActiveApp);
                        var application = team.applications.filter(filterApp)[0];

                        return {
                            organization: team,
                            application: application,
                            remoteProviderType: provider,
                            nativeName: app.nativeName,
                            customName: app.customName,
                            nativeId: app.nativeId
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
                        return tfEncoder.encode("/configuration/remoteproviders/" + provider.id + "/apps/" + app.id + "/delete/" + app.application.id);
                    } else {
                        return null;
                    }
                }
            }
        });

        modalInstance.result.then(function (editedApp) {

            app.application = editedApp.application;

            calculateShowImportAll(provider);

            $scope.successMessage = "Successfully edited mapping for " + provider.name;

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };


    $scope.openNameModal = function(provider, app) {

        var modalInstance = $modal.open({
            templateUrl: 'editRemoteProviderApplicationName.html',
            controller: 'GenericModalController',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/remoteproviders/" + provider.id + "/apps/" + app.id + "/setName");
                },
                object: function() {
                    return {
                        customName: app.customName,
                        nativeId: app.nativeId,
                        nativeName: app.nativeName
                    }
                },
                buttonText: function() {
                    return "Save";
                },
                config: function() {
                    return {
                        showDelete: false
                    };
                }
            }
        });

        modalInstance.result.then(function (editedApp) {

            app.customName = editedApp.customName;

            $scope.successMessage = "Successfully edited name for " + provider.name;

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.updateApplications = function(provider) {
        var url = tfEncoder.encode("/configuration/remoteproviders/" + provider.id + "/update");

        provider.updatingApps = true;

        $http.get(url).
            success(function(data, status, headers, config) {
                if (data.success) {
                    provider.successMessage = "Successfully updated " + provider.name + " applications.";
                    provider.remoteProviderApplications = data.object;
                    calculateShowImportAll(provider);
                    $scope.paginate(provider);
                } else {
                    $scope.errorMessage = "Error encountered: " + data.message;
                }
                provider.updatingApps = false;
            }).
            error(function(data, status, headers, config) {
                provider.errorMessage = "Failed to update applications. HTTP status was " + status;
                provider.updatingApps = false;
            });
    };

});