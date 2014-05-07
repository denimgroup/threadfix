var module = angular.module('threadfix');

module.controller("UserPermissionsConfigController", function($scope, $http, $modal, $log, tfEncoder){

    $scope.keys = [];

    var keyCompare = function(a,b) {
        return a.apiKey.localeCompare(b.apiKey);
    };

    var defaultTeam = { id: 0, name: 'Select a Team'};

    var refreshTable = function() {
        $http.get(tfEncoder.encode('/configuration/users/' + $scope.userId + '/permissions/map')).
            success(function(data, status, headers, config) {

                if (data.success) {
                    $scope.maps = data.object.maps;
                    $scope.teams = data.object.teams;
                    $scope.roles = data.object.roles;

                    $scope.teams.push(defaultTeam);

                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.initialized = true;
            }).
            error(function(data, status, headers, config) {
                $scope.initialized = true;
                $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
            });
    }

    // TODO move to service
    $scope.$on('rootScopeInitialized', function() {
        refreshTable();
    });

    $scope.openAddPermissionsModal = function() {
        var modalInstance = $modal.open({
            templateUrl: 'permissionForm.html',
            controller: 'PermissionModalController',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/users/" + $scope.userId + "/access/new");
                },
                object: function() {
                    return {
                        team: defaultTeam,
                        allApps: true,
                        application: {
                            id: 0
                        }, role: {
                            id: 0
                        }
                    };
                },
                buttonText: function() {
                    return "Save Map";
                },
                config: function() {
                    return {
                        teams: $scope.teams,
                        roles: $scope.roles
                    };
                },
                headerText: function() {
                    return "Add Permissions Mapping";
                }
            }
        });

        modalInstance.result.then(function (permissions) {

            refreshTable();

            $scope.successMessage = "Successfully added permissions.";

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }

    var doLookups = function(perms) {

        var lastTeam = undefined;
        var lastRole = undefined;

        $scope.teams.forEach(function(team) {
            if (team.id === perms.organization.id) {
                lastTeam = team;
            }
        });

        if (perms.role) {
            $scope.roles.forEach(function(role) {
                if (role.id === perms.role.id) {
                    lastRole = role;
                }
            });
        }

        perms.role = lastRole;
        perms.team = lastTeam;
        var appList = lastTeam.applications;

        var appMaps = perms.accessControlApplicationMaps;

        appMaps.forEach(function(map) {
            appList.forEach(function(app) {
                if (map.role.id !== 0 && app.id === map.application.id) {
                    app.role = { id: map.role.id };
                }
            });
        });

        appList.forEach(function(app) {
            if (!app.role) {
                app.role = { id: 0 };
            }
        });

        return appList;
    }

    $scope.edit = function(permObject) {

        var apps = doLookups(permObject);

        var modalInstance = $modal.open({
            templateUrl: 'permissionForm.html',
            controller: 'PermissionModalController',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/users/" + $scope.userId + "/access/" + permObject.id + "/edit");
                },
                object: function() {
                    return permObject;
                },
                buttonText: function() {
                    return "Save Edits";
                },
                deleteUrl: function() {
                    return tfEncoder.encode("/configuration/users/" + $scope.userId + "/access/" + permObject.id + "/delete");
                },
                config: function() {
                    return {
                        teams: $scope.teams,
                        roles: $scope.roles,
                        appList: apps
                    };
                },
                headerText: function() {
                    return "Edit Permissions Mapping";
                }
            }
        });

        modalInstance.result.then(function (editedPermissionsObject) {

            refreshTable();

            if (editedPermissionsObject) {
                $scope.successMessage = "Successfully edited permissions.";
            } else {
                $scope.successMessage = "Permissions object was successfully deleted.";
            }

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }

    var makeDeleteRequest = function(url) {
        if (confirm("Are you sure you want to delete this permission?")) {
            $http.post(tfEncoder.encode('/configuration/users/' + $scope.userId + url)).
                success(function(data, status, headers, config) {
                    if (data.success) {
                        refreshTable();
                        $scope.successMessage = "Permission was successfully deleted.";
                    } else {
                        $scope.errorMessage = "Failure. Message was : " + data.message;
                    }

                    $scope.initialized = true;
                }).
                error(function(data, status, headers, config) {
                    $scope.initialized = true;
                    $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
                });
        }
    }

    $scope.deleteApp = function(map) {
        makeDeleteRequest('/access/app/' + map.id + '/delete')
    }

    $scope.deleteTeam = function(map) {
        makeDeleteRequest('/access/team/' + map.id + '/delete')
    }

});