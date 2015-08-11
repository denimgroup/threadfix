var myAppModule = angular.module('threadfix');

myAppModule.controller('UserAuditPageController', function ($scope, $modal, $http, $log, $rootScope, tfEncoder, $filter) {

    ////////////////////////////////////////////////////////////////////////////////
    //             Basic Page Functionality + $on(rootScopeInitialized)
    ////////////////////////////////////////////////////////////////////////////////

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    $scope.activateTab = function(tab) {
        $scope.active = {}; //reset
        $scope.active[tab] = true;
        $rootScope.title = tab[0].toUpperCase() + tab.substr(1);
    };

    $scope.numberToShow = 10;

    $scope.updatePage = function(page) {
        $scope.page = page;
        reloadList();
    };

    $scope.$on('rootScopeInitialized', function() {
        reloadList();
    });

    $scope.$on('refreshUsers', function() {
        reloadList();
    });

    $scope.$on('refreshGroups', function() {
        reloadList();
    });

    $scope.$on('reloadRoles', function() {
        reloadList();
    });

    var reloadList = function() {
        $scope.initialized = false;

        $http.get(tfEncoder.encode('/configuration/users/map/page/' + $scope.page + '/' + $scope.numberToShow)).
            success(function(data) {

                if (data.success) {
                    $scope.countUsers = data.object.countUsers;
                    if (data.object.users.length > 0) {
                        $scope.users = data.object.users;
                        $scope.users.sort(nameCompare);
                    } else {

                        // If the last page is no longer exist then refresh to page 1
                        if ($scope.page !== 1) {
                            $scope.page = 1;
                            reloadList();
                        }
                    }
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.initialized = true;
            }).
            error(function(data, status, headers, config) {
                $scope.initialized = true;
                $scope.errorMessage = "Failed to retrieve user list. HTTP status was " + status;
            });
    };

    $scope.getAllUsers = function(callback) {

        var users = [];

        $http.get(tfEncoder.encode('/configuration/users/all')).
            success(function(data) {

                if (data.success) {
                    callback(data.object);
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }
            }).
            error(function(data, status, headers, config) {
                $scope.errorMessage = "Failed to retrieve user list. HTTP status was " + status;
            });

        return users;
    };

    $scope.openGroups = function(user) {

        $modal.open({
            templateUrl: 'groupsListModal.html',
            controller: 'ModalController',
            resolve: {
                data: function() {
                    return {
                        heading: 'User Groups',
                        list: user.groups
                    }
                }
            }
        });
    };

    $scope.openRoles = function(user) {

        var teamMaps = user.accessControlTeamMaps;
        var appMaps = getAppRoles(teamMaps);

        $modal.open({
            templateUrl: 'rolesListModal.html',
            controller: 'ModalController',
            resolve: {
                data: function() {
                    return {
                        heading: 'User Roles',
                        teamMaps: teamMaps,
                        appMaps: appMaps,
                        userGlobalRole: user.globalRole != null ? user.globalRole.displayName : '--'
                    }
                }
            }
        });
    };

    var getAppRoles = function(teamMaps) {

        var appMaps = [];

        for (var i = 0; i < teamMaps.length; i++) {
            var appRoles = teamMaps[i].appRoles;

            for (var j = 0; j < appRoles.length; j++) {
                var appRole = appRoles[j];
                appMaps.push(appRole);
            }
        }

        return appMaps;
    };

    $scope.exportPDF = function() {
        $scope.getAllUsers(function(users) {
            var data = [], fontSize = 12, height = 0, doc;

            doc = new jsPDF('p', 'pt', 'a4', true);
            doc.setFont("courier", "normal");
            doc.setFontSize(fontSize);

            for (var i = 0; i < users.length; i++) {

                var user = users[i];
                var groups = user.groups.map(function(group) {
                    return group.name;
                }).join(", ");

                var roles = "Global Role: " + (user.globalRole != null ? user.globalRole.displayName : "--");

                var teamRoles = user.accessControlTeamMaps.map(function(teamMap) {
                    if ( teamMap.roleName !== '-') {
                        return teamMap.roleName + " (" + teamMap.teamName + ")";
                    }
                });

                if ( teamRoles.length > 0 ) {
                    roles += "\nTeam Roles: " + teamRoles.join(", ");
                }

                var appRoles = getAppRoles(user.accessControlTeamMaps).map(function(appMap) {
                    if ( appMap.roleName !== '-') {
                        return appMap.roleName + " (" + appMap.teamName + ":" + appMap.appName + ")";
                    }
                });

                if ( appRoles.length > 0 )
                    roles += "\nApp Roles: " + appRoles.join(", ");

                data.push({
                    "Name" : user.displayName ? user.displayName : "-",
                    "Username" : user.name,
                    "Last Log In" : $filter('date')(user.lastLoginDate, 'medium'),
                    "Roles" : roles,
                    "Groups" : groups
                });
            }

            height = doc.drawTable(data, {
                xstart: 10,
                ystart: 10,
                tablestart: 70,
                marginleft: 50
            });

            var fileName = "user-audit-report-" + $filter('date')(new Date(), 'yyyyMMddHHmmss') + ".pdf";
            doc.save(fileName);
        });
    };

});
