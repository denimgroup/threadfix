var myAppModule = angular.module('threadfix');

myAppModule.controller('UserAuditPageController', function ($scope, $modal, $http, $log, $rootScope, tfEncoder, $filter) {

    ////////////////////////////////////////////////////////////////////////////////
    //             Basic Page Functionality + $on(rootScopeInitialized)
    ////////////////////////////////////////////////////////////////////////////////

    var lastSearchString = undefined;
    var lastNumber = 0;
    var lastPage = 0;

    $scope.activateTab = function(tab) {
        $scope.active = {}; //reset
        $scope.active[tab] = true;
        $rootScope.title = tab[0].toUpperCase() + tab.substr(1);
    };

    $scope.numberToShow = 10;

    $scope.updatePage = function(page, searchString) {
        $scope.page = page;
        $scope.searchUsers(searchString);
    };

    $scope.searchUsers = function(searchText) {

        if (lastSearchString && lastSearchString === searchText &&
            lastNumber === $scope.numberToShow &&
            lastPage === $scope.page) {
            return;
        }

        var users = [];

        var searchObject = {
            "searchString" : searchText,
            "page" : $scope.page,
            "number" : $scope.numberToShow
        };

        $http.post(tfEncoder.encode("/configuration/users/search"), searchObject).
            then(function(response) {

                var data = response.data;

                if (data.success) {
                    $scope.countUsers = data.object.countUsers;
                    lastSearchString = searchText;
                    lastNumber = $scope.numberToShow;
                    lastPage = $scope.page;
                    $scope.users = data.object.users;
                } else {
                    $scope.errorMessage = "Failed to receive search results. Message was : " + data.message;
                }

                return users;
            });

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

    $scope.openGroups = function(user) {

        $modal.open({
            templateUrl: 'attrListModal.html',
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

    $scope.exportPDF = function(users) {

        var data = []
            ,fontSize = 12
            ,height = 0
            ,doc
            ;

        doc = new jsPDF('p', 'pt', 'a4', true);
        doc.setFont("courier", "normal");
        doc.setFontSize(fontSize);

        for (var i = 0; i < users.length; i++) {

            var user = users[i];
            var groupListStr = user.groups.map(function(group) {
                return group.name;
            }).join(", ");

            data.push({
                "Name" : user.displayName ? user.displayName : "--",
                "Username" : user.name,
                "Last Log In" : $filter('date')(user.lastLoginDate, 'medium'),
                "Role" : user.globalRole ? user.globalRole.displayName : "--",
                "Groups" : groupListStr
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
    };

});
