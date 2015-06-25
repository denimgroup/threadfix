var module = angular.module('threadfix')

module.controller('EmailListsPageController', function($scope, $http, $modal, $log, tfEncoder){

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    $scope.$on('rootScopeInitialized', function() {
        $http.get(tfEncoder.encode('/configuration/emailLists/map')).
            success(function(data) {
                if (data.success) {
                    if (data.object.emailLists.length > 0) {
                        $scope.emailLists = data.object.emailLists;
                        $scope.emailLists.sort(nameCompare);
                    }
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }
                $scope.initialized = true;
            }).
            error(function(data, status, headers, config) {
                $scope.initialized = true;
                $scope.errorMessage = "Failed to retrieve email list. HTTP status was " + status;
            });
    });

    $scope.openNewModal = function() {
        var modalInstance = $modal.open({
            templateUrl: 'createEmailListModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/emailLists/new");
                },
                object: function () {
                    return {};
                },
                config: function() {
                    return {};
                },
                buttonText: function() {
                    return "Create Email List";
                }
            }
        });

        $scope.currentModal = modalInstance;
        modalInstance.result.then(function (emailList) {
            if (!$scope.emailLists) {
                $scope.emailLists = [ emailList ];
            } else {
                $scope.emailLists.push(emailList);
                $scope.emailLists.sort(nameCompare);
            }

            $scope.successMessage = "Successfully created email list " + emailList.name;
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.openEditModal = function(emailList) {
        var modalInstance = $modal.open({
            templateUrl: 'editEmailListModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/emailLists/" + emailList.id + "/edit");
                },
                object: function() {
                    return angular.copy(emailList);
                },
                buttonText: function() {
                    return "Save Edits";
                },
                config: function() {
                    return {}
                },
                deleteUrl: function() {
                    return tfEncoder.encode("/configuration/emailLists/" + emailList.id + "/delete");
                }
            }
        });

        modalInstance.result.then(function (emailListsMap) {
            if (emailListsMap) {
                $scope.emailLists = emailListsMap.emailLists;
                $scope.emailLists.sort(nameCompare);
                $scope.errorMessage = "";
                $scope.successMessage = "Successfully edited email list " + emailList.name;
            } else {
                var index = $scope.emailLists.indexOf(emailList);
                if (index > -1) {
                    $scope.emailLists.splice(index, 1);
                }
                if ($scope.emailLists.length === 0) {
                    $scope.emailLists = undefined;
                }

                $scope.successMessage = "The deletion was successful for email list " + emailList.name;
                $scope.errorMessage = "";
            }


        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };


});