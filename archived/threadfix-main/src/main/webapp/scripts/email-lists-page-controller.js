var module = angular.module('threadfix')

module.controller('EmailListsPageController', function($scope, $http, $modal, $log, tfEncoder, threadFixModalService){

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
                    } else {
                        $scope.emailLists = [];
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
                    return "Create";
                }
            }
        });

        $scope.currentModal = modalInstance;
        modalInstance.result.then(function (emailList) {
            $scope.emailLists.push(emailList);
            $scope.emailLists.sort(nameCompare);
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
                    return "Save";
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
                threadFixModalService.deleteElement($scope.emailLists, emailList);
                $scope.successMessage = "The deletion was successful for email list " + emailList.name;
                $scope.errorMessage = "";
            }
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.showEmailAddresses = function(emailList){
        if ("showEmailAddresses" in emailList){
            emailList.showEmailAddresses = !emailList.showEmailAddresses;
        }
        else {
            emailList.showEmailAddresses = true;
        }
    };

    $scope.addNewEmail = function(emailList){
        if (!emailList.newEmailAddress) return;
        emailList.newEmailError = null;
        emailList.newEmailLoading = true;
        var addEmailUrl = tfEncoder.encode("/configuration/emailLists/" + emailList.id + "/addEmail");
        $http.post(addEmailUrl, {"emailAddress": emailList.newEmailAddress}).
            success(function(data, status, headers, config) {
                if (data.success) {
                    emailList.newEmailAddress = null;

                    if (!emailList.emailAddresses) {
                        emailList.emailAddresses = [ data.object ];
                    } else {
                        threadFixModalService.addElement(emailList.emailAddresses, data.object);
                    }
                }
                else {
                    emailList.newEmailError = data.message;
                }
            }).
            error(function(data, status, headers, config) {
                $scope.error = "Failure. HTTP status was " + status;
            });
        emailList.newEmailLoading = false;
    };

    $scope.deleteEmailAddress = function(emailList, emailAddress){
        if (confirm("Delete this email address?")) {
            emailList.newEmailLoading = true;
            var deleteUrl = tfEncoder.encode("/configuration/emailLists/" + emailList.id + "/deleteEmail");
            $http.post(deleteUrl, {"emailAddress": emailAddress}).
                success(function(data, status, headers, config) {
                    if (data.success) {
                        $scope.successMessage = "Successfully deleted email address " + emailAddress;
                        threadFixModalService.deleteElement(emailList.emailAddresses, emailAddress);
                    }
                    else {
                        $scope.errorMessage = "Failure. Message was : " + data.message;
                    }
                }).
                error(function(data, status, headers, config) {
                    $scope.error = "Failure. HTTP status was " + status;
                });
            emailList.newEmailLoading = false;
        }
    };
});