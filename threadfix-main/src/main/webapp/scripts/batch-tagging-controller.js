var module = angular.module('threadfix')

module.controller('BatchTaggingController', function($scope, $http, $modal, $log, tfEncoder){

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    $scope.$on('rootScopeInitialized', function() {
        $scope.initialized = false;
        $scope.selectedApplications = [];
        $scope.selectedTags = [];
        $http.get(tfEncoder.encode('/configuration/tags/batchTagging/map')).
            success(function(data) {
                if (data.success) {
                    $scope.tags = data.object.tags;
                    $scope.applications = data.object.applications;

                    $scope.tags.sort(nameCompare);
                    if ($scope.tagIds) {
                        var idList = $scope.tagIds.split("-");
                        idList.forEach(function(id){
                            $scope.tags.forEach(function(tag){
                                if (tag.id == id)
                                    $scope.selectedTags.push(tag);
                            })
                        });
                        $scope.selectedTags.sort(nameCompare);
                    }
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }
                $scope.initialized = true;
            }).
            error(function(data, status, headers, config) {
                $scope.initialized = true;
                $scope.errorMessage = "Failed to retrieve waf list. HTTP status was " + status;
            });




        if ($scope.tagIds)
            $log.info($scope.tagIds);
        else {
            $log.info("balbal");
        }
    });

    $scope.addNew = function(collection, newElement) {
        var found = false;
        collection.forEach(function (item) {
            if (item && item.id === newElement.id) {
                found = true;
            }
        });

        if (!found) {
            collection.push(newElement);
        }
        collection.sort(nameCompare);
    };

    $scope.remove = function(collection, index) {
        collection.splice(index, 1);
    };

    $scope.submitBatchTag = function(){
        $scope.submitObj = {
            applications: $scope.selectedApplications,
            tags: $scope.selectedTags
        };

        $scope.submitting = true;

        var url = tfEncoder.encode("/configuration/tags/batchTagging/submit");

        $http.post(url, $scope.submitObj).
            success(function(data, status, headers, config) {
                $scope.submitting = false;

                if (data.success) {
                    $scope.successMessage = data.object;
                    $scope.error = null;
                    $scope.selectedApplications = [];
                    $scope.selectedTags = [];
                } else {
                    $scope.error = "Failure. Message was : " + data.message;
                }
            }).
            error(function(data, status, headers, config) {
                $scope.submitting = false;
                $scope.error = "Failure. HTTP status was " + status;
            });
    }

});