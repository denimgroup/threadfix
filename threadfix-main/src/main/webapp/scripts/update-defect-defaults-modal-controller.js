var myAppModule = angular.module('threadfix');

// mostly a copy of DefectSubmissionModalController because we want the same behavior (would be better factorized, but would break easily forward compatibility with denim group code)
myAppModule.controller('UpdateDefectDefaultsModalController', function ($scope, $rootScope, $modalInstance, $http, threadFixModalService, configUrl, url, timeoutService) {

    $scope.focusInput = true;

    $scope.object = {};
    $scope.isDynamicForm = false;
    $scope.hasFields = true;

    $scope.config = {};

    $scope.initialized = false;

    timeoutService.timeout();

    $scope.fieldsMap = {};
    $scope.requiredErrorMap = {};
    $scope.valueMappingMap = {};
    $scope.stdFormTemplateOptions = {};
    $scope.validModels = {};

    $http.get(configUrl).
        success(function(data, status, headers, config) {
            timeoutService.cancel();

            if (data.success) {
                $scope.config = data.object.projectMetadata;
                $scope.config.typeName = data.object.defectTrackerName;
                if ($scope.config.typeName === 'HP Quality Center'
                    || $scope.config.typeName === 'JIRA'
                    || $scope.config.typeName === 'Jira'
                    || $scope.config.typeName === 'Version One'
                    || $scope.config.typeName === 'Microsoft TFS')
                    $scope.isDynamicForm = true;
                $scope.config.defectTrackerName = data.object.defectTrackerName;

                $scope.config.defects = data.object.defectList;

                if ($scope.config.defects && $scope.config.defects.length > 0) {
                    $scope.config.placeholder = $scope.config.defects[0];
                }

                if (!$scope.config.editableFields || !$scope.config.editableFields.length === 0) {
                    $scope.object.id = $scope.config.defects[0];
                    $scope.object.selectedComponent = $scope.config.components[0];
                    $scope.object.priority = $scope.config.priorities[0];
                    $scope.object.status = $scope.config.statuses[0];
                    $scope.object.version = $scope.config.versions[0];
                    $scope.object.severity = $scope.config.severities[0];
                } else {
                    //here retrieving the defaults tags and field for that profile, createSubmitForm() is called after successfully retrieving the default tags
                    getExistingDefaultsAndTags();
                }
            } else {
                $scope.initialized = true;
                // setting these two booleans will hide the form.
                $scope.hasFields = false;
                $scope.isDynamicForm = true;

                $scope.errorMessage = data.message;
            }
        }).
        error(function(data, status, headers, config) {
            timeoutService.cancel();
            $scope.initialized = true;
            $scope.errorMessage = "Failure. HTTP status was " + status;
        });

    var getExistingDefaultsAndTags = function(){
        $http.get(url).success(function(data, status, headers, config) {
            $scope.initialized = true;
            timeoutService.cancel();

            if (data.success) {
                $scope.defaultTags = data.object.defaultTags;
                createSubmitForm(); //need to load tags before creating the form, or there are missing values
                loadExistingDefaults(data.object.defaultDefectFields);
            }
            else {
                $scope.errorMessage = data.message;
            }
        });
    };

    var loadExistingDefaults = function(defaultDefectFields){
        defaultDefectFields.forEach(function(defaultField) {
            var fieldName = defaultField.fieldName;
            if (fieldName in $scope.validModels){
                var isSelectField = (fieldName in $scope.stdFormTemplateOptions);

                if (!defaultField.dynamicDefault){
                    //static could be a select, if the field is a select, we check the static value is a valid option
                    if (!isSelectField){
                        $scope.fieldsMap[fieldName] = defaultField.staticValue;
                    }
                    else if (defaultField.staticValue in $scope.stdFormTemplateOptions[fieldName]){
                        $scope.fieldsMap[fieldName] = defaultField.staticValue;
                    }
                }
                else {
                    if (!defaultField.valueMapping){
                        if (defaultField.defaultTag)
                            $scope.fieldsMap[fieldName] = "@" + defaultField.defaultTag.name;
                        else
                            $scope.fieldsMap[fieldName] = defaultField.dynamicValue;
                    }
                    //value mapping fields to populate with existing defaults
                    else {

                        // maintain original form inputted
                        if (defaultField.staticValue)
                            $scope.fieldsMap[fieldName] = defaultField.staticValue;

                        var tagName = defaultField.defaultTag.name
                        $scope.valueMappingMap[fieldName].selectedTag = tagName;
                        $scope.valueMappingMap[fieldName][tagName] = {};

                        var map = defaultField.valueMappingMap;
                        for (var key in map){
                            if (map[key] in $scope.stdFormTemplateOptions[fieldName]){ //check if the select option exists in the form
                                $scope.valueMappingMap[fieldName][tagName][key] = map[key];
                            }
                        }
                    }
                }
            }
        });
    };

    $scope.ok = function (form) {
        var resultFieldsMap = angular.copy($scope.fieldsMap); //cloning this object to get rid of data-binding when modification
        for(var fieldName in $scope.valueMappingMap){
            var selectedTagName = $scope.valueMappingMap[fieldName]['selectedTag'];
            if (selectedTagName){
                valueMapping = $scope.valueMappingMap[fieldName][selectedTagName];
                if(Object.keys(valueMapping).length){ //check if the value mapping on the tag is not empty
                    resultFieldsMap[fieldName] = {"tagName":selectedTagName, "valueMapping":valueMapping,
                    "staticDisplayValue" : resultFieldsMap[fieldName]};  // "staticDisplayValue" saves this value to maintain original form inputted
                }
            }
        }
        $scope.object.fieldsMapStr = JSON.stringify(resultFieldsMap);
        threadFixModalService.post(url, $scope.object).
        success(function(data, status, headers, config) {
            timeoutService.cancel();
            $scope.loading = false;

            if (data.success) {
                $modalInstance.close(data.object);
            } else {
                $scope.errorMessage = "Failure. Message was : " + data.message;
            }
        }).
        error(function(data, status, headers, config) {
            timeoutService.cancel();
            $scope.loading = false;
            $scope.errorMessage = "Failure. HTTP status was " + status;
        });
    };

    $scope.cancel = function () {
        timeoutService.cancel();
        $modalInstance.dismiss('cancel');
    };

    var createSubmitForm = function() {
        $scope.stdFormTemplate = [];
        $scope.config.editableFields.forEach(function(field) {
            var type = calculateType(field.type);

            var fieldForm =  {
                "model" : field.name,
                "type" : type,
                "label" : field.required ? field.label + " *" : field.label,
                "labelClass" : field.required ? "errors" : null,
                "options" : calculateOptions(field),
                "multiple" : field.supportsMultivalue,
                //"val" : field.value,
            };

            if (!field.required) {
                fieldForm.empty = "Select";
            }

            if (field.placeholder) {
                fieldForm.placeholder = field.placeholder;
            }

            if (field.validate) {
                fieldForm.validate = field.validate;
            }

            if (field.errorsMap) {
                fieldForm.errorsMap = field.errorsMap;
            }

            if (field.show) {
                fieldForm.show = field.show;
            }
            if (type === "text")
                fieldForm.maxLength = field.maxLength;

            if (type === "number") {
                if  (field.step)
                    fieldForm.step = field.step;
                if (field.minValue !== null)
                    fieldForm.minValue = field.minValue;
                if (field.maxValue !== null)
                    fieldForm.maxValue = field.maxValue;
            }

            if (type === "select") { //preparing model and variables for construction of a value mapping form
                $scope.valueMappingMap[field.name]={}; //preparing the map here to receive the model
                $scope.stdFormTemplateOptions[field.name]=fieldForm.options;

                var selectOptionsAttr = "stdFormTemplateOptions";
                var modelAttr = "valueMappingMap";
                var tagsListAttr = "defaultTags";
                fieldForm.attributes = {"default-value-mapping":field.name, "select-options":selectOptionsAttr, "model":modelAttr, "tags-list":tagsListAttr };

            }

            if (field.editable === false) {
                fieldForm.readonly = true;
            }

            $scope.validModels[field.name]=true;
            $scope.stdFormTemplate.push(fieldForm)
        });

        if ($scope.config.editableFields.length === 1) {
            $scope.errorMessage = "ThreadFix was unable to populate a submission form. Check your configuration.";
            $scope.hasFields = false;
        }
    }

    /**
     * This is to customize type names used in Defect Tracker system to supported type in Dynamic form angular
     * @param oldType
     * @returns {string}
     */
    var calculateType = function (oldType) {

        if (oldType) {
            var lowerCaseOldType = oldType.toLowerCase();

            if (lowerCaseOldType === "userslist" || lowerCaseOldType === "lookuplist" || lowerCaseOldType === "reference")
                return "select";
            else if (lowerCaseOldType === "string")
                return "text";
            else if (lowerCaseOldType === "memo")
                return "textarea";
            else if (lowerCaseOldType === "float")
                return "number";
            else
                return lowerCaseOldType;
        }

    };

    var calculateOptions = function (field) {
        var options = new Object();

        for (var key in field.optionsMap) {
            var value = {
                "label" : field.optionsMap[key]
            };
            options[key] = value;
        };
        return options;
    };
});