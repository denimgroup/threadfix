var threadfixModule = angular.module('threadfix')

threadfixModule.directive('defaultValueMapping', function($compile) {
	return {
		restrict: 'A',
		scope: true,
		//controller's purpose is to build the tagFormTemplate according to the select Field
		controller: function($scope, $attrs){
			//retrieving necessary stuff from parent
			var fieldName = $attrs.defaultValueMapping;
			fieldOptions = $scope[$attrs.selectOptions][fieldName];
			subModel = $scope[$attrs.model][fieldName];
			tagsList = $scope[$attrs.tagsList];

			$scope.tagFormTemplate = [];
			$scope.valueMappingTagsNames = [];
			tagsList.forEach(function(tag) {
				if (tag.valueMapping){
					$scope.valueMappingTagsNames.push(tag.name);
					if (!(tag.name in subModel)) subModel[tag.name]={}; //prepare the deeper nesting for the dynamic form

					tag.valueMappingFields.forEach(function(valueMappingField) {
						var fieldForm =  {
								"model" : tag.name + "']['" + valueMappingField,   //This comes from hacking the dynamic-form directive to nest further the model
								"type" : "select",
								"show" : "selectedTag='" + tag.name + "'",
								"label" : valueMappingField,
								"options" : fieldOptions,
								"empty" : "---"
						};
						$scope.tagFormTemplate.push(fieldForm);
					});
				}
			});
			var tagSelector = {
					"model" : "selectedTag",
					"type" : "select",
					"autoOptions" : "tag as tag for tag in valueMappingTagsNames", //this constructs automatically the options object for the selector
					"empty" : "choose tag",
					"label" : "value mapping on"
			};
			$scope.tagFormTemplate.unshift(tagSelector); //prepend the selector to the cases fields
		},
		//at link time we generate a dynamic form with the template and the model prepared
		link: function(scope, element, attrs){
			var ngModelAttr = attrs.model + "['" + attrs.defaultValueMapping + "']";
			var e = $compile('<div class="nested-dynamic-form-wrapper"><dynamic-form ng-if="tagFormTemplate" template="tagFormTemplate" ng-model="'+ngModelAttr+'"></dynamic-form></div>')(scope);
			element.append(e);
		}
	}
});