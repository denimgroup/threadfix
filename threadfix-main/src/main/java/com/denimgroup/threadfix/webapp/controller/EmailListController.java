////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////

package com.denimgroup.threadfix.webapp.controller;

import com.denimgroup.threadfix.data.entities.EmailList;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.EmailListService;
import com.denimgroup.threadfix.service.email.EmailFilterService;
import com.denimgroup.threadfix.webapp.config.FormRestResponse;
import com.denimgroup.threadfix.webapp.utils.MessageConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;

/**
 * @author zabdisubhan
 */
@Controller
//@SessionAttributes({"user", "role", "editRole"})
@RequestMapping("/configuration/emailLists")
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_EMAIL_REPORTS')")
public class EmailListController {

    @Autowired
    private EmailListService emailListService;
    @Autowired
    private EmailFilterService emailFilterService;

    private final SanitizedLogger log = new SanitizedLogger(EmailListController.class);

    @RequestMapping(method = RequestMethod.GET)
    public String index() {
        log.info("Directing to email lists index page.");
        return "config/emailLists/index";
    }

    @RequestMapping(value = "/map", method = RequestMethod.GET)
    public @ResponseBody
    RestResponse<Map<String, Object>> emailListMap() {
        Map<String, Object> responseMap = map();
        responseMap.put("emailLists", emailListService.loadAllActive());
        return RestResponse.success(responseMap);
    }

    @RequestMapping(value = "/new", method = RequestMethod.POST)
    public @ResponseBody RestResponse<EmailList> newSubmit(@Valid @ModelAttribute EmailList emailList,
                                                     BindingResult result) {

        if (result.hasErrors()) {
            return FormRestResponse.failure("error", result);
        } else {
            if (emailList.getName().trim().equals("")) {
                result.rejectValue("name", null, null, "This field cannot be blank");
            }
            if (emailListService.nameExists(emailList.getName())) {
                result.rejectValue("name", null, null, "This name already exists");
            }
            if (result.hasErrors()) {
                return FormRestResponse.failure("error", result);
            }

            log.info("Saving new Email List " + emailList.getName());
            emailListService.saveOrUpdate(emailList);
            return RestResponse.success(emailList);
        }
    }

    @RequestMapping(value = "/{emailListId}/edit", method = RequestMethod.POST)
    public @ResponseBody RestResponse<Map<String, Object>> editSubmit(@PathVariable("emailListId") int emailListId,
                                                                      @Valid @ModelAttribute EmailList emailList,
                                                                      BindingResult result) {
        if (result.hasErrors()) {
            return FormRestResponse.failure("error", result);
        } else {
            EmailList databaseEmailList = null;

            if (emailList.getName().trim().equals("")) {
                result.rejectValue("name", null, null, "This field cannot be blank");
            } else {
                databaseEmailList = emailListService.loadByName(emailList.getName().trim());
                if (databaseEmailList != null && !databaseEmailList.getId().equals(emailListId)) {
                    result.rejectValue("name", MessageConstants.ERROR_NAMETAKEN);
                }
                databaseEmailList = emailListService.loadById(emailListId);
            }

            if (result.hasErrors()) {
                return FormRestResponse.failure("error", result);
            }

            if (databaseEmailList != null) {
                Map<String, Object> resultMap = map();
                log.info("Editing EmailList " + databaseEmailList.getName() + " to " + emailList.getName());
                databaseEmailList.setName(emailList.getName());
                emailListService.saveOrUpdate(databaseEmailList);
                resultMap.put("emailLists", emailListService.loadAll());
                return RestResponse.success(resultMap);
            } else {
                return RestResponse.failure("Error occurs.");
            }
        }
    }

    @RequestMapping(value = "/{emailListId}/delete", method = RequestMethod.POST)
    public @ResponseBody RestResponse<EmailList> deleteSubmit(@PathVariable("emailListId") int emailListId) {
        EmailList emailList = emailListService.loadById(emailListId);

        if (emailList != null) {
            emailListService.markInactive(emailList);
            return RestResponse.success(null);
        } else {
            log.warn("EmailList Id is invalid or EmailList currently can not be deleted.");
            return RestResponse.failure("EmailList Id is invalid or EmailList currently can not be deleted.");
        }
    }

    @RequestMapping(value = "/{emailListId}/addEmail", method = RequestMethod.POST)
    public @ResponseBody RestResponse<String> addEmailAddress(
            @PathVariable("emailListId") int emailListId,
            @RequestParam("emailAddress") String emailAddress) {

        EmailList emailList = emailListService.loadById(emailListId);
        if (emailList == null) {
            return RestResponse.failure("Invalid email list.");
        }
        List<String> emailAddresses = emailList.getEmailAddresses();
        if (emailAddresses.contains(emailAddress)){
            return RestResponse.failure("Email address already exists.");
        }
        if (!emailFilterService.validateEmailAddress(emailAddress)){
            return RestResponse.failure("Email address doesn't comply with filter");
        }
        else {
            return RestResponse.success(emailListService.addEmailAddress(emailList, emailAddress));
        }
    }

    @RequestMapping(value = "/{emailListId}/deleteEmail", method = RequestMethod.POST)
    public @ResponseBody RestResponse<String> deleteEmailAddress(
            @PathVariable("emailListId") int emailListId,
            @RequestParam("emailAddress") String emailAddress) {

        EmailList emailList = emailListService.loadById(emailListId);
        if (emailList == null) {
            return RestResponse.failure("Invalid email report.");
        }
        List<String> emailAddresses = emailList.getEmailAddresses();
        if (emailAddresses.contains(emailAddress)){
            return RestResponse.success(emailListService.removeEmailAddress(emailList, emailAddress));
        }
        else {
            return RestResponse.failure("Invalid email address.");
        }
    }
}
