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

package code.spring;

import com.github.elvan.ticketline.domain.Project;
import com.github.elvan.ticketline.domain.Ticket;
import com.github.elvan.ticketline.repository.ProjectRepository;
import com.github.elvan.ticketline.repository.TicketRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;
import javax.validation.Valid;

@Controller
@RequestMapping("/projects")
public class ProjectsController {

  @RequestMapping(value = "/add1", method = RequestMethod.POST)
  public String add(
      @Valid final Project project,
      final BindingResult result,
      final Model model,
      final RedirectAttributes redirectAttrs) {

    return "projects/add";
  }

  @RequestMapping(value = "/add2", method = RequestMethod.POST)
  public String add(
      @ModelAttribute Project project,
      final BindingResult result,
      final Model model,
      final RedirectAttributes redirectAttrs) {

    return "projects/add";
  }

  @RequestMapping(value = "/add3", method = RequestMethod.POST)
  public String add(
      @ModelAttribute final Project project,
      final BindingResult result,
      final Model model,
      final RedirectAttributes redirectAttrs) {

    return "projects/add";
  }

  @RequestMapping(value = "/add4", method = RequestMethod.POST)
  public String add(
      @ModelAttribute @Valid final Project project,
      BindingResult result,
      final Model model,
      final RedirectAttributes redirectAttrs) {

    return "projects/add";
  }

  @RequestMapping(value = "/add5", method = RequestMethod.POST)
  public String add(
      Project project,
      BindingResult result,
      Model model,
      final RedirectAttributes redirectAttrs) {

    return "projects/add";
  }

  @RequestMapping(value = "/add6", method = RequestMethod.POST)
  public String add(
      @ModelAttribute final Project project,
      BindingResult result,
      final Model model,
      final RedirectAttributes redirectAttrs) {

    return "projects/add";
  }

  @RequestMapping(value = "/add7", method = RequestMethod.POST)
  public String add(
      @Valid final Project project,
      BindingResult result,
      final Model model,
      final RedirectAttributes redirectAttrs) {

    return "projects/add";
  }

}
