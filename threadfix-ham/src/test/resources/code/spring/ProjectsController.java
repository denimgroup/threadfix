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
