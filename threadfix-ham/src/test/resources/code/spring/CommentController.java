package code.spring;

import it.redoddity.mvc.models.Comment;
import it.redoddity.mvc.services.PostService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.io.IOException;
import java.util.List;

@Controller
@RequestMapping("/blog/{postId}/comment")
public class CommentController {
    @Autowired
    PostService postService;

    @RequestMapping(method = RequestMethod.GET, produces = {"application/json"})
    @ResponseStatus(HttpStatus.OK)
    public @ResponseBody List<Comment> comments(@PathVariable Long postId) throws IOException {
        return postService.find(postId).getComments();
    }

    @RequestMapping(method = RequestMethod.POST, produces = {"text/html"})
    public String commentWithView(@PathVariable Long postId, @Valid Comment comment, BindingResult result, ModelMap model) throws IOException {
        if(!result.hasErrors()) {
            postService.addComment(postId, comment);
            return "redirect:/blog/"+ postId;
        } else {
            model.addAttribute("post", postService.find(postId));
            model.addAttribute("errors", result);
            return "post";
        }
    }

    @RequestMapping(method = RequestMethod.POST, produces = {"application/json"})
    @ResponseStatus(HttpStatus.CREATED)
    public Comment comment(@PathVariable Long postId, @Valid Comment comment, BindingResult result, HttpServletResponse response) throws IOException {
        if(!result.hasErrors()) {
            return postService.addComment(postId, comment);
        } else {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return null;
        }
    }
}
