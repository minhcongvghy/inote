package com.codegym.inote.controller;

import com.codegym.inote.model.Note;
import com.codegym.inote.model.Tag;
import com.codegym.inote.model.User;
import com.codegym.inote.service.NoteService;
import com.codegym.inote.service.TagService;
import com.codegym.inote.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import java.util.Optional;

@Controller
@RequestMapping("/tag")
public class TagController {

    private static final String ERROR_404 = "/error-404";

    @Autowired
    private TagService tagService;

    @Autowired
    private NoteService noteService;

    @Autowired
    private UserService userService;

    @ModelAttribute("user")
    public User user() {
        return userService.getCurrentUser();
    }

    @GetMapping("/tags/{id}")
    public ModelAndView showAllTag(@PathVariable Long id, @RequestParam("search") Optional<String> search, Pageable pageable) {
        Page<Tag> tags;

        if (search.isPresent()) {
            tags = tagService.findTagByName(search.get(), pageable);
        } else {
            tags = tagService.findAllByUser(userService.getCurrentUser(), pageable);
        }

        ModelAndView modelAndView = new ModelAndView("/tag/list");
        modelAndView.addObject("tags", tags);
        modelAndView.addObject("user", userService.getCurrentUser());
        return modelAndView;
    }

    @GetMapping("/create/{id}")
    public ModelAndView showCreateForm(@PathVariable Long id) {
        ModelAndView modelAndView = new ModelAndView("/tag/create");
        modelAndView.addObject("tag", new Tag());
        modelAndView.addObject("user", userService.getCurrentUser());
        return modelAndView;
    }

    @PostMapping("/create")
    public ModelAndView saveTag(@ModelAttribute Tag tag) {
        tag.setUser(userService.getCurrentUser());
        tagService.save(tag);
        ModelAndView modelAndView = new ModelAndView("/tag/create");
        modelAndView.addObject("tag", new Tag());
        modelAndView.addObject("message", "Created!");
        return modelAndView;
    }

    @GetMapping("/edit/{id}/{userId}")
    public ModelAndView showEditForm(@PathVariable Long id,@PathVariable Long userId) {
        Tag tag = tagService.findById(id);
        if (tag != null) {
            ModelAndView modelAndView = new ModelAndView("/tag/edit");
            modelAndView.addObject("tag", tag);
            modelAndView.addObject("user", userService.getCurrentUser());
            return modelAndView;
        }
        return new ModelAndView(ERROR_404);
    }

    @PostMapping("/edit")
    public ModelAndView updateTag(@ModelAttribute Tag tag) {
        tag.setUser(userService.getCurrentUser());
        tagService.save(tag);
        ModelAndView modelAndView = new ModelAndView("/tag/edit");
        modelAndView.addObject("tag", tag);
        modelAndView.addObject("message", "Updated!");
        return modelAndView;
    }

    @GetMapping("/delete/{id}/{userId}")
    public ModelAndView showDeleteForm(@PathVariable Long id,@PathVariable Long userId) {
        Tag tag = tagService.findById(id);
        if (tag != null) {
            ModelAndView modelAndView = new ModelAndView("/tag/delete");
            modelAndView.addObject("tag", tag);
            modelAndView.addObject("user", userService.getCurrentUser());
            return modelAndView;
        }
        return new ModelAndView(ERROR_404);
    }

    @PostMapping("/delete")
    public String deleteTag(@ModelAttribute Tag tag, Pageable pageable) {
        Tag currentTag = tagService.findById(tag.getId());
        Page<Note> notes = noteService.findAllByTags(currentTag, pageable);
        for (Note note : notes
        ) {
            note.setTags(null);
            noteService.save(note);
        }
        tagService.remove(tag.getId());
        return "redirect:/tag/tags/"+ userService.getCurrentUser().getId();
    }

    @GetMapping("/view/{id}/{userId}")
    public ModelAndView viewTag(@PathVariable Long id, Pageable pageable,@PathVariable Long userId) {
        Tag tag = tagService.findById(id);
        if (tag == null) {
            return new ModelAndView(ERROR_404);
        }
        Page<Note> notes = noteService.findAllByTags(tag, pageable);
        ModelAndView modelAndView = new ModelAndView("/tag/view");
        modelAndView.addObject("tag", tag);
        modelAndView.addObject("notes", notes);
        modelAndView.addObject("user", userService.getCurrentUser());
        return modelAndView;
    }
}
