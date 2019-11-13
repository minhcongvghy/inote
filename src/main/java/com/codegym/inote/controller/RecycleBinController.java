package com.codegym.inote.controller;

import com.codegym.inote.model.Note;
import com.codegym.inote.model.Trash;
import com.codegym.inote.model.User;
import com.codegym.inote.service.NoteService;
import com.codegym.inote.service.RecycleBinService;
import com.codegym.inote.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

@Controller
@RequestMapping("/recycleBin")
public class RecycleBinController {

    private static final String ERROR_404 = "/error-404";
    private static final String TRASH = "trash";

    @Autowired
    private RecycleBinService recycleBinService;

    @Autowired
    private NoteService noteService;

    @Autowired
    private UserService userService;

    @ModelAttribute("user")
    public User user() {
        return userService.getCurrentUser();
    }

    @GetMapping("/trashes/{id}")
    public ModelAndView recycleBin(Pageable pageable,@PathVariable Long id) {
        Page<Trash> trashes = recycleBinService.findAllByUser(userService.getCurrentUser(), pageable);

        ModelAndView modelAndView = new ModelAndView("/recycleBin/list");
        modelAndView.addObject("trashes", trashes);
        modelAndView.addObject("user", userService.getCurrentUser());
        return modelAndView;
    }

    @GetMapping("/recovery/{id}/{userId}")
    public ModelAndView recoveryForm(@PathVariable Long id,@PathVariable Long userId) {
        Trash trash = recycleBinService.findById(id);
        if (trash != null) {
            ModelAndView modelAndView = new ModelAndView("/recycleBin/recovery");
            modelAndView.addObject(TRASH, trash);
            modelAndView.addObject("user", userService.getCurrentUser());
            return modelAndView;
        }
        return new ModelAndView(ERROR_404);
    }

    @PostMapping("/recovery")
    public String recoverNote(@ModelAttribute Trash trash) {
        Trash currentTrash = recycleBinService.findById(trash.getId());
        Note note = new Note();
        note.setTitle(currentTrash.getTitle());
        note.setContentHtml(currentTrash.getContentHtml());
        note.setContentDelta(currentTrash.getContentDelta());
        note.setUser(currentTrash.getUser());
        note.setTime(currentTrash.getTime());
        noteService.save(note);
        recycleBinService.remove(trash.getId());
        ModelAndView modelAndView = new ModelAndView("/recycleBin/recovery");
        modelAndView.addObject(TRASH, trash);
        modelAndView.addObject("note", note);
        return "redirect:/recycleBin/trashes/"+ userService.getCurrentUser().getId();
    }

    @GetMapping("/delete/{id}/{userId}")
    public ModelAndView showDeleteForm(@PathVariable Long id,@PathVariable Long userId) {
        Trash trash = recycleBinService.findById(id);
        if (trash != null) {
            ModelAndView modelAndView = new ModelAndView("/recycleBin/delete");
            modelAndView.addObject(TRASH, trash);
            modelAndView.addObject("user", userService.getCurrentUser());
            return modelAndView;
        }
        return new ModelAndView(ERROR_404);
    }

    @PostMapping("/delete")
    public String deleteNoteType(@ModelAttribute Trash trash) {
        recycleBinService.remove(trash.getId());
        return "redirect:/recycleBin/trashes/"+ userService.getCurrentUser().getId();
    }

    @GetMapping("/view/{id}/{userId}")
    public ModelAndView viewNote(@PathVariable Long id, @PathVariable Long userId) {
        Trash trash = recycleBinService.findById(id);
        if (trash == null) {
            return new ModelAndView(ERROR_404);
        }

        ModelAndView modelAndView = new ModelAndView("/recycleBin/view");
        modelAndView.addObject("user", userService.getCurrentUser());
        modelAndView.addObject(TRASH, trash);
        return modelAndView;
    }
}
