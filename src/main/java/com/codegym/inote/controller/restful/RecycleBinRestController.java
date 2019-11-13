package com.codegym.inote.controller.restful;

import com.codegym.inote.model.Note;
import com.codegym.inote.model.Trash;
import com.codegym.inote.service.NoteService;
import com.codegym.inote.service.RecycleBinService;
import com.codegym.inote.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/restful")
public class RecycleBinRestController {
    @Autowired
    private RecycleBinService recycleBinService;

    @Autowired
    private UserService userService;

    @Autowired
    private NoteService noteService;

    @GetMapping("/trashes")
    public ResponseEntity<Page<Trash>> showAllTrashes(Pageable pageable) {
        Page<Trash> trashes = recycleBinService.findAllByUser(userService.getCurrentUser(), pageable);
        if (trashes.getTotalElements() == 0) {
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        }
        return new ResponseEntity<>(trashes, HttpStatus.OK);
    }

    @GetMapping("/trashes/{id}")
    public ResponseEntity<Trash> getTrash(@PathVariable Long id) {
        Trash trash = recycleBinService.findById(id);
        if (trash == null) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity<>(trash, HttpStatus.OK);
    }

    @DeleteMapping("/recovery/{id}")
    public ResponseEntity<Trash> recoverNote(@PathVariable Long id) {
        Trash trash = recycleBinService.findById(id);
        if (trash == null) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        Note note = new Note();
        note.setUser(trash.getUser());
        note.setTitle(trash.getTitle());
        note.setContentDelta(trash.getContentDelta());
        note.setContentHtml(trash.getContentHtml());
        note.setTime(trash.getTime());
        noteService.save(note);
        recycleBinService.remove(trash.getId());
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @DeleteMapping("/trashes/{id}")
    public ResponseEntity<Trash> deleteTrash(@PathVariable Long id) {
        Trash trash = recycleBinService.findById(id);
        if (trash == null) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        recycleBinService.remove(trash.getId());
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }


}
