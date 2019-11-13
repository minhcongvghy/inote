package com.codegym.inote.controller.restful;

import com.codegym.inote.model.Note;
import com.codegym.inote.service.NoteService;
import com.codegym.inote.service.RecycleBinService;
import com.codegym.inote.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Date;

@RestController
@RequestMapping("/restful")
public class NoteRestController {

    @Autowired
    private NoteService noteService;

    @Autowired
    private UserService userService;

    @Autowired
    private RecycleBinService recycleBinService;


    @GetMapping("/notes")
    public ResponseEntity<Page<Note>> showAllNote(Pageable pageable) {
        Page<Note> notes = noteService.findAllByUser(userService.getCurrentUser(), pageable);
        if (notes.getTotalElements() == 0) {
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        }
        return new ResponseEntity<>(notes, HttpStatus.OK);
    }

    @GetMapping(value = "/notes/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Note> getNote(@PathVariable Long id) {
        Note note = noteService.findById(id);
        if (note == null) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity<>(note, HttpStatus.OK);
    }

    @PostMapping(value = "/notes")
    public ResponseEntity<String> createNote(@RequestBody Note note) {
        note.setUser(userService.getCurrentUser());
        long millis = System.currentTimeMillis();
        Date date = new Date(millis);
        note.setTime(date);
        noteService.save(note);
        return new ResponseEntity<>("Created!", HttpStatus.CREATED);
    }

    @PutMapping("/notes/{id}")
    public ResponseEntity<Note> updateNote(@PathVariable Long id, @RequestBody Note note) {
        Note currentNote = noteService.findById(id);
        if (currentNote == null) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        long millis = System.currentTimeMillis();
        Date date = new Date(millis);
        currentNote.setTitle(note.getTitle());
        currentNote.setContentDelta(note.getContentDelta());
        currentNote.setContentHtml(note.getContentHtml());
        currentNote.setUser(note.getUser());
        currentNote.setTime(date);
        currentNote.setNoteType(note.getNoteType());
        currentNote.setTags(note.getTags());
        noteService.save(currentNote);
        return new ResponseEntity<>(currentNote, HttpStatus.OK);
    }

    @DeleteMapping("/notes/{id}")
    public ResponseEntity<Note> deleteNote(@PathVariable Long id) {
        Note note = noteService.findById(id);
        if (note == null) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        recycleBinService.addNoteToRecycleBin(note);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }
}
