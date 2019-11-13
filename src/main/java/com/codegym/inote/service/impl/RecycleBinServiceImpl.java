package com.codegym.inote.service.impl;

import com.codegym.inote.model.Note;
import com.codegym.inote.model.Trash;
import com.codegym.inote.model.User;
import com.codegym.inote.repository.RecycleBinRepository;
import com.codegym.inote.service.NoteService;
import com.codegym.inote.service.RecycleBinService;
import com.codegym.inote.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public class RecycleBinServiceImpl implements RecycleBinService {

    @Autowired
    private RecycleBinRepository recycleBinRepository;

    @Autowired
    private UserService userService;

    @Autowired
    private NoteService noteService;

    @Override
    public Page<Trash> findAll(Pageable pageable) {
        return recycleBinRepository.findAll(pageable);
    }

    @Override
    public Trash findById(Long id) {
        return recycleBinRepository.findOne(id);
    }

    @Override
    public void save(Trash model) {
        recycleBinRepository.save(model);
    }

    @Override
    public void remove(Long id) {
        recycleBinRepository.delete(id);
    }

    @Override
    public Page<Trash> findAllByUser(User user, Pageable pageable) {
        return recycleBinRepository.findAllByUser(user, pageable);
    }

    @Override
    public Trash addNoteToRecycleBin(Note note) {
        Trash trash = new Trash();
        trash.setTitle(note.getTitle());
        trash.setContentHtml(note.getContentHtml());
        trash.setContentDelta(note.getContentDelta());
        trash.setUser(userService.getCurrentUser());
        trash.setTime(note.getTime());
        this.save(trash);
        noteService.remove(note.getId());
        return trash;
    }

}
