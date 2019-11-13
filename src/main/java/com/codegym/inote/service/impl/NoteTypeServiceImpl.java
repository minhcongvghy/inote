package com.codegym.inote.service.impl;

import com.codegym.inote.model.NoteType;
import com.codegym.inote.model.Stack;
import com.codegym.inote.model.User;
import com.codegym.inote.repository.NoteTypeRepository;
import com.codegym.inote.service.NoteTypeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public class NoteTypeServiceImpl implements NoteTypeService {

    @Autowired
    private NoteTypeRepository noteTypeRepository;

    @Override
    public Page<NoteType> findAll(Pageable pageable) {
        return noteTypeRepository.findAll(pageable);
    }

    @Override
    public NoteType findById(Long id) {
        return noteTypeRepository.findOne(id);
    }

    @Override
    public void save(NoteType model) {
        noteTypeRepository.save(model);
    }

    @Override
    public void remove(Long id) {
        noteTypeRepository.delete(id);
    }

    @Override
    public Page<NoteType> findNoteTypeByName(String name, Pageable pageable) {
        return noteTypeRepository.findNoteTypeByName(name, pageable);
    }

    @Override
    public Page<NoteType> findNoteTypeByStack(Stack stack, Pageable pageable) {
        return noteTypeRepository.findNoteTypeByStack(stack, pageable);
    }

    @Override
    public Page<NoteType> findAllByUser(User user, Pageable pageable) {
        return noteTypeRepository.findAllByUser(user, pageable);
    }
}
