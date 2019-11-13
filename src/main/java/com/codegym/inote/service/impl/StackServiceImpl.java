package com.codegym.inote.service.impl;

import com.codegym.inote.model.Stack;
import com.codegym.inote.model.User;
import com.codegym.inote.repository.StackRepository;
import com.codegym.inote.service.StackService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public class StackServiceImpl implements StackService {

    @Autowired
    private StackRepository stackRepository;

    @Override
    public Page<Stack> findAll(Pageable pageable) {
        return stackRepository.findAll(pageable);
    }

    @Override
    public Stack findById(Long id) {
        return stackRepository.findOne(id);
    }

    @Override
    public void save(Stack model) {
        stackRepository.save(model);
    }

    @Override
    public void remove(Long id) {
        stackRepository.delete(id);
    }

    @Override
    public Page<Stack> findAllByUser(User user, Pageable pageable) {
        return stackRepository.findAllByUser(user, pageable);
    }
}
