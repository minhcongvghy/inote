package com.codegym.inote.service;

import com.codegym.inote.model.Stack;
import com.codegym.inote.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface StackService extends GeneralService<Stack> {
    Page<Stack> findAllByUser(User user, Pageable pageable);

}
