package com.codegym.inote.repository;

import com.codegym.inote.model.Stack;
import com.codegym.inote.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.PagingAndSortingRepository;

public interface StackRepository extends PagingAndSortingRepository<Stack, Long> {
    Page<Stack> findAllByUser(User user, Pageable pageable);

}
