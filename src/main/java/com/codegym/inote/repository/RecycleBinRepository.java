package com.codegym.inote.repository;

import com.codegym.inote.model.Trash;
import com.codegym.inote.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.PagingAndSortingRepository;

public interface RecycleBinRepository extends PagingAndSortingRepository<Trash, Long> {
    Page<Trash> findAllByUser(User user, Pageable pageable);
}
