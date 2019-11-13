package com.codegym.inote.service.impl;

import com.codegym.inote.model.Role;
import com.codegym.inote.repository.RoleRepository;
import com.codegym.inote.service.RoleService;
import org.springframework.beans.factory.annotation.Autowired;

public class RoleServiceImpl implements RoleService {

    @Autowired
    private RoleRepository roleRepository;

    @Override
    public Role findRoleByName(String roleName) {
        return roleRepository.findRoleByName(roleName);
    }
}
