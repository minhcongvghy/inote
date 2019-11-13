package com.codegym.inote.service;

import com.codegym.inote.model.Role;

public interface RoleService {
    Role findRoleByName(String roleName);
}
