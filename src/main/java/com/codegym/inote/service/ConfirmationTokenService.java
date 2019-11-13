package com.codegym.inote.service;

import com.codegym.inote.model.ConfirmationToken;

public interface ConfirmationTokenService {
    ConfirmationToken findByToken(String token);

    void save(ConfirmationToken confirmationToken);
}
