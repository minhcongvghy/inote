package com.codegym.inote.controller;

import com.codegym.inote.model.ConfirmationToken;
import com.codegym.inote.model.PasswordForgot;
import com.codegym.inote.model.User;
import com.codegym.inote.service.ConfirmationTokenService;
import com.codegym.inote.service.EmailService;
import com.codegym.inote.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.validation.Valid;
import java.util.UUID;

@Controller
public class ForgotPasswordController {
    @Autowired
    private UserService userService;

    @Autowired
    private EmailService emailService;

    @Autowired
    private ConfirmationTokenService tokenService;

    @GetMapping("/forgotPassword")
    public ModelAndView forgotPasswordForm(){
        ModelAndView modelAndView = new ModelAndView("/user/forgotPassword");
        modelAndView.addObject("passwordForgot",new PasswordForgot());
        return modelAndView;
    }

    @PostMapping("/forgotPassword")
    public ModelAndView forgotPassword(@Valid @ModelAttribute PasswordForgot passwordForgot, BindingResult bindingResult){
        if (bindingResult.hasFieldErrors()) {
            return new ModelAndView("/user/forgotPassword");
        }
        User user = userService.findByEmail(passwordForgot.getEmail());
        if(user == null){
            ModelAndView modelAndView = new ModelAndView("/error-404");
            modelAndView.addObject("message","your email isn't exist");
            return modelAndView;
        }
        ModelAndView modelAndView = new ModelAndView("/user/newPassword");
        modelAndView.addObject("passwordForgot",passwordForgot);
        ConfirmationToken token = new ConfirmationToken(user);
        token.setToken(UUID.randomUUID().toString());
        token.setExpiryDate(1);
        tokenService.save(token);
        SimpleMailMessage mailMessage = new SimpleMailMessage();
        mailMessage.setTo(user.getEmail());
        mailMessage.setSubject("You've successfully requested a new password reset!");
        mailMessage.setText("To change you password, please click here : "
                + "http://localhost:8080/inote/newPassword/" + user.getId()
                + "?token=" + token.getToken());

        emailService.sendEmail(mailMessage);
        return modelAndView;
    }
}
