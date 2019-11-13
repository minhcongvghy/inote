package com.codegym.inote.controller;

import com.codegym.inote.model.*;
import com.codegym.inote.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;


@Controller
public class UserController {

    private static final String USER_REGISTER = "/user/register";

    private static final String ERROR_404 = "/error-404";
    private static final String MESSAGE = "message";
    private static final String DEFAULT_ROLE = "ROLE_USER";

    @Autowired
    private UserService userService;

    @Autowired
    private RoleService roleService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private EmailService emailService;

    @Autowired
    private ConfirmationTokenService confirmationTokenService;

    @Autowired
    private SMSService smsService;

    @Autowired
    private RestFB restFB;


    @GetMapping("/register")
    public ModelAndView showRegisterForm() {
        ModelAndView modelAndView = new ModelAndView(USER_REGISTER);
        modelAndView.addObject("user", new User());
        return modelAndView;
    }

    @PostMapping("/register")
    public ModelAndView registerNewUser(@Valid @ModelAttribute User user, BindingResult bindingResult) {
        if (bindingResult.hasFieldErrors()) {
            return new ModelAndView(USER_REGISTER);
        }
        if (userService.isRegister(user)) {
            ModelAndView modelAndView = new ModelAndView(USER_REGISTER);
            modelAndView.addObject(MESSAGE, "username or email is already registered");
            return modelAndView;
        } else if (!userService.isCorrectConfirmPassword(user)) {
            ModelAndView modelAndView = new ModelAndView(USER_REGISTER);
            modelAndView.addObject(MESSAGE, "Confirm Password is incorrect");
            return modelAndView;
        } else {
            ModelAndView modelAndView = new ModelAndView("user/successfulRegister");
            Role role = roleService.findRoleByName(DEFAULT_ROLE);
            Set<Role> roles = new HashSet<>();
            roles.add(role);
            User currentUser = new User();
            currentUser.setUsername(user.getUsername());
            currentUser.setPassword(passwordEncoder.encode(user.getPassword()));
            currentUser.setConfirmPassword(passwordEncoder.encode(user.getConfirmPassword()));
            currentUser.setEmail(user.getEmail());
            currentUser.setPhoneNumber(user.getPhoneNumber());
            currentUser.setRoles(roles);
            userService.save(currentUser);
            ConfirmationToken token = new ConfirmationToken(currentUser);
            token.setExpiryDate(1);
            confirmationTokenService.save(token);
            SimpleMailMessage mailMessage = new SimpleMailMessage();
            mailMessage.setTo(user.getEmail());
            mailMessage.setSubject("Complete Registration!");
            mailMessage.setText("To confirm your account, please click here : "
                    + "http://localhost:8080/inote/confirm-account?token=" + token.getToken());

            emailService.sendEmail(mailMessage);
            modelAndView.addObject("user", currentUser);
            modelAndView.addObject("email", currentUser.getEmail());
            return modelAndView;
        }
    }

    @RequestMapping(value = "/confirm-account", method = {RequestMethod.GET, RequestMethod.POST})
    public ModelAndView confirmUserAccount(@RequestParam("token") String confirmationToken) {
        ModelAndView modelAndView;
        ConfirmationToken token = confirmationTokenService.findByToken(confirmationToken);
        if (token != null) {
            boolean isExpired = token.isExpired();
            if (!isExpired) {
                User user = userService.findByEmail(token.getUser().getEmail());
                user.setEnabled(true);
                userService.save(user);
                modelAndView = new ModelAndView("/user/accountVerified");
                return modelAndView;
            }
        }
        modelAndView = new ModelAndView("/user/error");
        modelAndView.addObject(MESSAGE, "The link is invalid or broken!");
        return modelAndView;
    }

    @GetMapping("/homepage")
    public ModelAndView home() {
        ModelAndView modelAndView = new ModelAndView("/user/homepage");
        modelAndView.addObject("user", userService.getCurrentUser());
        return modelAndView;
    }

    @GetMapping("/newPassword/{id}")
    public ModelAndView showEditForm(@PathVariable Long id, @RequestParam("token") String confirmationToken) {
        ConfirmationToken token = confirmationTokenService.findByToken(confirmationToken);
        if (token != null) {
            boolean isExpired = token.isExpired();
            if (!isExpired) {
                User user = userService.findById(id);
                if (user != null) {
                    ModelAndView modelAndView = new ModelAndView("user/newPassword");
                    modelAndView.addObject("user", user);
                    return modelAndView;
                }
            }
        } else {
            ModelAndView modelAndView = new ModelAndView("/user/error");
            modelAndView.addObject(MESSAGE, "The link is invalid or broken!");
            return modelAndView;
        }
        return new ModelAndView(ERROR_404);
    }

    @RequestMapping(value = "/newPassword", method = {RequestMethod.GET, RequestMethod.POST})
    public ModelAndView editUser(@ModelAttribute User user) {
        ModelAndView modelAndView = new ModelAndView("user/newPassword");
        if (!userService.isCorrectConfirmPassword(user)) {
            modelAndView.addObject(MESSAGE, "your confirm password is incorrect");
        } else {
            String newPassword = passwordEncoder.encode(user.getPassword());
            user = userService.findById(user.getId());
            user.setPassword(newPassword);
            userService.save(user);
            modelAndView.addObject("user", user);
            modelAndView.addObject(MESSAGE, "Your password is changed");
        }
        return modelAndView;
    }

    @GetMapping("/view/{id}")
    public ModelAndView viewUser(@PathVariable Long id) {
        User user = userService.findById(id);
        if (user == null) {
            return new ModelAndView(ERROR_404);
        }

        ModelAndView modelAndView = new ModelAndView("/user/view");
        modelAndView.addObject("user", user);
        return modelAndView;
    }

    @GetMapping("/login")
    public ModelAndView loginForm() {
        return new ModelAndView("/login");
    }

    @PostMapping("/login")
    public ModelAndView login(User user) {
        ModelAndView modelAndView;
        if (userService.checkLogin(user)) {
            modelAndView = new ModelAndView("/user/homepage");
            modelAndView.addObject("user", user);
            return modelAndView;
        }
        modelAndView = new ModelAndView("/login");
        modelAndView.addObject(MESSAGE, "username or password incorrect");
        return modelAndView;
    }

    @PostMapping("/login-facebook")
    public String loginFacebook(HttpServletRequest request) {
        String code = request.getParameter("code");
        String accessToken = "";
        try {
            accessToken = restFB.getToken(code);
        } catch (IOException e) {
            return "login?facebook=error";
        }
        com.restfb.types.User user = restFB.getUserInfo(accessToken);
        UserDetails userDetail = restFB.buildUser(user);
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetail, null,
                userDetail.getAuthorities());
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return "redirect:/login";
    }

    @GetMapping("/sendOTP")
    public ModelAndView showSMSForm() {
        ModelAndView modelAndView = new ModelAndView("/user/sendOTP");
        return modelAndView;
    }

    @PostMapping("/sendOTP")
    public ModelAndView sendSMS() {
        ModelAndView modelAndView = new ModelAndView("/user/inputOTP");
        modelAndView.addObject("otp", new CodeOTP());
        smsService.sendSMS();
        return modelAndView;
    }

    @GetMapping("/verifyOTPSuccess")
    public ModelAndView verifySuccess(@ModelAttribute CodeOTP otp) {
        return new ModelAndView("/user/verifyOTPSuccess");
    }
}
