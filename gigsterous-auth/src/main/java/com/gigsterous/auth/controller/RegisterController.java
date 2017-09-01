package com.gigsterous.auth.controller;

import com.gigsterous.auth.model.User;
import com.gigsterous.auth.repository.UserRepository;
import com.gigsterous.auth.service.EmailService;

import java.util.Map;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Controller
public class RegisterController {

	private BCryptPasswordEncoder bCryptPasswordEncoder;
	private UserRepository userRepository;
	private EmailService emailService;

	@Autowired
	public RegisterController(BCryptPasswordEncoder bCryptPasswordEncoder, UserRepository userRepository,
			EmailService emailService) {

		this.bCryptPasswordEncoder = bCryptPasswordEncoder;
		this.userRepository = userRepository;
		this.emailService = emailService;
	}

	// Return registration form template
	@RequestMapping(value = "/register", method = RequestMethod.GET)
	public ModelAndView showRegistrationPage(ModelAndView modelAndView, User user) {
		modelAndView.addObject("user", user);
		modelAndView.setViewName("register");
		return modelAndView;
	}

	// Process form input data
	@RequestMapping(value = "/register", method = RequestMethod.POST)
	public ModelAndView processRegistrationForm(ModelAndView modelAndView, @Valid User user,
			BindingResult bindingResult, HttpServletRequest request) {
		log.debug("User registration - POST");

		// Lookup user in database by e-mail
		User userExists = userRepository.findOneByEmail(user.getUsername());

		if (userExists != null) {
			log.warn("This user already exists.", userExists);

			modelAndView.addObject("alreadyRegisteredMessage",
					"Oops!  There is already a user registered with the email provided.");
			modelAndView.setViewName("register");
			bindingResult.reject("email");
		}

		if (bindingResult.hasErrors()) {
			modelAndView.setViewName("register");
		} else { // new user so we create user and send confirmation e-mail
			log.debug("Registering new user...");

			// Disable user until they click on confirmation link in email
			user.setEnabled(false);

			// Generate random 36-character string token for confirmation link
			user.setConfirmationToken(UUID.randomUUID().toString());

			userRepository.save(user);

			String appUrl = request.getScheme() + "://" + request.getServerName();

			log.debug("Sending confirmation token to the selected email: {}", user.getEmail());

			SimpleMailMessage registrationEmail = new SimpleMailMessage();
			registrationEmail.setTo(user.getEmail());
			registrationEmail.setSubject("Registration Confirmation");
			registrationEmail.setText("To confirm your e-mail address, please click the link below:\n" + appUrl
					+ "/confirm?token=" + user.getConfirmationToken());
			registrationEmail.setFrom("noreply@domain.com");

			emailService.sendEmail(registrationEmail);

			modelAndView.addObject("confirmationMessage", "A confirmation e-mail has been sent to " + user.getEmail());
			modelAndView.setViewName("register");
		}

		return modelAndView;
	}

	// Process confirmation link
	@RequestMapping(value = "/confirm", method = RequestMethod.GET)
	public ModelAndView showConfirmationPage(ModelAndView modelAndView, @RequestParam("token") String token) {

		User user = userRepository.findByConfirmationToken(token);

		if (user == null) { // No token found in DB
			modelAndView.addObject("invalidToken", "Oops!  This is an invalid confirmation link.");
		} else { // Token found
			modelAndView.addObject("confirmationToken", user.getConfirmationToken());
		}

		modelAndView.setViewName("confirm");
		return modelAndView;
	}

	// Process confirmation link
	@RequestMapping(value = "/confirm", method = RequestMethod.POST)
	public ModelAndView processConfirmationForm(ModelAndView modelAndView, BindingResult bindingResult,
			@RequestParam Map<String, String> requestParams, RedirectAttributes redir) {
		log.debug("Confirm endpoint - POST");

		modelAndView.setViewName("confirm");

		// Find the user associated with the reset token
		User user = userRepository.findByConfirmationToken(requestParams.get("token"));

		// Set new password
		user.setPassword(bCryptPasswordEncoder.encode((CharSequence) requestParams.get("password")));

		// Set user to enabled
		user.setEnabled(true);

		// Save user
		userRepository.save(user);

		modelAndView.addObject("successMessage", "Your password has been set!");
		return modelAndView;
	}

}