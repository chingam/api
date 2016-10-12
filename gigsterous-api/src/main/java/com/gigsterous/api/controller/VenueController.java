package com.gigsterous.api.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.gigsterous.api.model.Venue;
import com.gigsterous.api.repository.VenueRepository;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/venues")
public class VenueController {

	@Autowired
	private VenueRepository venueRepo;

	@RequestMapping(method = RequestMethod.GET)
	public ResponseEntity<Page<Venue>> getVenues(
			@RequestParam(value = "from", required = false, defaultValue = "0") int from,
			@RequestParam(value = "to", required = false, defaultValue = "20") int to) {
		log.debug("GET - venues");

		return new ResponseEntity<>(venueRepo.findAll(new PageRequest(from, to)), HttpStatus.OK);
	}

	@RequestMapping(value = "/{id}", method = RequestMethod.GET)
	public ResponseEntity<Venue> getEnsemble(@PathVariable long id) {
		log.debug("GET - venue {}", id);

		Venue venue = venueRepo.findOne(id);

		if (venue != null) {
			return new ResponseEntity<>(venue, HttpStatus.OK);
		} else {
			return new ResponseEntity<>(null, HttpStatus.NOT_FOUND);
		}
	}

	@RequestMapping(method = RequestMethod.POST)
	public ResponseEntity<Venue> addVenue(@RequestBody Venue venue) {
		log.debug("POST - venues");

		return new ResponseEntity<>(venueRepo.save(venue), HttpStatus.CREATED);
	}

}