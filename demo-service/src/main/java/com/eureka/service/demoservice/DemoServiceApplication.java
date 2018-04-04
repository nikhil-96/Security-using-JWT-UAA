package com.eureka.service.demoservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import brave.sampler.Sampler;

@EnableDiscoveryClient
@RestController
@SpringBootApplication
public class DemoServiceApplication {
	private Logger logger = LoggerFactory.getLogger(this.getClass());
	public static void main(String[] args) {
		SpringApplication.run(DemoServiceApplication.class, args);
	}
	
	@GetMapping("/hello")
	public String hello() {
		logger.info("{}", "hello");
		return "Hello";
	}
	@Bean
	public Sampler defaultSampler(){
		return Sampler.ALWAYS_SAMPLE;
	}
}