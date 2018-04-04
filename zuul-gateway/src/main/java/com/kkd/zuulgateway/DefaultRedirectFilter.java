package com.kkd.zuulgateway;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;

import org.apache.http.HttpStatus;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

@Component
public class DefaultRedirectFilter extends ZuulFilter {


    @Override
    public String filterType() {
        return "post";
    }

    @Override
    public int filterOrder() {
        return 5;
    }

    public boolean shouldFilter() {
        return true;
    }

    public Object run() {
    	
    	// ... permission check ...

        RequestContext ctx = RequestContext.getCurrentContext();

        //redirect
        HttpServletResponse response = ctx.getResponse();
        response.setStatus(HttpServletResponse.SC_FOUND);
        response.setHeader("Location", "http://www.google.com");

        return null;
    }
    
}
