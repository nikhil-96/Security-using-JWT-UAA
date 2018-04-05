package com.security.zuulgateway;

import org.springframework.stereotype.Component;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.List;

@Component
public class ZuulRedirectFilter extends ZuulFilter{
	
	@Override
    public String filterType() {
        return "post";
     }

    @Override
    public int filterOrder() {
      return 5;
    }

    @Override
    public boolean shouldFilter() {
		
    	/*URLConnection connection;
		try {
			connection = new URL("http://localhost:8204/hello-service/hello").openConnection();
			List<String> cookies = connection.getHeaderFields().get("Set-Cookie");

			if(cookies==null || cookies.size()==0)
				return false;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}*/
		return true;
		
    }

    @Override
    public Object run() {

         // ... permission check ...

    	/*if(shouldFilter()) {
    		return null;
    	}*/
    	
         RequestContext ctx = RequestContext.getCurrentContext();

         //redirect
         HttpServletResponse response = ctx.getResponse();
         response.setStatus(HttpServletResponse.SC_FOUND);
         response.setHeader("Location", "http://www.google.com");

         return null;
    }

}
