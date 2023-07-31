package com.practice.ecom.config;

import com.practice.ecom.service.JwtService;
import com.practice.ecom.util.JwtUtil;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private JwtService jwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        final String header = request.getHeader("Authorization");

        String jwtToken = null;
        String username = null;

        if(header != null && header.startsWith("Bearer ")){
            jwtToken = header.substring(7);

            try {
                username = jwtUtil.getUserNameFromToken(jwtToken);
            }
            catch (IllegalArgumentException e) {
                System.out.println("Unable to retrieve JWT Token");
            }
            catch (ExpiredJwtException e) {
                System.out.println("JWT Token is expired");
            }
        }
        else {
            System.out.println("JWT Token is Invalid");
        }

        if(username != null && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails = jwtService.loadUserByUsername(username);

            if(jwtUtil.validateToken(jwtToken, userDetails)){
                UsernamePasswordAuthenticationToken usernamePasswordAuthToken =
                        new UsernamePasswordAuthenticationToken(userDetails,
                                null,
                                userDetails.getAuthorities());

                usernamePasswordAuthToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthToken);
            }
        }

        filterChain.doFilter(request, response);
    }
}
