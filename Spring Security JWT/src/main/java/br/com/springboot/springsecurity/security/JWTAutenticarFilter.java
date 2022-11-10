package br.com.springboot.springsecurity.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;

import br.com.springboot.springsecurity.data.DetalheUsuarioData;
import br.com.springboot.springsecurity.model.Usuario;

/**
 * 
 * @author Nilso Junior
 *         - Como configurar a autenticação e a autorização no JWT para o Spring
 *         Boot em Java
 *         {@link}: https://www.freecodecamp.org/portuguese/news/como-configurar-a-autenticacao-e-a-autorizacao-no-jwt-para-o-spring-boot-em-java/
 */

public class JWTAutenticarFilter extends UsernamePasswordAuthenticationFilter {

    public static final int TOKEN_EXPIRACAO = 600_000;
    public static final String TOKEN_SENHA = "ca76cd44-b289-4b9a-99a8-21ebd152f487";

    @Autowired
    private final AuthenticationManager authenticationManager;

    public JWTAutenticarFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req,
            HttpServletResponse res) throws AuthenticationException {
        try {
            Usuario credenciais = new ObjectMapper()
                    .readValue(req.getInputStream(), Usuario.class);

            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            credenciais.getLogin(),
                            credenciais.getPassword(),
                            new ArrayList<>()));
        } catch (IOException err) {
            throw new RuntimeException("Falha ao autenticar usuário.", err);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest req,
            HttpServletResponse res,
            FilterChain chain,
            Authentication auth) throws IOException {
        DetalheUsuarioData usuarioData = (DetalheUsuarioData) auth.getPrincipal();
        String token = JWT.create()
                .withSubject(usuarioData.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + TOKEN_EXPIRACAO))
                .sign(Algorithm.HMAC512(TOKEN_SENHA));

        res.getWriter().write(token);
        res.getWriter().flush();
    }
}
