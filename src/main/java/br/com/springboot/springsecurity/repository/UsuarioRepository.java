package br.com.springboot.springsecurity.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import br.com.springboot.springsecurity.model.Usuario;

public interface UsuarioRepository extends JpaRepository<Usuario, Integer> {
    
    public Optional<Usuario> findByLogin(String login);
}
