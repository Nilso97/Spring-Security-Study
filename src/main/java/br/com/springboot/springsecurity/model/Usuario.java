package br.com.springboot.springsecurity.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity(name = "TB_USUARIOS")
public class Usuario {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(unique = true)
    private String login;

    private String password;

    // public Usuario(String login, String password) {
    //     this.login = login;
    //     this.password = password;
    // }

    // public String getLogin() {
    //     return login;
    // }

    // public void setLogin(String login) {
    //     this.login = login;
    // }

    // public String getPassword() {
    //     return password;
    // }

    // public void setPassword(String password) {
    //     this.password = password;
    // }

    // @Override
    // public int hashCode() {
    //     final int prime = 31;
    //     int result = 1;
    //     result = prime * result + ((id == null) ? 0 : id.hashCode());
    //     result = prime * result + ((login == null) ? 0 : login.hashCode());
    //     result = prime * result + ((password == null) ? 0 : password.hashCode());
    //     return result;
    // }

    // @Override
    // public boolean equals(Object obj) {
    //     if (this == obj)
    //         return true;
    //     if (obj == null)
    //         return false;
    //     if (getClass() != obj.getClass())
    //         return false;
    //     Usuario other = (Usuario) obj;
    //     if (id == null) {
    //         if (other.id != null)
    //             return false;
    //     } else if (!id.equals(other.id))
    //         return false;
    //     if (login == null) {
    //         if (other.login != null)
    //             return false;
    //     } else if (!login.equals(other.login))
    //         return false;
    //     if (password == null) {
    //         if (other.password != null)
    //             return false;
    //     } else if (!password.equals(other.password))
    //         return false;
    //     return true;
    // } 
}
