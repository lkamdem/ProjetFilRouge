package com.epita.filrouge.infrastructure.utilisateur;

import com.epita.filrouge.domain.utilisateur.UtilisateurRoleEnum;

import javax.persistence.*;

@Entity
public class UtilisateurEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String uid;
    private String nom;
    private String prenom;
    private String login;
    private String password;

    @Enumerated(EnumType.STRING)
    private UtilisateurRoleEnum userRole;


    public UtilisateurEntity() {
        // constructeur par defaut, indispensable pour hibernate
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUid() {
        return uid;
    }

    public void setUid(String uid) {
        this.uid = uid;
    }

    public String getNom() {
        return nom;
    }

    public void setNom(String nom) {
        this.nom = nom;
    }

    public String getPrenom() {
        return prenom;
    }

    public void setPrenom(String prenom) {
        this.prenom = prenom;
    }

    public String getLogin() {
        return login;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public UtilisateurRoleEnum getUserRole() {
        return userRole;
    }

    public void setUserRole(UtilisateurRoleEnum userRole) {
        this.userRole = userRole;
    }
}
