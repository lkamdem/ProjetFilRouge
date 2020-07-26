package com.epita.filrouge.domain.utilisateur;

public class Utilisateur {

    private String uid;
    private String nom;
    private String prenom;
    private String login;
    private String password;

    private UtilisateurRoleEnum userRole;

    public Utilisateur(String uid,String nom, String prenom) {
        this.uid = uid;
        this.nom= nom;
        this.prenom = prenom;
        password = "password";
        userRole= UtilisateurRoleEnum.ROLE_TYPE1;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    public void construireLogin() {
        this.login = this.prenom + "." + this.nom + "@entreprise.com";
    }

    public String getUid() {
        return uid;
    }

    public String getNom() {
        return nom;
    }

    public String getPrenom() {
        return prenom;
    }

    public String getLogin() {
        return login;
    }

    public String getPassword() {
        return password;
    }

    public UtilisateurRoleEnum getUserRole() {
        return userRole;
    }

    public void setNom(String nom) {
        this.nom = nom;
    }

    public void setPrenom(String prenom) {
        this.prenom = prenom;
    }

    public void setUserRole(UtilisateurRoleEnum userRole) {
        this.userRole = userRole;
    }

    public void setPassword(String password) {
        this.password = password;
    }


}
