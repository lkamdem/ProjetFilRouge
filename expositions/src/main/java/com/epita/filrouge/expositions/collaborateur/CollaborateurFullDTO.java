package com.epita.filrouge.expositions.collaborateur;

import com.epita.filrouge.domain.affectation.Affectation;

import java.util.List;

public class CollaborateurFullDTO {

    private String uid;
    private String nom;
    private String prenom;
    private String numeroLigne;

//    private List<Affectation> affectationCollaborateur;




    public void setUid(String uid) {
        this.uid = uid;
    }

    public void setNom(String nom) {
        this.nom = nom;
    }

    public void setPrenom(String prenom) {
        this.prenom = prenom;
    }

    public void setNumeroLigne(String numeroLigne) {
        this.numeroLigne = numeroLigne;
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

    public String getNumeroLigne() {
        return numeroLigne;
    }
}
