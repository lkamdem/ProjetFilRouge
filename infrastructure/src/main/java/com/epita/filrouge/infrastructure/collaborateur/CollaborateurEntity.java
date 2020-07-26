package com.epita.filrouge.infrastructure.collaborateur;

import com.epita.filrouge.domain.affectation.Affectation;
import com.epita.filrouge.infrastructure.affectation.AffectationEntity;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Entity
public class CollaborateurEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long collaborateurId;

    private String uid;

    private String nom;
    private String prenom;


    private String numeroLigne;

    @OneToMany(mappedBy = "collaborateur")
    private List<AffectationEntity> affectationCollaborateur = new ArrayList<>();

    public String getNumeroLigne() {
        return numeroLigne;
    }

    public void setNumeroLigne(String numeroLigne) {
        this.numeroLigne = numeroLigne;
    }

    public CollaborateurEntity() {

    }

    public void setUid(String uid) {
        this.uid = uid;
    }

    public void setNom(String nom) {
        this.nom = nom;
    }

    public void setPrenom(String prenom) {
        this.prenom = prenom;
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

    public List<AffectationEntity> getAffectationCollaborateur() {
        return affectationCollaborateur;
    }


    public Long getCollaborateurId() {
        return collaborateurId;
    }

    public void setCollaborateurId(Long collaborateurId) {
        this.collaborateurId = collaborateurId;
    }
}
