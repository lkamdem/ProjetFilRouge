package com.epita.filrouge.expositions.affectation;

import java.time.LocalDate;

public class AffectationDTO {

    private String collaborateurUid;
    private String iphoneNumeroSerie;
    private LocalDate affectationDate;
    private String collaborateurNumeroLigne;
    private String affectationCommentaire;

    public String getCollaborateurUid() {
        return collaborateurUid;
    }

    public void setCollaborateurUid(String collaborateurUid) {
        this.collaborateurUid = collaborateurUid;
    }

    public String getIphoneNumeroSerie() {
        return iphoneNumeroSerie;
    }

    public void setIphoneNumeroSerie(String iphoneNumeroSerie) {
        this.iphoneNumeroSerie = iphoneNumeroSerie;
    }

    public LocalDate getAffectationDate() {
        return affectationDate;
    }

    public void setAffectationDate(LocalDate affectationDate) {
        this.affectationDate = affectationDate;
    }

    public String getCollaborateurNumeroLigne() {
        return collaborateurNumeroLigne;
    }

    public void setCollaborateurNumeroLigne(String collaborateurNumeroLigne) {
        this.collaborateurNumeroLigne = collaborateurNumeroLigne;
    }

    public String getAffectationCommentaire() {
        return affectationCommentaire;
    }

    public void setAffectationCommentaire(String affectationCommentaire) {
        this.affectationCommentaire = affectationCommentaire;
    }
}
