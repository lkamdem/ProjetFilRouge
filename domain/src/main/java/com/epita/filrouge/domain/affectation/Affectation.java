package com.epita.filrouge.domain.affectation;

import com.epita.filrouge.domain.collaborateur.Collaborateur;
import com.epita.filrouge.domain.iphone.Iphone;

import java.time.LocalDate;
import java.time.Year;

public class Affectation {

    private Long numeroAffectation;
    private LocalDate dateAffectation;
    private LocalDate dateRenouvellementPrevue;
    private LocalDate dateRenouvellementEffective;
    private String commentaire;
    private String motifFin;

    private Collaborateur collaborateur;
    private Iphone iphone;

    public Affectation(Long numeroAffectation, LocalDate dateAttribution, String commentaire, Collaborateur collaborateur, Iphone iphone) {
        this.numeroAffectation = numeroAffectation;
        this.dateAffectation = dateAttribution;
        this.commentaire = commentaire;
        this.collaborateur = collaborateur;
        this.iphone = iphone;
        calculDateRenouvellement();
    }

    public Long getNumeroAffectation() {
        return numeroAffectation;
    }

    public LocalDate getDateAffectation() {
        return dateAffectation;
    }

    public LocalDate getDateRenouvellementPrevue() {
        return dateRenouvellementPrevue;
    }

    public LocalDate getDateRenouvellementEffective() {
        return dateRenouvellementEffective;
    }

    public String getCommentaire() {
        return commentaire;
    }

    public String getMotifFin() {
        return motifFin;
    }

    public Collaborateur getCollaborateur() {
        return collaborateur;
    }

    public Iphone getIphone() {
        return iphone;
    }

    private void calculDateRenouvellement () {
        dateRenouvellementPrevue =  dateAffectation.plusYears(2);
    }


}
