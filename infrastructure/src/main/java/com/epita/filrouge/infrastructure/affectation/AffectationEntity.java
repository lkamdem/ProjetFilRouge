package com.epita.filrouge.infrastructure.affectation;

import com.epita.filrouge.infrastructure.collaborateur.CollaborateurEntity;
import com.epita.filrouge.infrastructure.iphone.IphoneEntity;

import javax.persistence.*;
import java.time.LocalDate;

@Entity
public class AffectationEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Long numeroAffectation;
    private LocalDate dateAffectation;
    private LocalDate dateRenouvellementPrevue;
    private LocalDate dateFin;
    private String commentaire;
    private String motifFin;

    @ManyToOne(fetch = FetchType.LAZY  )
    @JoinColumn(name = "collaborateurId", nullable = false)
    private CollaborateurEntity collaborateur;

    @ManyToOne(fetch = FetchType.LAZY )
    @JoinColumn(name = "iphoneId", nullable = false)
    private IphoneEntity iphone;

    public AffectationEntity() {

    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getNumeroAffectation() {
        return numeroAffectation;
    }

    public void setNumeroAffectation(Long numeroAffectation) {
        this.numeroAffectation = numeroAffectation;
    }

    public LocalDate getDateAffectation() {
        return dateAffectation;
    }

    public void setDateAffectation(LocalDate dateAffectation) {
        this.dateAffectation = dateAffectation;
    }

    public LocalDate getDateRenouvellementPrevue() {
        return dateRenouvellementPrevue;
    }

    public void setDateRenouvellementPrevue(LocalDate dateRenouvellementPrevue) {
        this.dateRenouvellementPrevue = dateRenouvellementPrevue;
    }

    public LocalDate getDateFin() {
        return dateFin;
    }

    public void setDateFin(LocalDate dateFin) {
        this.dateFin = dateFin;
    }

    public String getCommentaire() {
        return commentaire;
    }

    public void setCommentaire(String commentaire) {
        this.commentaire = commentaire;
    }

    public String getMotifFin() {
        return motifFin;
    }

    public void setMotifFin(String motifFin) {
        this.motifFin = motifFin;
    }

    public CollaborateurEntity getCollaborateur() {
        return collaborateur;
    }

    public void setCollaborateur(CollaborateurEntity collaborateur) {
        this.collaborateur = collaborateur;
    }

    public IphoneEntity getIphone() {
        return iphone;
    }

    public void setIphone(IphoneEntity iphone) {
        this.iphone = iphone;
    }
}
