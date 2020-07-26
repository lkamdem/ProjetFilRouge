package com.epita.filrouge.infrastructure.affectation;

import com.epita.filrouge.domain.affectation.Affectation;
import com.epita.filrouge.domain.affectation.IRepositoryAffectation;
import com.epita.filrouge.domain.collaborateur.Collaborateur;
import com.epita.filrouge.domain.iphone.Iphone;
import com.epita.filrouge.domain.iphone.ModeleIphone;
import com.epita.filrouge.infrastructure.collaborateur.CollaborateurEntity;
import com.epita.filrouge.infrastructure.iphone.IphoneEntity;
import com.epita.filrouge.infrastructure.iphone.ModeleIphoneEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

@Repository
public class RepositoryAffectationImpl implements IRepositoryAffectation {

    @Autowired
    IRepositoryJpaAffectation iRepositoryJpaAffectation;

    @Override
    public void affecter(Affectation affectationACreer) {

        System.out.println("affectationACreer = " + affectationACreer);
        Collaborateur collaborateur = affectationACreer.getCollaborateur();
        CollaborateurEntity collaborateurEntity = new CollaborateurEntity();
        collaborateurEntity.setCollaborateurId(collaborateur.getId());
        collaborateurEntity.setUid(collaborateur.getUid());
        collaborateurEntity.setNom(collaborateur.getNom());
        collaborateurEntity.setPrenom(collaborateur.getPrenom());
        collaborateurEntity.setNumeroLigne(collaborateur.getNumeroLigne());

        System.out.println("collaborateurEntity.getCollaborateurId() = " + collaborateurEntity.getCollaborateurId());
        System.out.println("collaborateurEntity.getUid() = " + collaborateurEntity.getUid());
        System.out.println("collaborateurEntity.getNom() = " + collaborateurEntity.getNom());
        System.out.println("collaborateurEntity.getPrenom() = " + collaborateurEntity.getPrenom());
        System.out.println("collaborateurEntity.getCollaborateurId() = " + collaborateurEntity.getCollaborateurId());

        Iphone iPhone = affectationACreer.getIphone();
        ModeleIphone modeleIphone = iPhone.getModeleIphone();

        ModeleIphoneEntity modeleIphoneEntity = new ModeleIphoneEntity();
        modeleIphoneEntity.setNomModele(modeleIphone.getNomModele());
        modeleIphoneEntity.setModeleId(modeleIphone.getModeleID());
        System.out.println("infra modeleIphoneEntity.getModeleId() = " + modeleIphoneEntity.getModeleId());
        System.out.println("infra modeleIphoneEntity.getNomModele() = " + modeleIphoneEntity.getNomModele());


        IphoneEntity iphoneEntity = new IphoneEntity();
        iphoneEntity.setIphoneId(iPhone.getIphoneId());
        iphoneEntity.setNumeroSerie(iPhone.getNumeroSerie());
        iphoneEntity.setEtatIphone(iPhone.getEtatIphone());
        iphoneEntity.setModeleIphoneEntity(modeleIphoneEntity);
        System.out.println("iphoneEntity.getIphoneId() = " + iphoneEntity.getIphoneId());
        System.out.println("iphoneEntity.getEtatIphone() = " + iphoneEntity.getEtatIphone());
        System.out.println("iphoneEntity.getNumeroSerie() = " + iphoneEntity.getNumeroSerie());

        AffectationEntity affectationEntity = new AffectationEntity();

        affectationEntity.setNumeroAffectation(affectationACreer.getNumeroAffectation());
        affectationEntity.setDateAffectation(affectationACreer.getDateAffectation());
        affectationEntity.setDateRenouvellementPrevue(affectationACreer.getDateRenouvellementPrevue());
        affectationEntity.setDateFin(affectationACreer.getDateAffectation());
        affectationEntity.setCommentaire(affectationACreer.getCommentaire());
        affectationEntity.setMotifFin(affectationACreer.getMotifFin());
        affectationEntity.setCollaborateur(collaborateurEntity);
        affectationEntity.setIphone(iphoneEntity);

        iRepositoryJpaAffectation.save(affectationEntity);
    }
}
