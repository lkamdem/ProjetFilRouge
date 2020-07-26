package com.epita.filrouge.application.affectation;

import com.epita.filrouge.domain.affectation.Affectation;
import com.epita.filrouge.domain.affectation.IRepositoryAffectation;
import com.epita.filrouge.domain.collaborateur.Collaborateur;
import com.epita.filrouge.domain.collaborateur.IRepositoryCollaborateur;
import com.epita.filrouge.domain.iphone.IRepositoryIphone;
import com.epita.filrouge.domain.iphone.Iphone;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Random;

import java.time.LocalDate;

@Service
public class AffectationManagementImpl implements IAffectationManagement {

    @Autowired
    private IRepositoryAffectation repositoryAffectation;

    @Autowired
    private IRepositoryCollaborateur repositoryCollaborateur;

    @Autowired
    private IRepositoryIphone repositoryIphone;

    @Override
    public Affectation creerAffectation(String collaborateurUid, String iPhoneNumeroSerie, LocalDate dateAffectation, String numeroLigne, String commentaire) {

        Collaborateur collaborateur = repositoryCollaborateur.findByUid(collaborateurUid);

        System.out.println("application collaborateur.getPrenom() = " + collaborateur.getPrenom());
        System.out.println("application collaborateur.getPrenom() = " + collaborateur.getId());
//        if (user == null) {
//            throw new NotFoundException(USER_NOT_FOUND, "Email " + userName + " not found");
//        }

        Iphone iPhone = repositoryIphone.findByNumeroSerie(iPhoneNumeroSerie);
        System.out.println("application iPhone.getIphoneId() = " + iPhone.getIphoneId());
//      test existence Iphone
        Long numeroAffectation = genererNumeroAffectation();
        Affectation affectationACreer = new Affectation(numeroAffectation, dateAffectation, commentaire,collaborateur, iPhone);

        repositoryAffectation.affecter(affectationACreer);

        repositoryCollaborateur.miseAJourCollaborateur(collaborateur, numeroLigne);

        repositoryIphone.miseAJourEtatIphone(iPhone, iPhoneNumeroSerie);

        return affectationACreer;

    }

    private static Long genererNumeroAffectation() {
        final Random random = new Random();
        return random.nextLong();
    }
}
