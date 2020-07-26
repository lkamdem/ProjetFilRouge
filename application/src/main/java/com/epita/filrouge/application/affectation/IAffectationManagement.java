package com.epita.filrouge.application.affectation;


import com.epita.filrouge.domain.affectation.Affectation;

import java.time.LocalDate;
import java.util.List;

public interface IAffectationManagement {

    Affectation creerAffectation(String collaborateurUid, String iPhoneNumeroSerie, LocalDate dateAffectation, String numeroLigne, String commentaire);

//     List<Affectation> listerAllAffection();

//    public <T> List<Affectation> listerAffection(T criteresDeFiltre );   // l'objet T est une liste contenant les critères de filtre transmis par le front

//    <T> List<Affectation> listerAffection( List<T> listeCriteresDeFiltre );


}
