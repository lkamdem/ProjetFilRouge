package com.epita.filrouge.domain.affectation;

import com.epita.filrouge.domain.collaborateur.Collaborateur;
import com.epita.filrouge.domain.iphone.EtatIphoneEnum;
import com.epita.filrouge.domain.iphone.Iphone;
import com.epita.filrouge.domain.iphone.ModeleIphone;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.LocalDate;

import static org.junit.jupiter.api.Assertions.*;

class AffectationTest {
    private static final Long COLLABORATEUR_ID = 1L;
    private static final String COLLABORATEUR_UID = "666999";
    private static final String COLLABORATEUR_NOM = "Doe";
    private static final String COLLABORATEUR_PRENOM = "John";
    private static final String COLLABORATEUR_NUMEROLIGNE = "0612345678";

    private static final Long MODELE_ID = 1L;
    private static final String MODELE_NOMMODELE = "Iphone8";

    private static final Long IPHONE_ID = 1L;
    private static final String IPHONE_NUMEROSERIE = "123456";
    private static final Double IPHONE_PRIX = 800D;
    private static final EtatIphoneEnum IPHONE_ETAT = EtatIphoneEnum.DISPONIBLE;

    private static final Long AFFECTATION_NUMERO = 1L;
    private static final LocalDate AFFECTATION_DATE = LocalDate.now();
    private static final String AFFECTATION_COMMENTAIRE = "Premeire affectation";

    @Test
    void ShouldReturnADateInTwoYears() {
        //Given
        LocalDate dateRevouvelementAttentue = AFFECTATION_DATE.plusYears(2);

        Collaborateur collaborateur = new Collaborateur( COLLABORATEUR_UID, COLLABORATEUR_NOM, COLLABORATEUR_PRENOM, COLLABORATEUR_NUMEROLIGNE);
        collaborateur.setId(1L);

        ModeleIphone modeleIphone = new ModeleIphone(1L, MODELE_NOMMODELE);
        Iphone iphone = new Iphone(1L, IPHONE_NUMEROSERIE, IPHONE_PRIX, modeleIphone, IPHONE_ETAT);

        //When
        Affectation affectationACreer = new Affectation(AFFECTATION_NUMERO, AFFECTATION_DATE, AFFECTATION_COMMENTAIRE, collaborateur, iphone);


        //Then
        assertThat(affectationACreer.getDateRenouvellementPrevue()).isEqualTo(dateRevouvelementAttentue);
    }

}