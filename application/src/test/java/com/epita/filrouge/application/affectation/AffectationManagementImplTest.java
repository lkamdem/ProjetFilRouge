package com.epita.filrouge.application.affectation;

import com.epita.filrouge.domain.affectation.Affectation;
import com.epita.filrouge.domain.affectation.IRepositoryAffectation;
import com.epita.filrouge.domain.collaborateur.Collaborateur;
import com.epita.filrouge.domain.collaborateur.IRepositoryCollaborateur;
import com.epita.filrouge.domain.iphone.EtatIphoneEnum;
import com.epita.filrouge.domain.iphone.IRepositoryIphone;
import com.epita.filrouge.domain.iphone.Iphone;
import com.epita.filrouge.domain.iphone.ModeleIphone;

import org.junit.jupiter.api.Test;

import org.junit.jupiter.api.extension.ExtendWith;

import org.mockito.Mockito;
import org.mockito.stubbing.OngoingStubbing;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.time.LocalDate;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = { AffectationManagementImpl.class } )
public class AffectationManagementImplTest {

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

    @Autowired
    private IAffectationManagement affectationManagementImpl;

    @MockBean
    private IRepositoryCollaborateur repositoryCollaborateur;

    @MockBean
    private IRepositoryCollaborateur repositoryCollaborateur1;

    @MockBean
    private IRepositoryIphone repositoryIphone;

    @MockBean
    private IRepositoryAffectation repositoryAffectation;

    @Test
    void ShouldCallFindByUid_And_FindByNumeroSerie_And_repositoryAffectationSave() {
        //Given
        Collaborateur collaborateur = new Collaborateur( COLLABORATEUR_UID, COLLABORATEUR_NOM, COLLABORATEUR_PRENOM, COLLABORATEUR_NUMEROLIGNE);
        collaborateur.setId(1L);

        ModeleIphone modeleIphone = new ModeleIphone(1L, MODELE_NOMMODELE);
        Iphone iphone = new Iphone(1L, IPHONE_NUMEROSERIE, IPHONE_PRIX, modeleIphone, IPHONE_ETAT);

        when(repositoryCollaborateur.findByUid(COLLABORATEUR_UID)).thenReturn(collaborateur);
        when(repositoryIphone.findByNumeroSerie(IPHONE_NUMEROSERIE)).thenReturn(iphone);

        //When
        affectationManagementImpl.creerAffectation(COLLABORATEUR_UID,IPHONE_NUMEROSERIE,AFFECTATION_DATE,COLLABORATEUR_NUMEROLIGNE,AFFECTATION_COMMENTAIRE);

        //Then
        verify(repositoryCollaborateur, Mockito.times(1)).findByUid(COLLABORATEUR_UID);
        verify(repositoryIphone,Mockito.times(1)).findByNumeroSerie(IPHONE_NUMEROSERIE);
        verify(repositoryAffectation,Mockito.times(1)).affecter(any(Affectation.class));
        verify(repositoryCollaborateur, Mockito.times(1)).miseAJourCollaborateur(collaborateur,COLLABORATEUR_NUMEROLIGNE);
    }
}