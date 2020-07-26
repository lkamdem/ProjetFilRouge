package com.epita.filrouge.infrastructure.iphone;

import com.epita.filrouge.domain.collaborateur.Collaborateur;
import com.epita.filrouge.domain.iphone.EtatIphoneEnum;
import com.epita.filrouge.domain.iphone.Iphone;
import com.epita.filrouge.domain.iphone.ModeleIphone;
import com.epita.filrouge.infrastructure.collaborateur.CollaborateurEntity;
import com.epita.filrouge.infrastructure.collaborateur.RepositoryCollaborateurImpl;
import javafx.beans.binding.When;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import javax.persistence.EntityManager;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(SpringExtension.class)
@DataJpaTest
public class RepositoryIphoneImplTest {

    private IphoneEntity iphoneEntity3persiste;
    @Autowired
    RepositoryIphoneImpl repositoryIphoneImpl;

    @Autowired
    TestEntityManager entityManager;

    @BeforeEach // pour créer en base de donnée H2 suite au positionnement de DataJpaTest
    public void init() {

        ModeleIphoneEntity modeleIphone8Entity = new ModeleIphoneEntity();
        modeleIphone8Entity.setNomModele("Iphone8");
        entityManager.persistAndFlush(modeleIphone8Entity);

        IphoneEntity iphoneEntity = new IphoneEntity();
        iphoneEntity.setNumeroSerie("010203");
        iphoneEntity.setEtatIphone(EtatIphoneEnum.DISPONIBLE);
        iphoneEntity.setModeleIphoneEntity(modeleIphone8Entity);
        entityManager.persistAndFlush(iphoneEntity);

        IphoneEntity iphoneEntity1 = new IphoneEntity();
        iphoneEntity1.setNumeroSerie("010204");
        iphoneEntity1.setEtatIphone(EtatIphoneEnum.DISPONIBLE);
        iphoneEntity1.setModeleIphoneEntity(modeleIphone8Entity);
        entityManager.persistAndFlush(iphoneEntity1);

        ModeleIphoneEntity modeleIphone10Entity = new ModeleIphoneEntity();
        modeleIphone10Entity.setNomModele("Iphone10");
        entityManager.persistAndFlush(modeleIphone10Entity);

        IphoneEntity iphoneEntity2 = new IphoneEntity();
        iphoneEntity2.setNumeroSerie("010205");
        iphoneEntity2.setEtatIphone(EtatIphoneEnum.DISPONIBLE);
        iphoneEntity2.setModeleIphoneEntity(modeleIphone10Entity);
        entityManager.persistAndFlush(iphoneEntity2);

        ModeleIphoneEntity modeleIphone9Entity = new ModeleIphoneEntity();
        modeleIphone9Entity.setNomModele("Iphone9");
        entityManager.persistAndFlush(modeleIphone9Entity);

        IphoneEntity iphoneEntity3 = new IphoneEntity();
        iphoneEntity3.setNumeroSerie("010206");
        iphoneEntity3.setEtatIphone(EtatIphoneEnum.DISPONIBLE);
        iphoneEntity3.setModeleIphoneEntity(modeleIphone9Entity);
        iphoneEntity3persiste = entityManager.persistAndFlush(iphoneEntity3);

    }

    @Test
    void shouldReturnAnIphoneModele8 () {

       // Given

        // When
       Iphone iphoneRetour = repositoryIphoneImpl.findByNomModele("Iphone8");

        // Then
       assertThat(iphoneRetour.getNumeroSerie()).isEqualTo("010203");
       assertThat(iphoneRetour.getModeleIphone().getNomModele()).isEqualTo("Iphone8");
       assertThat(iphoneRetour.getEtatIphone()).isEqualTo(EtatIphoneEnum.DISPONIBLE);
         }

    @Test
    void shouldReturnAnIphoneModele10() {

        // Given

        // When
        Iphone iphoneRetour = repositoryIphoneImpl.findByNomModele("Iphone10");

        // Then
        assertThat(iphoneRetour.getNumeroSerie()).isEqualTo("010205");
        assertThat(iphoneRetour.getModeleIphone().getNomModele()).isEqualTo("Iphone10");
        assertThat(iphoneRetour.getEtatIphone()).isEqualTo(EtatIphoneEnum.DISPONIBLE);
    }

    @Test
    void shouldReturnAnIphone_WhenFindByNumeroSerie() {
        //Given

        //When
        Iphone iphoneRetour = repositoryIphoneImpl.findByNumeroSerie("010204");

        //then
        assertThat(iphoneRetour.getNumeroSerie()).isEqualTo("010204");
        assertThat(iphoneRetour.getModeleIphone().getNomModele()).isEqualTo("Iphone8");
        assertThat(iphoneRetour.getEtatIphone()).isEqualTo(EtatIphoneEnum.DISPONIBLE);

    }

    @Test
    @DisplayName("Actualisation l'état de l'iphone après affectation, qui passe de l'état DISPONIBLE à AFFECTE")
    public void should_update_etatIphone_when_affecterIscalled(){
        //given

        System.out.println("Hello dans should_update_etatIphone_when_affecterIscalled");
        ModeleIphone modeleIphone9 = new ModeleIphone(3L, "Iphone9");
        Iphone iphone = new Iphone(4L,"010206", 1400.00, modeleIphone9,EtatIphoneEnum.DISPONIBLE);
        String iPhoneNumeroSerie = "010206";

        //when
        repositoryIphoneImpl.miseAJourEtatIphone(iphone, iPhoneNumeroSerie);

        //then
        IphoneEntity iphoneEntityLu = entityManager.find(IphoneEntity.class,iphoneEntity3persiste.getIphoneId());
        System.out.println("iphoneEntityLu: "+ iphoneEntityLu.toString());
        assertThat(iphoneEntityLu.getEtatIphone()).isEqualTo(EtatIphoneEnum.AFFECTE);
    }
}
