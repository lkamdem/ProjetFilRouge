package com.epita.filrouge.infrastructure.collaborateur;

import com.epita.filrouge.domain.collaborateur.Collaborateur;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import static org.assertj.core.api.Assertions.assertThat;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.junit4.SpringRunner;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SpringExtension.class)
@DataJpaTest // permet de dire que l'on utilise h2 si trouve le package h2 dans le pom
class RepositoryCollaborateurImplTest {

    private CollaborateurEntity monCollaborateurPersiste;

    @Autowired
    RepositoryCollaborateurImpl repositoryCollaborateurImpl;

    @Autowired
    private TestEntityManager entityManager;

    @BeforeEach
    public void init() {
        CollaborateurEntity collaborateurEntity = new CollaborateurEntity();
        collaborateurEntity.setUid("425895");
        collaborateurEntity.setNom("Vivier");
        collaborateurEntity.setPrenom("D");
        collaborateurEntity.setNumeroLigne("0612345678");
        monCollaborateurPersiste = entityManager.persist(collaborateurEntity);
    }

    @Test
    void shouldReturnACollaborateur () {
        // Given

        // When
        Collaborateur collaborateurRetour = repositoryCollaborateurImpl.findByUid("425895");

        // Then
        assertThat(collaborateurRetour.getNom()).isEqualTo("Vivier");
        assertThat(collaborateurRetour.getPrenom()).isEqualTo("D");
        assertThat(collaborateurRetour.getNumeroLigne()).isEqualTo("0612345678");
    }

    @Test
    void shouldReturnACollaborateur_WhenFindByNumeroLigne() {
        //Given

        //When
        Collaborateur collaborateurRetour = repositoryCollaborateurImpl.findByNumeroLigne("0612345678");

        // Then
        assertThat(collaborateurRetour.getNom()).isEqualTo("Vivier");
        assertThat(collaborateurRetour.getPrenom()).isEqualTo("D");
        assertThat(collaborateurRetour.getUid()).isEqualTo("425895");

    }

    @Test
    @DisplayName("Actualisation du numéro de ligne sur le collaborateur après affectation")
    public void should_update_collaborateur_with_numLigne_given_if_different(){
        //given
        Collaborateur monCollaborateur = new Collaborateur("425895", "Vivier", "D","0612345678");
        String numeroLigne = "0670588845";

        //when
        repositoryCollaborateurImpl.miseAJourCollaborateur(monCollaborateur, numeroLigne);

        //then
        CollaborateurEntity collaborateurEntityLu = entityManager.find(CollaborateurEntity.class,monCollaborateurPersiste.getCollaborateurId());
        if (collaborateurEntityLu != null)
             {assertThat(collaborateurEntityLu.getNumeroLigne()).isEqualTo(numeroLigne);}
    }
}