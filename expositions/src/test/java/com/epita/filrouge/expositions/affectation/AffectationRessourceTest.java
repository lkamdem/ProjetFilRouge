package com.epita.filrouge.expositions.affectation;

import com.epita.filrouge.application.affectation.IAffectationManagement;
import com.epita.filrouge.domain.affectation.Affectation;
import com.epita.filrouge.domain.collaborateur.Collaborateur;
import com.epita.filrouge.domain.iphone.EtatIphoneEnum;
import com.epita.filrouge.domain.iphone.Iphone;
import com.epita.filrouge.domain.iphone.ModeleIphone;
import com.epita.filrouge.expositions.collaborateur.CollaborateurRessource;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@WebMvcTest(AffectationRessource.class)
class AffectationRessourceTest {
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
    private MockMvc mockMvc;

    @MockBean
    private IAffectationManagement affectationManagement;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
//    @Disabled("En attendant")
    @WithMockUser(roles = {"TYPE2","ADMIN"})  // controle de l'AUTHENTIFICATION (Spring security), l'anotation @Secured est non indispensable dans le controller
    @DisplayName("Doit appeler le saveAffectation de la couche application avec les bons paramètres")
    void role_type2_et_admin_doitAppelerSaveDeCoucheApplication() throws Exception {

        // Given
        AffectationDTO affectationDTO = new AffectationDTO();
        affectationDTO.setCollaborateurUid(COLLABORATEUR_UID);
        affectationDTO.setIphoneNumeroSerie(IPHONE_NUMEROSERIE);
        affectationDTO.setAffectationDate(AFFECTATION_DATE);
        affectationDTO.setCollaborateurNumeroLigne(COLLABORATEUR_NUMEROLIGNE);
        affectationDTO.setAffectationCommentaire(AFFECTATION_COMMENTAIRE);

        String monObjetMapper = objectMapper.writeValueAsString(affectationDTO);

        //When
        mockMvc.perform(post("/gestaffectation/affectation")//
                .content(monObjetMapper) //
                .contentType(MediaType.APPLICATION_JSON))
         // Then
                .andExpect(status().isCreated());    // controle de l'AUTORISATION (spring security)
    }

    @Test
//    @Disabled("En attendant")
    @WithMockUser(roles = {"TYPE1"})
    @DisplayName("Interdiction creation affectation pour role TYPE1")
    void role_type1_ne_peux_pas_creer_affectation() throws Exception {

        // Given
        AffectationDTO affectationDTO = new AffectationDTO();
        affectationDTO.setCollaborateurUid(COLLABORATEUR_UID);
        affectationDTO.setIphoneNumeroSerie(IPHONE_NUMEROSERIE);
        affectationDTO.setAffectationDate(AFFECTATION_DATE);
        affectationDTO.setCollaborateurNumeroLigne(COLLABORATEUR_NUMEROLIGNE);
        affectationDTO.setAffectationCommentaire(AFFECTATION_COMMENTAIRE);

        String monObjetMapper = objectMapper.writeValueAsString(affectationDTO);

        //When
        mockMvc.perform(post("/gestaffectation/affectation")//
                .content(monObjetMapper) //
                .contentType(MediaType.APPLICATION_JSON))
                // Then
                .andExpect(status().isForbidden());
    }




    }

