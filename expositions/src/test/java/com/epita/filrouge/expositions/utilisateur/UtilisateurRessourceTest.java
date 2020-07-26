package com.epita.filrouge.expositions.utilisateur;

import com.epita.filrouge.application.utilisateur.IUtilisateurManagement;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;


import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@WebMvcTest(UtilisateurRessource.class)
public class UtilisateurRessourceTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private IUtilisateurManagement utilisateurManagement;

    @Autowired
    private ObjectMapper objectMapper;


    @Test
    @WithMockUser(roles = "ADMIN")
    public void role_admin_peut_creer_des_utilisateurs() throws Exception {

        // Given
        UtilisateurDTO utilisateurDTO = new UtilisateurDTO();
        utilisateurDTO.setUid("a19390");

        String monObjetMapper = objectMapper.writeValueAsString(utilisateurDTO);

        //When
        mockMvc.perform(post("/gestaffectation/utilisateur/create")//
                .content(monObjetMapper) //
                .contentType(MediaType.APPLICATION_JSON))
                // Then
                .andExpect(status().isCreated());    // controle de l'AUTORISATION (spring security)

    }

    @Test
    @WithMockUser(roles = {"TYPE1","TYPE2"})
    public void role_autre_que_admin_ne_peut_pas_creer_des_utilisateurs() throws Exception {

        // Given
        UtilisateurDTO utilisateurDTO = new UtilisateurDTO();
        utilisateurDTO.setUid("a19390");

        String monObjetMapper = objectMapper.writeValueAsString(utilisateurDTO);

        //When
        mockMvc.perform(post("/gestaffectation/utilisateur/create")//
                .content(monObjetMapper) //
                .contentType(MediaType.APPLICATION_JSON))
                // Then
                .andExpect(status().isForbidden());    // controle de l'AUTORISATION (spring security)

    }




}