package com.epita.filrouge.expositions.iphone;

import com.epita.filrouge.application.collaborateur.ICollaborateurManagement;
import com.epita.filrouge.application.iphone.IIphoneManagement;
import com.epita.filrouge.domain.collaborateur.Collaborateur;
import com.epita.filrouge.domain.iphone.EtatIphoneEnum;
import com.epita.filrouge.domain.iphone.Iphone;
import com.epita.filrouge.domain.iphone.ModeleIphone;
import com.epita.filrouge.expositions.collaborateur.CollaborateurRessource;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@WebMvcTest(IphoneRessource.class)
public class IphoneRessourceTest {
    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private IIphoneManagement iPhoneManagement; //Mockito cree cette instance, rend un objet interface

    @Test
    @WithMockUser(roles = {"TYPE1","TYPE2","ADMIN"})
    void DoitRetournerIphone_SurSaisieNomModele () throws Exception {
        // Given

        ModeleIphone modeleIphone = new ModeleIphone(1L,"Iphone8");

        Iphone iphoneRetour = new Iphone(1L,"010203",1400d,modeleIphone, EtatIphoneEnum.DISPONIBLE);
        when(iPhoneManagement.findByNomModele("Iphone8")).thenReturn(iphoneRetour);

        // When
        final String result = mockMvc.perform(get("/gestaffectation/iphone/{nommodele}", "Iphone8")
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

        // Then
        assertThat(result).isEqualTo("{\"iphoneId\":1,\"numeroSerie\":\"010203\"}");
    }

}
