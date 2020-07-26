package com.epita.filrouge.expositions.affectation;

import com.epita.filrouge.application.affectation.IAffectationManagement;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.*;

import javax.validation.constraints.NotNull;

@RestController
@RequestMapping("/gestaffectation")

public class AffectationRessource {

    @Autowired
    private IAffectationManagement affectationManagement;

    @PostMapping(value = "/affectation", consumes = { "application/json" }, produces =  { "application/json" })
    @ResponseStatus(HttpStatus.CREATED)
    @Secured({"ROLE_ADMIN","ROLE_TYPE2"})
    public void saveAffectation(@NotNull @RequestBody final AffectationDTO affectationDTO) {

        System.out.println("DV  -  dans le post  mapping");
        affectationManagement.creerAffectation(affectationDTO.getCollaborateurUid(),affectationDTO.getIphoneNumeroSerie(),
                                   affectationDTO.getAffectationDate(),affectationDTO.getCollaborateurNumeroLigne(),
                                   affectationDTO.getAffectationCommentaire());

    }
}
