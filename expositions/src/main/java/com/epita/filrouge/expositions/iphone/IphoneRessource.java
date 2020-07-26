package com.epita.filrouge.expositions.iphone;

import com.epita.filrouge.application.iphone.IIphoneManagement;
import com.epita.filrouge.domain.iphone.Iphone;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/gestaffectation")
public class IphoneRessource {

    @Autowired
    IIphoneManagement iphoneManagement;

    @GetMapping(value = "/iphone/{nommodele}" , produces = {"application/json"})
    public ResponseEntity<IphoneFullDTO> rechercheCollaborateurParUid (@PathVariable("nommodele") String nomModele) {

        System.out.println("on est rentre par Iphone");


        final Iphone iphone = iphoneManagement.findByNomModele(nomModele);

        final IphoneFullDTO iphoneFullDTO = new IphoneFullDTO();
        iphoneFullDTO.setIphoneId(iphone.getIphoneId());
        iphoneFullDTO.setNumeroSerie(iphone.getNumeroSerie());

        return new ResponseEntity<IphoneFullDTO>(iphoneFullDTO, HttpStatus.OK);

    }


}
