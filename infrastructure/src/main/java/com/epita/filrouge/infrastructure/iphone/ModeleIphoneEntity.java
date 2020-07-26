package com.epita.filrouge.infrastructure.iphone;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
@Entity
public class ModeleIphoneEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long modeleId;
    private String nomModele;

    public ModeleIphoneEntity() {
          }

    public Long getModeleId() {
        return modeleId;
    }

    public String getNomModele() {
        return nomModele;
    }

    public void setModeleId(Long modeleId) {
        this.modeleId = modeleId;
    }
    public void setNomModele(String nomModele) {
        this.nomModele = nomModele;
    }
}
