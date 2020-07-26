package com.epita.filrouge.domain.iphone;

public class ModeleIphone {

    private Long modeleID;
    private String nomModele;

    public ModeleIphone(Long modeleID,String nomModele) {
        this.modeleID = modeleID;
        this.nomModele = nomModele;

    }

    public Long getModeleID() {
        return modeleID;
    }

    public String getNomModele() {
        return nomModele;
    }

}
