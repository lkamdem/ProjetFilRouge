package com.epita.filrouge.infrastructure.iphone;

import com.epita.filrouge.domain.iphone.EtatIphoneEnum;
import com.epita.filrouge.infrastructure.affectation.AffectationEntity;

import javax.persistence.*;
import java.util.List;
@Entity
public class IphoneEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long iphoneId;

    private String numeroSerie;
    private double prixIphone;

    @ManyToOne(fetch = FetchType.LAZY  )
    @JoinColumn(name = "modeleId", nullable = false)
    private ModeleIphoneEntity modeleIphoneEntity;

//    @ElementCollection
    @Enumerated(EnumType.STRING)
    private EtatIphoneEnum etatIphone;

    @OneToMany(mappedBy = "iphone" )
    private List<AffectationEntity> affectationIphone;

    public IphoneEntity () {

    }

    public void setIphoneId(Long iphoneId) {
        this.iphoneId = iphoneId;
    }

    public void setNumeroSerie(String numeroSerie) {
        this.numeroSerie = numeroSerie;
    }

    public void setPrixIphone(double prixIphone) {
        this.prixIphone = prixIphone;
    }


    public void setEtatIphone(EtatIphoneEnum etatIphone) {
        this.etatIphone = etatIphone;
    }

    public void setAffectationIphone(List<AffectationEntity> affectationIphone) {
        this.affectationIphone = affectationIphone;
    }

    public ModeleIphoneEntity getModeleIphoneEntity() {
        return modeleIphoneEntity;
    }

    public void setModeleIphoneEntity(ModeleIphoneEntity modeleIphoneEntity) {
        this.modeleIphoneEntity = modeleIphoneEntity;
    }

    public Long getIphoneId() {
        return iphoneId;
    }

    public String getNumeroSerie() {
        return numeroSerie;
    }

    public double getPrixIphone() {
        return prixIphone;
    }

    public EtatIphoneEnum getEtatIphone() {
        return etatIphone;
    }

    public List<AffectationEntity> getAffectationIphone() {
        return affectationIphone;
    }

    @Override
    public String toString() {
        return "\n---------------\nEtat: "+ this.getEtatIphone().toString() +"\n"
                + "Id: " + this.getIphoneId()  +"\n"
                + "NumeroSerie: " + this.getNumeroSerie()  +"\n"
                + "AffecationIphone: " + this.getAffectationIphone()  +"\n"
                + "ModeleEntityIphone: " + this.getModeleIphoneEntity()  +"\n"
                + "PrixIphone: " + this.getPrixIphone();
    }
}
