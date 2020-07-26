package com.epita.filrouge.infrastructure.iphone;

import com.epita.filrouge.domain.iphone.EtatIphoneEnum;
import com.epita.filrouge.domain.iphone.IRepositoryIphone;
import com.epita.filrouge.domain.iphone.Iphone;
import com.epita.filrouge.domain.iphone.ModeleIphone;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class RepositoryIphoneImpl implements IRepositoryIphone {

    @Autowired
    private IRepositoryJpaIphone repositoryJpaIphone;

    @Override
    public Iphone findByNomModele(String nomModele) {
        // modification suite à ajout de la list pour ne prendre que le premier enregistrement envoyé car pas de règles métier. On prend
        // le premier iphone disponible
        // ajouter le test de la liste vide et voir pour mettre un try catch
        List<IphoneEntity> iphoneEntityList = repositoryJpaIphone.findByModeleIphoneEntityNomModele(nomModele);

        for ( IphoneEntity iphoneElement : iphoneEntityList) {
            if (iphoneElement.getEtatIphone() == EtatIphoneEnum.DISPONIBLE) {
                ModeleIphoneEntity modeleIphoneEntity = iphoneElement.getModeleIphoneEntity();
                ModeleIphone modeleIphone = new ModeleIphone(modeleIphoneEntity.getModeleId(),modeleIphoneEntity.getNomModele());

                return new Iphone(iphoneElement.getIphoneId(), iphoneElement.getNumeroSerie(), iphoneElement.getPrixIphone(), modeleIphone, iphoneElement.getEtatIphone());
            }
        }
        return null; // à gérer avec l'ajout des exceptions

        /* IphoneEntity iphoneEntity =  repositoryJpaIphone.findByModeleIphoneEntityNomModele(nomModele); //recherche en base pour récupérer l'objet IphoneEntity correspondant au nom passé
        ModeleIphoneEntity modeleIphoneEntity = iphoneEntity.getModeleIphoneEntity(); */ // récupère l'objet ModeleIphoneEntity de l'objet Iphone recherché par le nom
       /*   ModeleIphone modeleIphone = new ModeleIphone(modeleIphoneEntity.getModeleId(), modeleIphoneEntity.getNomModele() ); //creation de l'objet ModelIphone de la couche domain
        return new Iphone(iphoneEntity.getIphoneId(),iphoneEntity.getNumeroSerie(),iphoneEntity.getPrixIphone(),modeleIphone,iphoneEntity.getEtatIphone());*/ //creation de l'objet Iphone de la couche domain
    }

    @Override
    public Iphone findByNumeroSerie(String iPhoneNumeroSerie) {
        IphoneEntity iphoneEntity = repositoryJpaIphone.findByNumeroSerie(iPhoneNumeroSerie);
        ModeleIphoneEntity modeleIphoneEntity = iphoneEntity.getModeleIphoneEntity();
        ModeleIphone modeleIphone = new ModeleIphone(modeleIphoneEntity.getModeleId(),modeleIphoneEntity.getNomModele());

        return new Iphone(iphoneEntity.getIphoneId(), iphoneEntity.getNumeroSerie(), iphoneEntity.getPrixIphone(), modeleIphone, iphoneEntity.getEtatIphone());
    }

    @Override
    // mise à jour de l'état de l'Iphone suite à une affectation. Pas besoin de retester l'état car seul le premier disponible est remonté

    public void miseAJourEtatIphone(Iphone iPhone, String iPhoneNumeroSerie){

        IphoneEntity iphoneEntity = repositoryJpaIphone.findByNumeroSerie(iPhoneNumeroSerie);
        iphoneEntity.setEtatIphone(EtatIphoneEnum.AFFECTE);

        repositoryJpaIphone.save(iphoneEntity);
    }
}
