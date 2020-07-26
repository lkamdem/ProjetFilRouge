package com.epita.filrouge.infrastructure.iphone;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface IRepositoryJpaIphone extends JpaRepository<IphoneEntity,Long> {

    List<IphoneEntity> findByModeleIphoneEntityNomModele(String nomModele);

    IphoneEntity findByNumeroSerie(String numeroSerie);
}
