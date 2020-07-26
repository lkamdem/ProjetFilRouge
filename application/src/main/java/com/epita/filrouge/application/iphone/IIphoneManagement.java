package com.epita.filrouge.application.iphone;

import com.epita.filrouge.domain.iphone.Iphone;

public interface IIphoneManagement {

    Iphone findByNomModele(String nomModele);
}
