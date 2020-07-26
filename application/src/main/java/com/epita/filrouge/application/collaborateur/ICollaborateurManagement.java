package com.epita.filrouge.application.collaborateur;

import com.epita.filrouge.domain.collaborateur.Collaborateur;

public interface ICollaborateurManagement {

    Collaborateur findByUid(String uid);

    Collaborateur findByNumeroLigne (String numeroLigne);

}
