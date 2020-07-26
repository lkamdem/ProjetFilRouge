package com.epita.filrouge.application.collaborateur;

import com.epita.filrouge.domain.collaborateur.Collaborateur;
import com.epita.filrouge.domain.collaborateur.IRepositoryCollaborateur;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class CollaborateurManagementImpl implements ICollaborateurManagement {

    @Autowired
    private IRepositoryCollaborateur repositoryCollaborateur;

    @Override
    public Collaborateur findByUid(String uid) {

        return repositoryCollaborateur.findByUid(uid);
    }

    @Override
    public Collaborateur findByNumeroLigne(String numeroLigne) {
        return repositoryCollaborateur.findByNumeroLigne(numeroLigne);
    }
}
