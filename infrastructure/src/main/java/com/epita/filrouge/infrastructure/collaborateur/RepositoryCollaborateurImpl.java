package com.epita.filrouge.infrastructure.collaborateur;

import com.epita.filrouge.domain.collaborateur.Collaborateur;
import com.epita.filrouge.domain.collaborateur.IRepositoryCollaborateur;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

@Repository
public class RepositoryCollaborateurImpl implements IRepositoryCollaborateur {

    @Autowired
    private IRepositoryJpaCollaborateur repositoryJpaCollaborateur;

    @Override
    public Collaborateur findByUid(String uid) {


        CollaborateurEntity collaborateurEntity =  repositoryJpaCollaborateur.findByUid(uid);

        Collaborateur collaborateur = new Collaborateur(collaborateurEntity.getUid(), collaborateurEntity.getNom(), collaborateurEntity.getPrenom(),collaborateurEntity.getNumeroLigne());
        collaborateur.setNumeroLigne(collaborateurEntity.getNumeroLigne());
        collaborateur.setId(collaborateurEntity.getCollaborateurId());

        return collaborateur;

    }

    @Override
    public Collaborateur findByNumeroLigne(String numeroLigne) {
        CollaborateurEntity collaborateurEntity =  repositoryJpaCollaborateur.findByNumeroLigne(numeroLigne);

        return new Collaborateur(collaborateurEntity.getUid(), collaborateurEntity.getNom(), collaborateurEntity.getPrenom(),collaborateurEntity.getNumeroLigne());

    }

    @Override
    public void miseAJourCollaborateur(Collaborateur collaborateur, String numLigne) {
        // maj du numero de ligne du collaborateur avec celui fourni
        CollaborateurEntity monCollaborateurEntity = repositoryJpaCollaborateur.findByUid(collaborateur.getUid());

        if (monCollaborateurEntity.getNumeroLigne() != numLigne) {
            monCollaborateurEntity.setNumeroLigne(numLigne);
            repositoryJpaCollaborateur.save(monCollaborateurEntity);
        }

    }
}
