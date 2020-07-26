package com.epita.filrouge.application.utilisateur;

import com.epita.filrouge.application.collaborateur.ICollaborateurManagement;
import com.epita.filrouge.domain.collaborateur.Collaborateur;
import com.epita.filrouge.domain.utilisateur.IRepositoryUtilisateur;
import com.epita.filrouge.domain.utilisateur.Utilisateur;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UtilisateurManagementImpl implements IUtilisateurManagement{

    @Autowired
    private ICollaborateurManagement monCollaborateurManagement;

    @Autowired
    private IRepositoryUtilisateur repositoryUtilisateur;

    @Override
    public void enregistrerUtilisateur(String uid) {
        Collaborateur monCollaborateur = monCollaborateurManagement.findByUid(uid);
        Utilisateur utilisateurACreer = new Utilisateur(monCollaborateur.getUid(),monCollaborateur.getNom(), monCollaborateur.getPrenom());
        utilisateurACreer.construireLogin();
        repositoryUtilisateur.creerUser(utilisateurACreer);
    }

    @Override
    public Utilisateur rechercheUtilisateur(String login) {
        return null;
    }
}
