package com.epita.filrouge.application.utilisateur;

import com.epita.filrouge.domain.utilisateur.Utilisateur;

public interface IUtilisateurManagement {

    void enregistrerUtilisateur(String uid);

    Utilisateur rechercheUtilisateur(String login);
}
