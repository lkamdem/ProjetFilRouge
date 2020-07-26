package com.epita.filrouge.domain.utilisateur;

import java.util.List;

public interface IRepositoryUtilisateur {
    void creerUser(Utilisateur utilisateur);

     Utilisateur rechercherUser(String login);

    List<Utilisateur> findAllUser();

    List<Utilisateur> rechercherParUserRole(UtilisateurRoleEnum userRole);

    void upgradeUser(Utilisateur utilisateur);

    void setAdmin(Utilisateur utilisateur);

}
