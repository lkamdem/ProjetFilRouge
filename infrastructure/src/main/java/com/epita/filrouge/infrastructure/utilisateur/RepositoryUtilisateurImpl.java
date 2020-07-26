package com.epita.filrouge.infrastructure.utilisateur;

import com.epita.filrouge.domain.utilisateur.IRepositoryUtilisateur;
import com.epita.filrouge.domain.utilisateur.Utilisateur;
import com.epita.filrouge.domain.utilisateur.UtilisateurRoleEnum;
import com.epita.filrouge.infrastructure.collaborateur.CollaborateurEntity;
import com.epita.filrouge.infrastructure.collaborateur.IRepositoryJpaCollaborateur;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class RepositoryUtilisateurImpl implements IRepositoryUtilisateur {

    @Autowired
    private IRepositoryJpaUtilisateur userJpaRepository;

    @Override
    public void creerUser(Utilisateur utilisateur) {

        UtilisateurEntity monUtilisateurEntity = UtilisateurMapper.mapToInfra(utilisateur);

        userJpaRepository.save(monUtilisateurEntity);
    }




    @Override
    public Utilisateur rechercherUser(String login) {
        UtilisateurEntity monUtilisateurEntity = userJpaRepository.findByLogin(login);
        return UtilisateurMapper.mapToDomain(monUtilisateurEntity);
    }

    @Override
    public List<Utilisateur> findAllUser() {
        return null;
    }

    @Override
    public List<Utilisateur> rechercherParUserRole(UtilisateurRoleEnum userRole) {
        return null;
    }

    @Override
    public void upgradeUser(Utilisateur utilisateur) {
        UtilisateurEntity monUtilisateurEntity = userJpaRepository.findByLogin(utilisateur.getLogin());
        monUtilisateurEntity.setUserRole(UtilisateurRoleEnum.ROLE_TYPE2);
    }

    @Override
    public void setAdmin(Utilisateur utilisateur) {
        UtilisateurEntity monUtilisateurEntity = userJpaRepository.findByLogin(utilisateur.getLogin());
        monUtilisateurEntity.setUserRole(UtilisateurRoleEnum.ROLE_ADMIN);
    }
}
