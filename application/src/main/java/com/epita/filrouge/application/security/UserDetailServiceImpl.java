package com.epita.filrouge.application.security;

import com.epita.filrouge.domain.utilisateur.IRepositoryUtilisateur;
import com.epita.filrouge.domain.utilisateur.Utilisateur;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;

@Service
public class UserDetailServiceImpl implements UserDetailsService {

    @Autowired
    IRepositoryUtilisateur myUtilisateurRepository;

    @Override
    public UserDetails loadUserByUsername(String login) throws UsernameNotFoundException {
        Utilisateur myUtilisateur = myUtilisateurRepository.rechercherUser(login);

        if (myUtilisateur == null) {
            throw new UsernameNotFoundException("login non trouvé " + login );
        } else {
            User monUser = new User(myUtilisateur.getLogin(), myUtilisateur.getPassword(), getAuthorities(myUtilisateur));
            System.out.println("****** PROFIL AUTHENTIFIER ******");
            System.out.println("login : " + monUser.getUsername());
            System.out.println("mdp : " + monUser.getPassword());
            System.out.println("profil : " + monUser.getAuthorities());
            return monUser;
        }
    }

    private static Collection<? extends GrantedAuthority> getAuthorities(Utilisateur myUtilisateur) {
        String[] userRoles = new String[1];
        userRoles[0] = myUtilisateur.getUserRole().name();
        final Collection<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList(userRoles);
        return authorities;
    }
}
